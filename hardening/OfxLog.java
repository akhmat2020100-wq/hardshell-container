package top.niunaijun.blackbox.util;

import android.content.ContentUris;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.provider.MediaStore;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;

/**
 * Plain-text logger that lands in /sdcard/Download/hardbox-log.txt.
 *
 * Every process of the container (host + :p0..:p49 guests) writes into the same
 * file: on API 29+ the URI is resolved by display name first so all processes
 * append to one row instead of creating duplicates.
 */
public final class OfxLog {

    private static final String NAME = "hardbox-log.txt";

    private static volatile Context ctx;
    private static volatile Uri uri;
    private static volatile boolean installed;
    private static volatile int fd = -1;
    private static volatile int cachedMode = -1;
    private static volatile String modeSource = "default";

    private OfxLog() {
    }

    public static void install(Context c) {
        if (c == null) {
            return;
        }
        Context app = c.getApplicationContext();
        ctx = (app != null) ? app : c;

        if (installed) {
            return;
        }
        installed = true;

        Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
            write("CRASH " + t.getName() + " -> " + e);
            write(stack(e));
            Process.killProcess(Process.myPid());
        });

        startDrain();
        startWatchdog();
        scheduleLogcat(8000);
        scheduleLogcat(20000);

        write("boot pid=" + Process.myPid()
                + " proc=" + processName()
                + " sdk=" + Build.VERSION.SDK_INT
                + " model=" + Build.MODEL
                + " fd=" + logFd()
                + " mode=" + mode()
                + " src=" + modeSource());
    }

    public static void log(String msg) {
        write(msg);
    }

    /** Pulls the native stealth trace (if any) into the same file every 2s. */
    private static void startDrain() {
        Thread t = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    return;
                }
                try {
                    String s = top.niunaijun.blackbox.core.NativeCore.ofxDrainTrace();
                    if (s != null && s.length() > 0) {
                        write("--- native ---\n" + s.trim());
                    }
                } catch (Throwable ignored) {
                }
            }
        }, "ofx-drain");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Guest boot can stall before any Java callback fires, so snapshot every
     * thread a few times early in the process. The main thread's top frame is
     * the call that never returned.
     */
    private static void startWatchdog() {
        Thread t = new Thread(() -> {
            long start = android.os.SystemClock.elapsedRealtime();
            long[] at = {6000L, 12000L, 20000L, 32000L, 50000L};
            for (long ms : at) {
                long left = ms - (android.os.SystemClock.elapsedRealtime() - start);
                if (left > 0) {
                    try {
                        Thread.sleep(left);
                    } catch (InterruptedException e) {
                        return;
                    }
                }
                try {
                    write("--- stacks @" + ms + "ms ---" + snapshot());
                } catch (Throwable ignored) {
                }
            }
        }, "ofx-watchdog");
        t.setDaemon(true);
        t.start();
    }

    private static String snapshot() {
        StringBuilder sb = new StringBuilder();
        try {
            for (Map.Entry<Thread, StackTraceElement[]> e : Thread.getAllStackTraces().entrySet()) {
                Thread th = e.getKey();
                sb.append("\n\"").append(th.getName()).append("\" id=").append(th.getId())
                        .append(" state=").append(th.getState());
                for (StackTraceElement el : e.getValue()) {
                    sb.append("\n    at ").append(el);
                }
            }
        } catch (Throwable t) {
            sb.append("\nsnapshot failed: ").append(t);
        }
        return sb.toString();
    }

    /**
     * Unity reports its native failures only through logd. The container runs
     * under the same uid as the guest, so logcat -d from inside the process
     * returns this process's own lines.
     */
    private static void scheduleLogcat(final long delayMs) {
        Thread t = new Thread(() -> {
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                return;
            }
            dumpLogcat(delayMs);
        }, "ofx-logcat-" + delayMs);
        t.setDaemon(true);
        t.start();
    }

    private static void dumpLogcat(long tag) {
        StringBuilder sb = new StringBuilder();
        try {
            java.lang.Process p = Runtime.getRuntime().exec(new String[]{
                    "/system/bin/logcat", "-d", "-v", "time", "-t", "4000"});
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            String line;
            while ((line = r.readLine()) != null) {
                if (line.contains("Unity") || line.contains("unity3d")
                        || line.contains("il2cpp") || line.contains("EGL")
                        || line.contains("GLES") || line.contains("OpenGL")
                        || line.contains("ofx") || line.contains("catsbit")
                        || line.contains("blackbox") || line.contains("DEBUG")) {
                    sb.append(line).append('\n');
                }
            }
            r.close();
        } catch (Throwable t) {
            sb.append("dump failed: ").append(t).append('\n');
        }
        if (sb.length() > 20000) {
            sb.delete(0, sb.length() - 20000);
        }
        write("--- logcat @" + tag + "ms ---\n" + sb);
    }

    /**
     * Detached append-mode fd to this log file. Native code writes straight into
     * it, so a trace line survives a hard SIGSEGV later in the same process.
     * Returns -1 when MediaStore gives us nothing.
     */
    public static int logFd() {
        int have = fd;
        if (have >= 0) {
            return have;
        }
        Context c = ctx;
        if (c == null) {
            return -1;
        }
        synchronized (OfxLog.class) {
            if (fd >= 0) {
                return fd;
            }
            try {
                Uri u = uri;
                if (u == null) {
                    u = findOrCreate(c);
                    uri = u;
                }
                if (u == null) {
                    return -1;
                }
                ParcelFileDescriptor p = c.getContentResolver().openFileDescriptor(u, "wa");
                if (p == null) {
                    return -1;
                }
                fd = p.detachFd();
                return fd;
            } catch (Throwable t) {
                return -1;
            }
        }
    }

    /**
     * Stealth bitmask: 1 props, 2 cmdline, 4 status, 8 maps, 16 root paths.
     * Read from /sdcard/Download/hardbox-mode.txt, so the layer can be bisected
     * from the phone without a rebuild. Missing file = 0 = trace only, nothing
     * modified: the first launch must prove the hooks themselves are harmless.
     */
    public static int mode() {
        int have = cachedMode;
        if (have >= 0) {
            return have;
        }
        int m = 0;
        String src = "default";
        try {
            File root = Environment.getExternalStoragePublicDirectory(
                    Environment.DIRECTORY_DOWNLOADS);
            File f = new File(root, "hardbox-mode.txt");
            if (!f.canRead()) {
                File hb = new File(new File(root, "HardBox"), "hardbox-mode.txt");
                if (hb.canRead()) {
                    f = hb;
                }
            }
            if (!f.canRead()) {
                Context c = ctx;
                if (c != null) {
                    File g = new File(c.getFilesDir(), "hardbox-mode.txt");
                    if (g.canRead()) {
                        f = g;
                    }
                }
            }
            if (f.canRead()) {
                java.io.BufferedReader r = new java.io.BufferedReader(new java.io.FileReader(f));
                String s = r.readLine();
                r.close();
                if (s != null) {
                    m = Integer.parseInt(s.trim());
                    src = "file:" + f.getAbsolutePath();
                }
            } else {
                src = "unreadable:" + f.getAbsolutePath();
            }
        } catch (Throwable t) {
            src = "err:" + t;
        }
        if (m < 0) {
            m = 0;
        }
        cachedMode = m;
        modeSource = src;
        return m;
    }

    public static String modeSource() {
        return modeSource;
    }

    private static String processName() {
        try {
            java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.FileReader("/proc/self/cmdline"));
            String s = r.readLine();
            r.close();
            return (s == null) ? "?" : s.replace('\u0000', ' ').trim();
        } catch (Throwable t) {
            return "?";
        }
    }

    private static String stack(Throwable e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }

    private static synchronized void write(String msg) {
        String line = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(new Date())
                + " [" + Process.myPid() + "]  " + msg + "\n";
        Context c = ctx;
        if (c == null) {
            return;
        }

        // After IOCore.enableRedirect, MediaStore re-opens and direct
        // /sdcard paths can go to the virtual dir, so Java logs after
        // redirect were lost from the host log file even though the code
        // continued. The native fd (opened before redirect) still points
        // at the host file, so write through it first when it exists.
        try {
            if (fd >= 0) {
                top.niunaijun.blackbox.core.NativeCore.ofxWriteLog(line.trim());
                return;
            }
        } catch (Throwable ignored) {
        }

        if (Build.VERSION.SDK_INT >= 29) {
            try {
                Uri u = uri;
                if (u == null) {
                    u = findOrCreate(c);
                    uri = u;
                }
                if (u != null) {
                    OutputStream os = c.getContentResolver().openOutputStream(u, "wa");
                    if (os != null) {
                        os.write(line.getBytes("UTF-8"));
                        os.close();
                        return;
                    }
                }
            } catch (Throwable ignored) {
                uri = null;
            }
        }

        try {
            File dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            File f = new File(dir, NAME);
            FileOutputStream fos = new FileOutputStream(f, true);
            fos.write(line.getBytes("UTF-8"));
            fos.close();
            return;
        } catch (Throwable ignored) {
        }

        try {
            FileOutputStream fos = new FileOutputStream(new File(c.getFilesDir(), NAME), true);
            fos.write(line.getBytes("UTF-8"));
            fos.close();
        } catch (Throwable ignored) {
        }
    }

    private static Uri findOrCreate(Context c) {
        Uri collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI;
        try {
            Cursor cur = c.getContentResolver().query(
                    collection,
                    new String[]{MediaStore.MediaColumns._ID},
                    MediaStore.MediaColumns.DISPLAY_NAME + "=?",
                    new String[]{NAME},
                    MediaStore.MediaColumns.DATE_ADDED + " DESC");
            if (cur != null) {
                try {
                    if (cur.moveToFirst()) {
                        return ContentUris.withAppendedId(collection, cur.getLong(0));
                    }
                } finally {
                    cur.close();
                }
            }
        } catch (Throwable ignored) {
        }

        try {
            ContentValues v = new ContentValues();
            v.put(MediaStore.MediaColumns.DISPLAY_NAME, NAME);
            v.put(MediaStore.MediaColumns.MIME_TYPE, "text/plain");
            v.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);
            return c.getContentResolver().insert(collection, v);
        } catch (Throwable t) {
            return null;
        }
    }
}
