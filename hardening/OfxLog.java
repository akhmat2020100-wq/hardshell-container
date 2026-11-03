package top.niunaijun.blackbox.util;

import android.content.ContentUris;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
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

        write("boot pid=" + Process.myPid()
                + " proc=" + processName()
                + " sdk=" + Build.VERSION.SDK_INT
                + " model=" + Build.MODEL);
    }

    public static void log(String msg) {
        write(msg);
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
