package top.niunaijun.blackbox.util;

import android.content.pm.ApplicationInfo;
import android.os.Environment;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.Locale;

/**
 * Boot-time overrides for a single guest package, driven by a plain text file
 * on shared storage so the behaviour can be changed without rebuilding:
 *
 *   /storage/emulated/0/Download/oxide-app.txt
 *   /storage/emulated/0/Download/HardBox/oxide-app.txt
 *
 *     default  replace the guest Application class with android.app.Application
 *     force    the same, plus makeApplication(forceDefaultAppClass = true)
 *     real     leave the class reported by the package manager untouched
 *
 * Only the class name is touched. Paths, uid, abi and every other field of
 * ApplicationInfo stay exactly as the package manager produced them.
 */
public final class OfxPatch {

    public static final String OXIDE_PKG = "com.catsbit.oxidesurvivalisland";

    private static final String DIR_NAME = "HardBox";
    private static final String MODE_FILE = "oxide-app.txt";
    private static final String DEFAULT_MODE = "default";
    private static final String DEFAULT_APP_CLASS = "android.app.Application";

    private static volatile String cachedMode;
    private static volatile String cachedSource = "default";
    private static volatile int homeFlag = -1;

    private OfxPatch() {
    }

    public static String modeSource() {
        return cachedSource;
    }

    /** Reads the mode once per process; every guest boots in its own process. */
    public static String modeName() {
        String cached = cachedMode;
        if (cached != null) {
            return cached;
        }
        String mode = DEFAULT_MODE;
        String src = "default";
        File root = Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOWNLOADS);
        File[] candidates = {
                new File(root, MODE_FILE),
                new File(new File(root, DIR_NAME), MODE_FILE)
        };
        for (File f : candidates) {
            if (f == null || !f.isFile()) {
                continue;
            }
            try {
                BufferedReader reader = new BufferedReader(new FileReader(f));
                try {
                    String line = reader.readLine();
                    if (line != null) {
                        line = line.trim().toLowerCase(Locale.ROOT);
                        if (line.length() > 0 && line.length() < 32) {
                            mode = line;
                            src = f.getAbsolutePath();
                        }
                    }
                } finally {
                    reader.close();
                }
                break;
            } catch (Throwable ignored) {
            }
        }
        cachedMode = mode;
        cachedSource = src;
        return mode;
    }

    /**
     * Returns the ApplicationInfo the framework will use for this process.
     * The caller passes the object straight into LoadedApk#makeApplication,
     * so whichever class name survives here is the one that gets instantiated.
     */
    public static ApplicationInfo adjust(ApplicationInfo info, String packageName, String processName) {
        if (info == null || packageName == null) {
            return info;
        }
        if (!OXIDE_PKG.equals(packageName)) {
            return info;
        }
        // Primed here: by the time the app is created, IOCore has redirected
        // /storage/emulated/0 into the container and the flag file is gone.
        homeEnabled();
        keepAlive();
        blockedClass(null);
        String mode = modeName();
        OfxLog.log("appMode=" + mode + " src=" + cachedSource + " pkg=" + packageName
                + " proc=" + processName + " manifestClass=" + info.className);
        if ("real".equals(mode)) {
            OfxLog.log("appMode keeps manifest Application");
            return info;
        }
        info.className = DEFAULT_APP_CLASS;
        OfxLog.log("appMode Application -> " + info.className);
        return info;
    }

    /** True when makeApplication should also be told to ignore the manifest. */
    public static boolean forceDefault(String packageName) {
        return OXIDE_PKG.equals(packageName) && "force".equals(modeName());
    }

    /**
     * The SDK keeps announcing the host package even after the home path is
     * fixed, so it is not reading dataDir. Print every "name" a process can
     * hold at once and see which one still says top.niunaijun.blackbox.
     */
    public static void diagNames(android.app.Application app) {
        if (app == null) {
            return;
        }
        try {
            ApplicationInfo ai = app.getApplicationInfo();
            String cmd = "";
            try {
                BufferedReader r = new BufferedReader(new FileReader("/proc/self/cmdline"));
                StringBuilder sb = new StringBuilder();
                int c;
                while ((c = r.read()) > 0) {
                    sb.append((char) c);
                }
                r.close();
                cmd = sb.toString();
            } catch (Throwable ignored) {
            }
            OfxLog.log("names pkg=" + app.getPackageName()
                    + " op=" + app.getOpPackageName()
                    + " ctx=" + (app.getApplicationContext() == null ? "?"
                        : app.getApplicationContext().getPackageName())
                    + " base=" + (app.getBaseContext() == null ? "?"
                        : app.getBaseContext().getClass().getName())
                    + " basePkg=" + (app.getBaseContext() == null ? "?"
                        : app.getBaseContext().getPackageName())
                    + " appProc=" + app.getProcessName()
                    + " atProc=" + OfxLog.procName()
                    + " aiProc=" + (ai == null ? "?" : ai.processName)
                    + " uid=" + android.os.Process.myUid()
                    + " cmdline=" + cmd);
        } catch (Throwable t) {
            OfxLog.log("names failed " + t);
        }
    }

    /** hardbox-home.txt on shared storage switches the home-path rewrite on. */
    public static boolean homeEnabled() {
        int cached = homeFlag;
        if (cached >= 0) {
            return cached == 1;
        }
        boolean on = false;
        try {
            File root = Environment.getExternalStoragePublicDirectory(
                    Environment.DIRECTORY_DOWNLOADS);
            File[] candidates = {
                    new File(root, "hardbox-home.txt"),
                    new File(new File(root, DIR_NAME), "hardbox-home.txt")
            };
            for (File f : candidates) {
                if (f != null && f.isFile()) {
                    on = true;
                    break;
                }
            }
        } catch (Throwable ignored) {
        }
        homeFlag = on ? 1 : 0;
        return on;
    }

    /**
     * A sandbox gives itself away long before anyone reads /proc: the guest's
     * own ApplicationInfo points at /data/user/0/top.niunaijun.blackbox/...
     * and one substring check is enough. Report the path a real install would
     * have; IOCore already redirects that path into the container, so file
     * access keeps working.
     */
    public static void sanitizeHome(android.app.Application app) {
        if (app == null) {
            return;
        }
        if (!homeEnabled()) {
            OfxLog.log("home off");
            return;
        }
        try {
            String pkg = app.getPackageName();
            if (pkg == null) {
                return;
            }
            String real = "/data/user/0/" + pkg;
            ApplicationInfo ai = app.getApplicationInfo();
            if (ai != null) {
                ai.dataDir = real;
                ai.deviceProtectedDataDir = real;
            }
            Object base = app.getBaseContext();
            Object loadedApk = null;
            if (base != null) {
                try {
                    loadedApk = black.android.app.BRContextImpl.get(base).mPackageInfo();
                } catch (Throwable ignored) {
                }
            }
            if (loadedApk != null) {
                setField(loadedApk.getClass(), loadedApk, "mDataDirFile", new File(real));
                setField(loadedApk.getClass(), loadedApk, "mCredentialProtectedDataDirFile", new File(real));
                setField(loadedApk.getClass(), loadedApk, "mDeviceProtectedDataDirFile", new File(real));
            }
            if (base != null) {
                Class<?> c = base.getClass();
                while (c != null && !"android.app.ContextImpl".equals(c.getName())) {
                    c = c.getSuperclass();
                }
                if (c != null) {
                    String[] caches = {"mFilesDir", "mCacheDir", "mNoBackupFilesDir",
                            "mCodeCacheDir", "mPreferencesDir"};
                    for (String f : caches) {
                        setField(c, base, f, null);
                    }
                }
            }
            OfxLog.log("home -> " + real + " ai=" + (ai != null)
                    + " loadedApk=" + (loadedApk != null)
                    + " files=" + app.getFilesDir()
                    + " cache=" + app.getCacheDir()
                    + " dataDir=" + (ai == null ? "?" : ai.dataDir)
                    + " libs=" + (ai == null ? "?" : ai.nativeLibraryDir)
                    + " code=" + app.getPackageCodePath());
        } catch (Throwable t) {
            OfxLog.log("home sanitize failed " + t);
        }
    }

    /**
     * Rewrite the package name a guest Context reports. The container builds
     * the guest ContextImpl from the host process, so getPackageName() can
     * answer with the host package; integrity checks compare that against the
     * APK path and read the mismatch as virtualization.
     */
    public static void fixContext(android.content.Context c) {
        if (c == null) {
            return;
        }
        try {
            String pkg = c.getPackageName();
            Object impl = c;
            int guard = 0;
            while (impl instanceof android.content.ContextWrapper && guard++ < 16) {
                android.content.Context base =
                        ((android.content.ContextWrapper) impl).getBaseContext();
                if (base == null || base == impl) {
                    break;
                }
                impl = base;
            }
            Class<?> cls = Class.forName("android.app.ContextImpl");
            if (!cls.isInstance(impl)) {
                OfxLog.log("ctxfix not impl=" + (impl == null ? "null"
                        : impl.getClass().getName()) + " pkg=" + pkg);
                return;
            }
            java.lang.reflect.Field f = cls.getDeclaredField("mBasePackageName");
            f.setAccessible(true);
            Object old = f.get(impl);
            if (pkg != null && !pkg.equals(old)) {
                f.set(impl, pkg);
                OfxLog.log("ctxfix mBasePackageName " + old + " -> " + pkg);
            }
        } catch (Throwable t) {
            OfxLog.log("ctxfix failed " + t);
        }
    }

    /**
     * The uid the guest runs under is the host's, so anything that maps
     * uid -> package (getPackagesForUid, currentPackageName) still answers
     * with the container. Record every one of those answers once at boot.
     */
    public static void envDiag(android.app.Application app) {
        if (app == null) {
            return;
        }
        try {
            int uid = android.os.Process.myUid();
            String[] pkgs = null;
            try {
                pkgs = app.getPackageManager().getPackagesForUid(uid);
            } catch (Throwable ignored) {
            }
            String atPkg = null;
            try {
                Class<?> at = Class.forName("android.app.ActivityThread");
                java.lang.reflect.Method m = at.getDeclaredMethod("currentPackageName");
                m.setAccessible(true);
                atPkg = (String) m.invoke(null);
            } catch (Throwable t) {
                atPkg = "err:" + t.getClass().getSimpleName();
            }
            String atOp = null;
            try {
                Class<?> at = Class.forName("android.app.ActivityThread");
                java.lang.reflect.Method m = at.getDeclaredMethod("currentOpPackageName");
                m.setAccessible(true);
                atOp = (String) m.invoke(null);
            } catch (Throwable t) {
                atOp = "err:" + t.getClass().getSimpleName();
            }
            OfxLog.log("env uid=" + uid
                    + " pkgs=" + (pkgs == null ? "null" : java.util.Arrays.toString(pkgs))
                    + " atPkg=" + atPkg
                    + " atOp=" + atOp
                    + " process=" + app.getProcessName()
                    + " myPid=" + android.os.Process.myPid());
        } catch (Throwable t) {
            OfxLog.log("env failed " + t);
        }
    }

    private static volatile int keepFlag = -1;
    private static volatile String[] blockList;    /** hardbox-keepalive.txt present: drop activity-finish requests. */
    public static boolean keepAlive() {
        int c = keepFlag;
        if (c >= 0) {
            return c == 1;
        }
        boolean on = flagFile("hardbox-keepalive.txt") != null;
        keepFlag = on ? 1 : 0;
        return on;
    }

    /** hardbox-block.txt: one class-name fragment per line to refuse. */
    public static boolean blockedClass(String cls) {
        String[] list = blockList;
        if (list == null) {
            java.util.ArrayList<String> acc = new java.util.ArrayList<String>();
            File f = flagFile("hardbox-block.txt");
            if (f != null) {
                try {
                    BufferedReader r = new BufferedReader(new FileReader(f));
                    try {
                        String line;
                        while ((line = r.readLine()) != null) {
                            line = line.trim();
                            if (line.length() > 0) {
                                acc.add(line);
                            }
                        }
                    } finally {
                        r.close();
                    }
                } catch (Throwable ignored) {
                }
            }
            list = acc.toArray(new String[0]);
            blockList = list;
        }
        if (cls == null) {
            return false;
        }
        for (String s : list) {
            if (cls.contains(s)) {
                return true;
            }
        }
        return false;
    }

    private static File flagFile(String name) {
        try {
            File root = Environment.getExternalStoragePublicDirectory(
                    Environment.DIRECTORY_DOWNLOADS);
            File[] c = {
                    new File(root, name),
                    new File(new File(root, DIR_NAME), name)
            };
            for (File f : c) {
                if (f != null && f.isFile()) {
                    return f;
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static void setField(Class<?> cls, Object target, String name, Object value) {
        Class<?> c = cls;
        while (c != null) {
            try {
                java.lang.reflect.Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                f.set(target, value);
                return;
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            } catch (Throwable ignored) {
                return;
            }
        }
    }
}
