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

    /** hardbox-home.txt on shared storage switches the home-path rewrite on. */
    public static boolean homeEnabled() {
        File root = Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOWNLOADS);
        File[] candidates = {
                new File(root, "hardbox-home.txt"),
                new File(new File(root, DIR_NAME), "hardbox-home.txt")
        };
        for (File f : candidates) {
            if (f != null && f.isFile()) {
                return true;
            }
        }
        return false;
    }

    /**
     * A sandbox gives itself away long before anyone reads /proc: the guest's
     * own ApplicationInfo points at /data/user/0/top.niunaijun.blackbox/...
     * and one substring check is enough. Report the path a real install would
     * have; IOCore already redirects that path into the container, so file
     * access keeps working.
     */
    public static void sanitizeHome(android.app.Application app) {
        if (app == null || !homeEnabled()) {
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
                    + " files=" + app.getFilesDir());
        } catch (Throwable t) {
            OfxLog.log("home sanitize failed " + t);
        }
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
