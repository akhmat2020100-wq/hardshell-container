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
}
