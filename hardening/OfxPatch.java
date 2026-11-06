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
    /** Set after the guest Application.onCreate has finished; scrubbing before
     *  that point corrupts the objects the framework uses to build the
     *  process (IOCore map + createPackageContext), so results stay real. */
    private static volatile boolean booted = false;

    public static void appCreated() {
        booted = true;
    }

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
        // Never touch className or dataDir here. AppDome's manifest Application
        // loads libloader.so and registers its JNI methods; replacing it made
        // Unity die with UnsatisfiedLinkError, and rewriting dataDir before
        // IOCore.enableRedirect turned the path map into a no-op (EACCES).
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
     * The post-onCreate sanitizer above is too late for a packer that reads
     * its own paths while Application.onCreate is still running. Run the same
     * rewrite on the package Context between `enableRedirect` and
     * `makeApplication`: IOCore has already recorded the virtual target, so
     * every file access to the real-looking path is still redirected into the
     * container, but the guest only ever sees the path a normal install has.
     */
    public static void sanitizeEarly(android.content.Context base) {
        if (base == null) {
            return;
        }
        if (!homeEnabled()) {
            return;
        }
        try {
            String pkg = base.getPackageName();
            if (pkg == null) {
                return;
            }
            String real = "/data/user/0/" + pkg;
            ApplicationInfo ai = base.getApplicationInfo();
            if (ai != null) {
                ai.dataDir = real;
                ai.deviceProtectedDataDir = real;
                setField(ApplicationInfo.class, ai, "credentialProtectedDataDir", real);
            }
            Object impl = base;
            int guard = 0;
            while (impl instanceof android.content.ContextWrapper && guard++ < 16) {
                android.content.Context b =
                        ((android.content.ContextWrapper) impl).getBaseContext();
                if (b == null || b == impl) {
                    break;
                }
                impl = b;
            }
            Object loadedApk = null;
            try {
                loadedApk = black.android.app.BRContextImpl.get(impl).mPackageInfo();
            } catch (Throwable ignored) {
            }
            if (loadedApk != null) {
                setField(loadedApk.getClass(), loadedApk, "mDataDirFile", new File(real));
                setField(loadedApk.getClass(), loadedApk, "mCredentialProtectedDataDirFile", new File(real));
                setField(loadedApk.getClass(), loadedApk, "mDeviceProtectedDataDirFile", new File(real));
            }
            Class<?> c = impl.getClass();
            while (c != null && !"android.app.ContextImpl".equals(c.getName())) {
                c = c.getSuperclass();
            }
            if (c != null) {
                String[] caches = {"mFilesDir", "mCacheDir", "mNoBackupFilesDir",
                        "mCodeCacheDir", "mPreferencesDir"};
                for (String f : caches) {
                    setField(c, impl, f, null);
                }
            }
            OfxLog.log("home early -> " + real
                    + " ai=" + (ai != null)
                    + " loadedApk=" + (loadedApk != null)
                    + " dataDir=" + base.getDataDir()
                    + " ext=" + earlyPath(base, 0)
                    + " obb=" + earlyPath(base, 1)
                    + " sdcard=" + Environment.getExternalStorageDirectory());
        } catch (Throwable t) {
            OfxLog.log("home early failed " + t);
        }
    }

    /**
     * The virtual PM builds every ApplicationInfo with the container path in
     * dataDir. A packer that walks getInstalledPackages() - or asks for its
     * own PackageInfo - reads "blackbox" straight out of that field. Rewrite
     * the three path fields to the layout a normal install has. IOCore already
     * owns the redirect for these names, so file access is unaffected.
     */
    public static void scrub(ApplicationInfo ai) {
        if (ai == null || !homeEnabled() || !booted) {
            return;
        }
        try {
            String pkg = ai.packageName;
            if (pkg == null) {
                return;
            }
            String was = ai.dataDir;
            // Only the guest objects built by the virtual PM carry a container
            // path. System packages already report their real dataDir and must
            // never be rewritten, even if the host package name matches.
            if (was == null || !was.contains("/blackbox/")) {
                return;
            }
            String real = "/data/user/0/" + pkg;
            ai.dataDir = real;
            ai.deviceProtectedDataDir = real;
            setField(ApplicationInfo.class, ai, "credentialProtectedDataDir", real);
            if (OXIDE_PKG.equals(pkg)) {
                OfxLog.log("scrub " + pkg + " was=" + was);
            }
        } catch (Throwable ignored) {
        }
    }

    private static String earlyPath(android.content.Context base, int kind) {
        try {
            if (kind == 0) {
                return String.valueOf(base.getExternalFilesDir(null));
            }
            return String.valueOf(base.getObbDir());
        } catch (Throwable t) {
            return "err:" + t;
        }
    }

    /**
     * Single choke point behind every proxied system-service call. Mutate any
     * ApplicationInfo the guest is about to receive, in place, so the virtual
     * paths never cross the Java boundary. ParceledListSlice is unwrapped by
     * reflection because its getList() is the only public view of the items.
     */
    public static Object scrubResult(Object result) {
        if (result == null || !homeEnabled() || !booted) {
            return result;
        }
        try {
            if (result instanceof android.content.pm.PackageInfo) {
                return copyPackageInfo((android.content.pm.PackageInfo) result);
            }
            if (result instanceof ApplicationInfo) {
                return copyApplicationInfo((ApplicationInfo) result);
            }
            // Lists are left alone: replacing a ParceledListSlice backing list
            // is not safe across framework versions, and getInstalledPackages
            // results are also used internally while activities start.
        } catch (Throwable ignored) {
        }
        return result;
    }

    private static ApplicationInfo copyApplicationInfo(ApplicationInfo ai) {
        try {
            android.os.Parcel p = android.os.Parcel.obtain();
            try {
                ai.writeToParcel(p, 0);
                p.setDataPosition(0);
                ApplicationInfo c = ApplicationInfo.CREATOR.createFromParcel(p);
                scrub(c);
                return c;
            } finally {
                p.recycle();
            }
        } catch (Throwable t) {
            return ai;
        }
    }

    private static android.content.pm.PackageInfo copyPackageInfo(
            android.content.pm.PackageInfo pi) {
        try {
            android.os.Parcel p = android.os.Parcel.obtain();
            try {
                pi.writeToParcel(p, 0);
                p.setDataPosition(0);
                android.content.pm.PackageInfo c =
                        android.content.pm.PackageInfo.CREATOR.createFromParcel(p);
                scrub(c.applicationInfo);
                return c;
            } finally {
                p.recycle();
            }
        } catch (Throwable t) {
            return pi;
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
     * AppDome's native library lands while LoadedApk#makeApplication is still
     * running the guest Application's constructor. At that instant the real
     * ActivityThread.mInitialApplication is still BlackBox's own Application,
     * so any native code that caches currentApplication() captures the host
     * package ("top.niunaijun.blackbox") and reads it back later as
     * "virtualized environment". Park a guest-backed placeholder in that field
     * before the constructor runs; the real Application replaces it a few
     * milliseconds later in BActivityThread.
     */
    public static final class TmpApp extends android.app.Application {
        void bind(android.content.Context base) {
            attachBaseContext(base);
        }
    }

    public static void preBindApplication(android.content.Context base) {
        if (base == null) {
            return;
        }
        // sanitizeEarly is deliberately not called: rewriting the live
        // ContextImpl/LoadedApk dirs to /data/user/0/<pkg> made ContextImpl
        // mkdir fail with EACCES and native SQLite open the wrong path, which
        // is exactly the black screen. Runtime dirs stay on the container.
        try {
            TmpApp tmp = new TmpApp();
            tmp.bind(base);
            black.android.app.BRActivityThread.get(
                    top.niunaijun.blackbox.BlackBoxCore.mainThread())
                    ._set_mInitialApplication(tmp);
            OfxLog.log("preBind tmp=" + tmp.getPackageName()
                    + " base=" + base.getPackageName());
        } catch (Throwable t) {
            OfxLog.log("preBind failed " + t);
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

    /**
     * One line per distinct identity query that reaches a system service.
     *
     * Every call the guest makes to PackageManager/ActivityManager lands in
     * ClassInvocationStub.invoke before it is proxied. The checks that decide
     * "this is a container" are made of exactly these questions - who owns
     * this uid, what does this package's ApplicationInfo say, is some known
     * host package installed - so the argument plus the caller stack is the
     * cheapest place to see the decision being made. Nothing is answered
     * differently here.
     */
    public static void noteCall(String name, Object[] args) {
        if (name == null) {
            return;
        }
        switch (name) {
            case "getPackageInfo":
            case "getApplicationInfo":
            case "getInstalledPackages":
            case "getInstalledApplications":
            case "getPackageUid":
            case "getPackagesForUid":
            case "getNameForUid":
            case "getNamesForUids":
            case "resolveIntent":
            case "queryIntentActivities":
            case "checkSignatures":
            case "getInstallerPackageName":
            case "getRunningAppProcesses":
            case "getRunningTasks":
            case "getRecentTasks":
            case "getMyMemoryState":
            case "getProcessesInErrorState":
            case "getUidProcessState":
            case "getAppStartMode":
            case "getPackageProcessState":
            case "getRunningServices":
                break;
            default:
                return;
        }
        String a0 = "";
        try {
            if (args != null && args.length > 0 && args[0] != null) {
                a0 = String.valueOf(args[0]);
            }
        } catch (Throwable ignored) {
        }
        if (a0.length() > 120) {
            a0 = a0.substring(0, 120);
        }
        int seq;
        synchronized (pmSeen) {
            if (pmCount >= 400) {
                return;
            }
            seq = ++pmCount;
        }
        long ms = android.os.SystemClock.elapsedRealtime() - pmStart;
        OfxLog.log("pm" + seq + " +" + ms + "ms " + name + " " + a0 + " @ " + callStack());
    }

    private static final java.util.HashSet<String> pmSeen = new java.util.HashSet<String>();
    private static final long pmStart = android.os.SystemClock.elapsedRealtime();
    private static int pmCount = 0;

    /** Full caller stack for the toast / package observers. */
    public static String trace() {
        return callStack();
    }

    private static String callStack() {
        try {
            StackTraceElement[] st = new Throwable().getStackTrace();
            StringBuilder sb = new StringBuilder();
            for (StackTraceElement e : st) {
                String cn = e.getClassName();
                if (cn == null || cn.startsWith("top.niunaijun.blackbox.util.OfxPatch")) {
                    continue;
                }
                if (sb.length() > 0) {
                    sb.append(" < ");
                }
                sb.append(cn).append('.').append(e.getMethodName());
                if (sb.length() > 900) {
                    break;
                }
            }
            return sb.toString();
        } catch (Throwable t) {
            return "?";
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
