// harden.cpp — anti-detection for the BlackBox container, guest processes only.
//
// Installed from BActivityThread.initProcess through
//   NativeCore.ofxSetGuestPackage(String pkg, int logFd, int mode)
// which only ever runs inside a guest process and hands us three things:
//   * the guest package name, needed for the /proc scrub
//   * a detached MediaStore file descriptor opened in append mode, so every
//     trace line is on disk the moment it happens (a native crash cannot lose it)
//   * the mode bitmask, so the stealth can be bisected without a rebuild:
//       1  mask root/emulator properties
//       2  /proc/self/cmdline      -> guest package
//       4  /proc/self/status Name  -> guest package
//       8  /proc/self/maps|smaps   -> container paths rewritten, our libs dropped
//      16  root/container marker paths (su, magisk, blackbox data dir) -> ENOENT
//
// The mode comes from /sdcard/Download/hardbox-mode.txt (first line, integer);
// missing file = 31 = everything on.

#include <jni.h>
#include <android/log.h>
#include <link.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <cerrno>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <string>
#include <atomic>
#include <mutex>

#include "Dobby/dobby.h"

#define HLOG(...) __android_log_print(ANDROID_LOG_INFO, "ofx-harden", __VA_ARGS__)

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef SYS_mkdirat
#define SYS_mkdirat __NR_mkdirat
#endif

namespace {

enum {
    M_PROPS     = 1,
    M_CMDLINE   = 2,
    M_STATUS    = 4,
    M_MAPS      = 8,
    M_ROOTPATHS = 16,
};

std::atomic<bool> g_installed{false};
std::atomic<int>  g_budget{30000};

int  g_logFd = -1;
int  g_mode  = M_PROPS | M_CMDLINE | M_STATUS | M_MAPS | M_ROOTPATHS;
char g_pkg[128] = {0};
std::mutex g_mtx;
std::string g_buf;   // fallback when no fd was handed over

bool modeOn(int bit) { return (g_mode & bit) != 0; }

const char* guestPkg() {
    return g_pkg[0] ? g_pkg : "android";
}

// ---------------------------------------------------------------------------
// trace: straight to the append-mode fd, one write per line
// ---------------------------------------------------------------------------
void rawWrite(const char* data, size_t n) {
    if (g_logFd >= 0) {
        size_t off = 0;
        while (off < n) {
            ssize_t w = (ssize_t)syscall(SYS_write, g_logFd, data + off, n - off);
            if (w <= 0) break;
            off += (size_t)w;
        }
        return;
    }
    std::lock_guard<std::mutex> lk(g_mtx);
    if (g_buf.size() < 200000) g_buf.append(data, n);
}

void nlogRaw(const char* tag, const char* detail) {
    if (g_budget.fetch_sub(1) <= 0) return;
    char line[900];
    int n = snprintf(line, sizeof(line), "%d %s %s\n", (int)getpid(), tag, detail ? detail : "");
    if (n <= 0) return;
    if (n > (int)sizeof(line) - 1) n = (int)sizeof(line) - 1;
    rawWrite(line, (size_t)n);
}

uint32_t fnv(const char* s) {
    uint32_t h = 2166136261u;
    while (s && *s) { h ^= (uint32_t)(unsigned char)*s++; h *= 16777619u; }
    return h;
}

// Log each distinct probe once: we want the anti-cheat's checklist, not volume.
bool firstTime(const char* s) {
    static uint32_t seen[1024];
    static int used = 0;
    std::lock_guard<std::mutex> lk(g_mtx);
    uint32_t h = fnv(s);
    for (int i = 0; i < used; i++) if (seen[i] == h) return false;
    if (used < 1024) seen[used++] = h;
    return true;
}

void trace(const char* tag, const char* s) {
    if (!s || !firstTime(s)) return;
    nlogRaw(tag, s);
}

// ---------------------------------------------------------------------------
// what the container leaks
// ---------------------------------------------------------------------------
const char* kProps[][2] = {
    {"ro.kernel.qemu",              ""},
    {"ro.kernel.qemu.gles",         ""},
    {"ro.boot.qemu",                ""},
    {"ro.build.tags",               "release-keys"},
    {"ro.build.type",               "user"},
    {"ro.debuggable",               "0"},
    {"ro.secure",                   "1"},
    {"ro.adb.secure",               "1"},
    {"ro.boot.verifiedbootstate",   "green"},
    {"ro.boot.flash.locked",        "1"},
    {"ro.boot.vbmeta.device_state", "locked"},
    {"ro.boot.veritymode",          "enforcing"},
    {"ro.sys.safemode",             "0"},
    {"ro.dalvik.vm.native.bridge",  "0"},
    {"ro.enable.native.bridge.exec","0"},
    {"sys.oem_unlock_allowed",      "0"},
    {"ro.boot.warranty_bit",        "0"},
    {"ro.warranty_bit",             "0"},
    {"service.adb.root",            "0"},
};

const char* kHiddenProps[] = {
    "persist.magisk.hide",
    "ro.virtual",
    "ro.debuggable.qemu",
    "init.svc.magisk",
};

// substrings that make a /proc line or module name a giveaway
const char* kMarks[] = {
    "blackbox", "sandbox", "sandhook", "virtualapp", "vspace", "xposed",
    "magisk", "frida", "gum-js", "substrate", "lspd", "multiapp", "dualapp",
    "parallel.", "dobby", "libxdl", "memfd:jit-cache",
};

bool marked(const char* s) {
    if (!s) return false;
    for (const char* m : kMarks) if (strstr(s, m)) return true;
    return false;
}

const char* kPaths[] = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
    "/data/adb", "/system/app/Superuser.apk", "/dev/socket/su",
};

bool hiddenPath(const char* p) {
    if (!p) return false;
    for (const char* x : kPaths) if (strstr(p, x)) return true;
    return false;
}

bool isSelf(const char* p) {
    if (!p || strncmp(p, "/proc/", 6) != 0) return false;
    if (strstr(p, "/self/") || strstr(p, "/thread-self/")) return true;
    char me[32];
    snprintf(me, sizeof(me), "/proc/%d/", (int)getpid());
    return strstr(p, me) != nullptr;
}

bool procTarget(const char* p) {
    if (!isSelf(p)) return false;
    return strstr(p, "/maps") || strstr(p, "/smaps") || strstr(p, "/cmdline")
        || strstr(p, "/status") || strstr(p, "/stat") || strstr(p, "/comm")
        || strstr(p, "/mountinfo") || strstr(p, "/mounts") || strstr(p, "/environ")
        || strstr(p, "/task/") || strstr(p, "/map_files");
}

// ---------------------------------------------------------------------------
// memfd
// ---------------------------------------------------------------------------
int memfdFor(const std::string& data) {
    int fd = (int)syscall(SYS_memfd_create, "jit-cache", MFD_CLOEXEC);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < data.size()) {
        ssize_t w = write(fd, data.data() + off, data.size() - off);
        if (w <= 0) { close(fd); return -1; }
        off += (size_t)w;
    }
    lseek(fd, 0, SEEK_SET);
    return fd;
}

void replaceAll(std::string& s, const std::string& from, const std::string& to) {
    if (from.empty()) return;
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
}

// Everything the container imprints on a path becomes the guest's own app dir.
void rewritePaths(std::string& line) {
    static std::string app = std::string("/data/app/~~ofxQm9w==/") + guestPkg() + "-ofxQm9w==";
    static std::string host1 = "/data/user/0/top.niunaijun.blackbox/files/blackbox/";
    static std::string host2 = "/data/data/top.niunaijun.blackbox/files/blackbox/";
    static std::string host3 = "/data/user/0/top.niunaijun.blackbox/";
    static std::string host4 = "/data/data/top.niunaijun.blackbox/";
    replaceAll(line, host1, app + "/");
    replaceAll(line, host2, app + "/");
    replaceAll(line, host3, app + "/");
    replaceAll(line, host4, app + "/");
    replaceAll(line, "/files/blackbox/", "/");
    replaceAll(line, "top.niunaijun.blackbox", guestPkg());
}

std::string comm15() {
    std::string p = guestPkg();
    if (p.size() > 15) p.resize(15);
    return p;
}

std::string sanitize(const std::string& raw, const char* path) {
    bool statusMode = strstr(path, "/status") != nullptr;
    bool commMode   = strstr(path, "/comm") != nullptr;
    bool statMode   = strstr(path, "/stat") && !strstr(path, "/status");

    if (commMode) return comm15();

    std::string out;
    out.reserve(raw.size() + 64);
    size_t pos = 0;
    while (pos < raw.size()) {
        size_t nl = raw.find('\n', pos);
        if (nl == std::string::npos) nl = raw.size();
        std::string line = raw.substr(pos, nl - pos);
        pos = nl + 1;

        if (statusMode && line.compare(0, 5, "Name:") == 0) {
            out += "Name:\t" + comm15() + "\n";
            continue;
        }
        if (statMode) {
            size_t lp = line.find('('), rp = line.find(')');
            if (lp != std::string::npos && rp != std::string::npos && rp > lp)
                line = line.substr(0, lp + 1) + comm15() + line.substr(rp);
        }

        rewritePaths(line);

        bool drop = false;
        for (const char* m : kMarks) {
            if (line.find(m) != std::string::npos) { drop = true; break; }
        }
        if (drop) continue;

        out += line;
        out += '\n';
    }
    return out;
}

int scrubbedOpen(const char* path) {
    if (strstr(path, "/cmdline")) {
        std::string s = guestPkg();
        s.push_back('\0');
        return memfdFor(s);
    }

    int in = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
    if (in < 0) return in;

    std::string raw;
    char buf[16384];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) raw.append(buf, (size_t)n);
    close(in);

    return memfdFor(sanitize(raw, path));
}

// ---------------------------------------------------------------------------
// hooks
// ---------------------------------------------------------------------------
typedef int   (*propGetFn)(const char*, char*);
typedef const void* (*propFindFn)(const char*);
typedef int   (*statFn)(const char*, struct stat*);
typedef int   (*accessFn)(const char*, int);
typedef int   (*openFn)(const char*, int, ...);
typedef int   (*openatFn)(int, const char*, int, ...);
typedef FILE* (*fopenFn)(const char*, const char*);
typedef int   (*unameFn)(struct utsname*);
typedef int   (*dlIterFn)(int (*)(struct dl_phdr_info*, size_t, void*), void*);
typedef int   (*dladdrFn)(const void*, Dl_info*);
typedef int   (*execveFn)(const char*, char* const[], char* const[]);
typedef ssize_t (*readlinkFn)(const char*, char*, size_t);

propGetFn  origPropGet;
propFindFn origPropFind;
statFn     origStat, origLstat;
accessFn   origAccess;
openFn     origOpen;
openatFn   origOpenat;
fopenFn    origFopen;
unameFn    origUname;
dlIterFn   origDlIter;
dladdrFn   origDladdr;
execveFn   origExecve;
readlinkFn origReadlink;

int hookPropGet(const char* key, char* out) {
    if (!key) return origPropGet ? origPropGet(key, out) : 0;
    trace("prop", key);
    if (modeOn(M_PROPS)) {
        for (const char* h : kHiddenProps) {
            if (strcmp(key, h) == 0) { if (out) out[0] = '\0'; return 0; }
        }
        for (const auto& p : kProps) {
            if (strcmp(key, p[0]) == 0) {
                size_t n = strlen(p[1]);
                if (out) memcpy(out, p[1], n + 1);
                return (int)n;
            }
        }
    }
    return origPropGet ? origPropGet(key, out) : 0;
}

const void* hookPropFind(const char* key) {
    if (key) trace("find", key);
    return origPropFind ? origPropFind(key) : nullptr;
}

int hookStat(const char* p, struct stat* b) {
    if (modeOn(M_ROOTPATHS) && hiddenPath(p)) { errno = ENOENT; return -1; }
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/"))) trace("stat", p);
    return origStat(p, b);
}
int hookLstat(const char* p, struct stat* b) {
    if (modeOn(M_ROOTPATHS) && hiddenPath(p)) { errno = ENOENT; return -1; }
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/"))) trace("lstat", p);
    return origLstat(p, b);
}
int hookAccess(const char* p, int m) {
    if (modeOn(M_ROOTPATHS) && hiddenPath(p)) { errno = ENOENT; return -1; }
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/"))) trace("access", p);
    return origAccess(p, m);
}

bool scrubThisOpen(const char* p) {
    if (!procTarget(p)) return false;
    if (strstr(p, "/cmdline")) return modeOn(M_CMDLINE);
    if (strstr(p, "/status") || strstr(p, "/comm")) return modeOn(M_STATUS);
    if (strstr(p, "/maps") || strstr(p, "/smaps") || strstr(p, "/map_files")) return modeOn(M_MAPS);
    return modeOn(M_MAPS) || modeOn(M_STATUS);
}

int hookOpen(const char* p, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/"))) trace("open", p);
    if (scrubThisOpen(p)) {
        int fd = scrubbedOpen(p);
        if (fd >= 0) return fd;
        errno = EACCES;
        return -1;
    }
    if (modeOn(M_ROOTPATHS) && hiddenPath(p)) { errno = ENOENT; return -1; }
    return origOpen ? origOpen(p, flags, mode) : -1;
}

int hookOpenat(int dirfd, const char* p, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/"))) trace("openat", p);
    if (scrubThisOpen(p)) {
        int fd = scrubbedOpen(p);
        if (fd >= 0) return fd;
        errno = EACCES;
        return -1;
    }
    if (modeOn(M_ROOTPATHS) && hiddenPath(p)) { errno = ENOENT; return -1; }
    return origOpenat ? origOpenat(dirfd, p, flags, mode) : -1;
}

FILE* hookFopen(const char* p, const char* mode) {
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/"))) trace("fopen", p);
    if (scrubThisOpen(p)) {
        int fd = scrubbedOpen(p);
        if (fd < 0) { errno = EACCES; return nullptr; }
        return fdopen(fd, "r");
    }
    if (modeOn(M_ROOTPATHS) && hiddenPath(p)) { errno = ENOENT; return nullptr; }
    return origFopen ? origFopen(p, mode) : nullptr;
}

int hookUname(struct utsname* u) {
    int r = origUname ? origUname(u) : -1;
    if (r == 0 && u) {
        char b[400];
        snprintf(b, sizeof(b), "%s %s %s", u->sysname, u->release, u->machine);
        trace("uname", b);
    }
    return r;
}

struct DlCtx { int (*cb)(struct dl_phdr_info*, size_t, void*); void* user; };

int dlTrampoline(struct dl_phdr_info* info, size_t sz, void* data) {
    DlCtx* c = (DlCtx*)data;
    if (info && info->dlpi_name && marked(info->dlpi_name)) {
        trace("mod", info->dlpi_name);
        if (modeOn(M_MAPS)) return 0;   // pretend the container module is not there
    }
    return c->cb(info, sz, c->user);
}

int hookDlIterate(int (*cb)(struct dl_phdr_info*, size_t, void*), void* data) {
    DlCtx c{cb, data};
    return origDlIter ? origDlIter(dlTrampoline, &c) : 0;
}

int hookDladdr(const void* addr, Dl_info* info) {
    int r = origDladdr ? origDladdr(addr, info) : 0;
    if (r && info && info->dli_fname) trace("dladdr", info->dli_fname);
    return r;
}

int hookExecve(const char* path, char* const argv[], char* const envp[]) {
    char b[512];
    snprintf(b, sizeof(b), "%s argv0=%s", path ? path : "?",
             (argv && argv[0]) ? argv[0] : "-");
    trace("execve", b);
    return origExecve ? origExecve(path, argv, envp) : -1;
}

ssize_t hookReadlink(const char* p, char* buf, size_t n) {
    ssize_t r = origReadlink ? origReadlink(p, buf, n) : -1;
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/"))) trace("readlink", p);
    if (r > 0 && buf && marked(buf) && modeOn(M_MAPS)) {
        std::string s(buf, (size_t)r);
        rewritePaths(s);
        size_t c = s.size() < n ? s.size() : n;
        memcpy(buf, s.data(), c);
        return (ssize_t)c;
    }
    return r;
}

void* sym(const char* name) { return dlsym(RTLD_DEFAULT, name); }

void patch(const char* name, void* replace, void** orig, const char* tag) {
    void* target = sym(name);
    if (!target) { nlogRaw("miss", name); return; }
    if (DobbyHook(target, replace, orig) != 0) { nlogRaw("fail", name); return; }
    nlogRaw("hook", tag ? tag : name);
}

} // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_top_niunaijun_blackbox_core_NativeCore_ofxDrainTrace(JNIEnv *env, jclass) {
    std::string out;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        out.swap(g_buf);
    }
    if (out.empty()) return nullptr;
    return env->NewStringUTF(out.c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_top_niunaijun_blackbox_core_NativeCore_ofxSetGuestPackage(
        JNIEnv *env, jclass, jstring pkg, jint logFd, jint mode) {
    if (!pkg) return;
    const char* c = env->GetStringUTFChars(pkg, nullptr);
    if (!c) return;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        strncpy(g_pkg, c, sizeof(g_pkg) - 1);
        g_pkg[sizeof(g_pkg) - 1] = '\0';
        if (logFd >= 0) g_logFd = (int)dup(logFd);
        if (mode >= 0) g_mode = mode;
    }
    env->ReleaseStringUTFChars(pkg, c);

    if (g_installed.exchange(true)) return;

    char head[256];
    snprintf(head, sizeof(head), "%s fd=%d mode=%d", g_pkg, g_logFd, g_mode);
    nlogRaw("install", head);
    nlogRaw("mypid", std::to_string(getpid()).c_str());

    patch("__system_property_get",  (void*)hookPropGet,  (void**)&origPropGet,  "propget");
    patch("__system_property_find", (void*)hookPropFind, (void**)&origPropFind, "propfind");
    patch("open",                   (void*)hookOpen,     (void**)&origOpen,     "open");
    patch("openat",                 (void*)hookOpenat,   (void**)&origOpenat,   "openat");
    patch("__open_2",               (void*)hookOpen,     (void**)&origOpen,     "open2");
    patch("__openat_2",             (void*)hookOpenat,   (void**)&origOpenat,   "openat2");
    patch("fopen",                  (void*)hookFopen,    (void**)&origFopen,    "fopen");
    patch("stat",                   (void*)hookStat,     (void**)&origStat,     "stat");
    patch("lstat",                  (void*)hookLstat,    (void**)&origLstat,    "lstat");
    patch("access",                 (void*)hookAccess,   (void**)&origAccess,   "access");
    patch("uname",                  (void*)hookUname,    (void**)&origUname,    "uname");
    patch("dl_iterate_phdr",        (void*)hookDlIterate,(void**)&origDlIter,   "dliter");
    patch("dladdr",                 (void*)hookDladdr,   (void**)&origDladdr,   "dladdr");
    patch("execve",                 (void*)hookExecve,   (void**)&origExecve,   "execve");
    patch("readlink",               (void*)hookReadlink, (void**)&origReadlink, "readlink");

    nlogRaw("done", "hooks installed");
    HLOG("hardening installed for %s mode=%d fd=%d", g_pkg, g_mode, g_logFd);
}
