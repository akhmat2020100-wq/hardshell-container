// harden.cpp — anti-detection for the BlackBox container, guest processes only.
//
// Installed from BActivityThread.initProcess through
//   NativeCore.ofxSetGuestPackage(String pkg, int logFd, int mode)
//
// mode bitmask (read from /sdcard/Download/hardbox-mode.txt):
//    1  mask root/emulator properties
//    2  /proc/self/cmdline   -> guest package
//    4  /proc/self/status    -> Name / comm rewritten
//    8  /proc/self/maps      -> container paths rewritten, our libs dropped
//   16  root marker paths    -> ENOENT
//   64  install NO hooks at all (bisect: is the hook layer itself the problem?)
//
// Everything is written straight into the append-mode fd the Java side hands
// over, so a native crash cannot swallow the trace. A SIGSEGV handler logs the
// faulting pc plus the /proc/self/maps line it belongs to; a heartbeat thread
// proves the process was alive and when it stopped being alive.

#include <jni.h>
#include <android/log.h>
#include <signal.h>
#include <ucontext.h>
#include <pthread.h>
#include <link.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/utsname.h>
#include <time.h>
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

namespace {

enum {
    M_PROPS     = 1,
    M_CMDLINE   = 2,
    M_STATUS    = 4,
    M_MAPS      = 8,
    M_ROOTPATHS = 16,
    M_NOHOOKS   = 64,
};

std::atomic<bool> g_installed{false};
std::atomic<int>  g_budget{30000};
std::atomic<bool> g_hbStop{false};

int  g_logFd = -1;
int  g_mode  = 0;
char g_pkg[128] = {0};
std::mutex g_mtx;
std::string g_buf;

bool modeOn(int bit) { return (g_mode & bit) != 0; }

const char* guestPkg() {
    return g_pkg[0] ? g_pkg : "android";
}

// ---------------------------------------------------------------------------
// trace
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
// crash handler: sig + faulting pc + the maps line that owns it
// ---------------------------------------------------------------------------
char g_maps[65536];

void mapsScan(uintptr_t pc) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t n = (ssize_t)syscall(SYS_read, fd, g_maps, sizeof(g_maps) - 1);
    syscall(SYS_close, fd);
    if (n <= 0) return;
    g_maps[n] = '\0';

    char* p = g_maps;
    while (p && *p) {
        char* nl = strchr(p, '\n');
        unsigned long a = 0, b = 0;
        if (sscanf(p, "%lx-%lx", &a, &b) == 2 && pc >= a && pc < b) {
            nlogRaw("crashmap", p);
            return;
        }
        if (!nl) break;
        p = nl + 1;
    }
}

void sigHandler(int sig, siginfo_t* si, void* uc) {
    uintptr_t pc = 0, lr = 0, sp = 0;
    ucontext_t* u = (ucontext_t*)uc;
#if defined(__aarch64__)
    if (u) {
        pc = (uintptr_t)u->uc_mcontext.pc;
        lr = (uintptr_t)u->uc_mcontext.regs[30];
        sp = (uintptr_t)u->uc_mcontext.sp;
    }
#elif defined(__arm__)
    if (u) {
        pc = (uintptr_t)u->uc_mcontext.arm_pc;
        lr = (uintptr_t)u->uc_mcontext.arm_lr;
        sp = (uintptr_t)u->uc_mcontext.arm_sp;
    }
#endif
    char b[256];
    snprintf(b, sizeof(b), "sig=%d addr=%p pc=%p lr=%p sp=%p",
             sig, si ? si->si_addr : nullptr, (void*)pc, (void*)lr, (void*)sp);
    nlogRaw("CRASH", b);
    if (pc) mapsScan(pc);
    signal(sig, SIG_DFL);
    raise(sig);
}

void installCrashHandler() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigHandler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    int sigs[] = {SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE, SIGTRAP};
    for (int s : sigs) sigaction(s, &sa, nullptr);
}

// ---------------------------------------------------------------------------
// heartbeat: proves when the process stopped breathing
// ---------------------------------------------------------------------------
void* hbThread(void*) {
    for (int i = 0; i < 90 && !g_hbStop.load(); i++) {
        char b[32];
        snprintf(b, sizeof(b), "hb %d", i);
        nlogRaw("alive", b);
        struct timespec ts;
        ts.tv_sec = 2;
        ts.tv_nsec = 0;
        nanosleep(&ts, nullptr);
    }
    return nullptr;
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
    // NOTE: was "jit-cache" — that string itself is in kMarks, so a raw-syscall
    // maps read would flag our own scrubbed fd. Use the guest package instead.
    std::string memName = guestPkg();
    if (memName.size() > 15) memName.resize(15);
    if (memName.empty()) memName = "android";
    int fd = (int)syscall(SYS_memfd_create, memName.c_str(), MFD_CLOEXEC);
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
typedef int   (*open2Fn)(const char*, int);
typedef int   (*openat2Fn)(int, const char*, int);
typedef FILE* (*fopenFn)(const char*, const char*);
typedef int   (*unameFn)(struct utsname*);
typedef int   (*execveFn)(const char*, char* const[], char* const[]);
typedef ssize_t (*readlinkFn)(const char*, char*, size_t);

propGetFn  origPropGet;
propFindFn origPropFind;
statFn     origStat, origLstat;
accessFn   origAccess;
openFn     origOpen;
openatFn   origOpenat;
open2Fn    origOpen2;
openat2Fn  origOpenat2;
fopenFn    origFopen;
unameFn    origUname;
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
    // Previously find() was trace-only: native code using find()+read()
    // bypassed the propget mask entirely. Hide the same props here.
    if (key && modeOn(M_PROPS)) {
        for (const char* h : kHiddenProps) {
            if (strcmp(key, h) == 0) return nullptr;
        }
    }
    return origPropFind ? origPropFind(key) : nullptr;
}

// dl_iterate_phdr bypasses /proc/self/maps completely: it lists every
// loaded .so (libBoxCore, Dobby, BlackBox) straight from the linker.
// Filter marked libraries out of the callback stream.
typedef int (*dlIterateFn)(int (*)(struct dl_phdr_info*, size_t, void*), void*);
dlIterateFn origDlIterate = nullptr;
struct DlWrap {
    int (*cb)(struct dl_phdr_info*, size_t, void*);
    void* data;
};
int dlWrapCb(struct dl_phdr_info* info, size_t size, void* data) {
    DlWrap* w = (DlWrap*)data;
    if (info && info->dlpi_name && marked(info->dlpi_name)) return 0;
    return w->cb(info, size, w->data);
}
int hookDlIterate(int (*cb)(struct dl_phdr_info*, size_t, void*), void* data) {
    if (!cb) return origDlIterate ? origDlIterate(cb, data) : -1;
    if (!modeOn(M_MAPS)) return origDlIterate ? origDlIterate(cb, data) : -1;
    DlWrap w{cb, data};
    return origDlIterate ? origDlIterate(dlWrapCb, &w) : -1;
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

// FORTIFY variants: two arguments, no mode. Kept separate from open/openat so
// the trampolines never point at each other (that used to recurse forever).
int hookOpen2(const char* p, int flags) {
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/"))) trace("open2", p);
    if (scrubThisOpen(p)) {
        int fd = scrubbedOpen(p);
        if (fd >= 0) return fd;
        errno = EACCES;
        return -1;
    }
    if (modeOn(M_ROOTPATHS) && hiddenPath(p)) { errno = ENOENT; return -1; }
    return origOpen2 ? origOpen2(p, flags) : -1;
}

int hookOpenat2(int dirfd, const char* p, int flags) {
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/"))) trace("openat2", p);
    if (scrubThisOpen(p)) {
        int fd = scrubbedOpen(p);
        if (fd >= 0) return fd;
        errno = EACCES;
        return -1;
    }
    if (modeOn(M_ROOTPATHS) && hiddenPath(p)) { errno = ENOENT; return -1; }
    return origOpenat2 ? origOpenat2(dirfd, p, flags) : -1;
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

void logSymbols() {
    char b[256];
    snprintf(b, sizeof(b), "open=%p open2=%p openat=%p openat2=%p prop=%p propfind=%p",
             sym("open"), sym("__open_2"), sym("openat"), sym("__openat_2"),
             sym("__system_property_get"), sym("__system_property_find"));
    nlogRaw("sym", b);
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
Java_top_niunaijun_blackbox_core_NativeCore_ofxWriteLog(JNIEnv *env, jclass, jstring msg) {
    if (!msg) return;
    const char* c = env->GetStringUTFChars(msg, nullptr);
    if (!c) return;
    // Write straight to the already-open MediaStore fd, bypassing Java
    // MediaStore re-opens and IOCore IO redirection. This is why Java logs
    // after enableRedirect were lost: MediaStore re-open / redirected path
    // went to the virtual dir, while the native fd still points at the host file.
    if (g_logFd >= 0) {
        char line[1024];
        int n = snprintf(line, sizeof(line), "%d %s\n", (int)getpid(), c);
        if (n > 0) rawWrite(line, (size_t)(n > (int)sizeof(line) - 1 ? sizeof(line) - 1 : n));
    }
    env->ReleaseStringUTFChars(msg, c);
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

    installCrashHandler();

    pthread_t th;
    if (pthread_create(&th, nullptr, hbThread, nullptr) == 0) pthread_detach(th);

    if (modeOn(M_NOHOOKS)) {
        nlogRaw("hooks", "off (mode 64)");
        HLOG("hardening %s mode=%d NO HOOKS", g_pkg, g_mode);
        return;
    }

    logSymbols();

    patch("__system_property_get",  (void*)hookPropGet,  (void**)&origPropGet,  "propget");
    patch("__system_property_find", (void*)hookPropFind, (void**)&origPropFind, "propfind");
    patch("open",                   (void*)hookOpen,     (void**)&origOpen,     "open");
    patch("openat",                 (void*)hookOpenat,   (void**)&origOpenat,   "openat");
    patch("fopen",                  (void*)hookFopen,    (void**)&origFopen,    "fopen");
    patch("stat",                   (void*)hookStat,     (void**)&origStat,     "stat");
    patch("lstat",                  (void*)hookLstat,    (void**)&origLstat,    "lstat");
    patch("access",                 (void*)hookAccess,   (void**)&origAccess,   "access");
    patch("uname",                  (void*)hookUname,    (void**)&origUname,    "uname");
    patch("execve",                 (void*)hookExecve,   (void**)&origExecve,   "execve");
    patch("readlink",               (void*)hookReadlink, (void**)&origReadlink, "readlink");
    patch("dl_iterate_phdr",        (void*)hookDlIterate, (void**)&origDlIterate, "dl_iterate_phdr");

    // FORTIFY wrappers: only patch when they are distinct symbols, otherwise the
    // two trampolines call each other and the guest dies of stack overflow.
    void* o = sym("open");
    void* o2 = sym("__open_2");
    if (o2 && o2 != o) {
        patch("__open_2", (void*)hookOpen2, (void**)&origOpen2, "open2");
    } else {
        nlogRaw("skip", "__open_2 aliases open");
    }
    void* oa = sym("openat");
    void* oa2 = sym("__openat_2");
    if (oa2 && oa2 != oa) {
        patch("__openat_2", (void*)hookOpenat2, (void**)&origOpenat2, "openat2");
    } else {
        nlogRaw("skip", "__openat_2 aliases openat");
    }

    nlogRaw("done", "hooks installed");
    HLOG("hardening installed for %s mode=%d fd=%d", g_pkg, g_mode, g_logFd);
}
