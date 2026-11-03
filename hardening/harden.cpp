// harden.cpp — anti-detection for the BlackBox container, guest processes only.
//
// The container itself works on Android 16 (guest :pN spawns, Application binds).
// What fails is the game's own anti-cheat: it looks at the process it is running
// in and finds container fingerprints. This layer removes them and writes a
// trace of everything the game inspects to
//   /storage/emulated/0/Android/data/top.niunaijun.blackbox/files/harden.log
// (own external dir, no permission needed on any API level, readable from the
// build sandbox).
//
// Installation is triggered from BActivityThread.initProcess via the JNI call
// NativeCore.ofxSetGuestPackage(String) — that only ever happens inside a guest
// process, and it hands us the guest package name we need for the scrub.

#include <jni.h>
#include <android/log.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
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

std::atomic<bool> g_installed{false};
std::atomic<int> g_budget{4000};

char g_pkg[128] = {0};
std::mutex g_mtx;

const char* guestPkg() {
    return g_pkg[0] ? g_pkg : "android";
}

// ---------------------------------------------------------------------------
// trace ring buffer -> drained by Java (MediaStore log), no filesystem access
// ---------------------------------------------------------------------------
std::string g_trace;
std::atomic<int> g_budget{4000};

void nlogRaw(const char* tag, const char* detail) {
    if (g_budget.fetch_sub(1) <= 0) return;
    char line[600];
    int n = snprintf(line, sizeof(line), "[%d] %s %s\n", (int)getpid(), tag, detail);
    if (n <= 0) return;
    if (n > (int)sizeof(line) - 1) n = (int)sizeof(line) - 1;
    std::lock_guard<std::mutex> lk(g_mtx);
    if (g_trace.size() < 60000) g_trace.append(line, (size_t)n);
}

uint32_t fnv(const char* s) {
    uint32_t h = 2166136261u;
    while (s && *s) { h ^= (uint32_t)(unsigned char)*s++; h *= 16777619u; }
    return h;
}

// Log each distinct path/property once: the point is the list of probes the
// anti-cheat makes, not the volume.
bool firstTime(const char* s) {
    static uint32_t seen[512];
    static int used = 0;
    std::lock_guard<std::mutex> lk(g_mtx);
    uint32_t h = fnv(s);
    for (int i = 0; i < used; i++) if (seen[i] == h) return false;
    if (used < 512) seen[used++] = h;
    return true;
}

void trace(const char* tag, const char* s) {
    if (s && firstTime(s)) nlogRaw(tag, s);
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

// line markers dropped from /proc output
const char* kDropMarks[] = {
    "virtualapp", "vspace", "sandhook", "xposed", "magisk",
    "frida", "gum-js", "substrate", "tcpdump", "lspd",
    "multiapp", "dualapp", "parallel.", "dobby", "memfd:",
};

const char* kPaths[] = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
    "/data/adb", "/system/app/Superuser.apk", "/dev/socket/su",
};

bool hiddenPath(const char* p) {
    if (!p) return false;
    for (const char* x : kPaths) if (strstr(p, x)) return true;
    return false;
}

bool procTarget(const char* p) {
    if (!p || strncmp(p, "/proc/", 6) != 0) return false;
    return strstr(p, "/maps") || strstr(p, "/smaps")
        || strstr(p, "/cmdline") || strstr(p, "/status")
        || strstr(p, "/mountinfo") || strstr(p, "/task/");
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

std::string sanitize(const std::string& raw, bool statusMode) {
    std::string out;
    out.reserve(raw.size() + 64);
    size_t pos = 0;
    while (pos < raw.size()) {
        size_t nl = raw.find('\n', pos);
        if (nl == std::string::npos) nl = raw.size();
        std::string line = raw.substr(pos, nl - pos);
        pos = nl + 1;

        if (statusMode && line.compare(0, 5, "Name:") == 0) {
            std::string pkg = guestPkg();
            if (pkg.size() > 15) pkg.resize(15);
            out += "Name:\t" + pkg + "\n";
            continue;
        }

        replaceAll(line, "top.niunaijun.blackbox", guestPkg());
        replaceAll(line, "/files/blackbox/", "/files/");

        bool drop = false;
        for (const char* m : kDropMarks) {
            if (line.find(m) != std::string::npos) { drop = true; break; }
        }
        if (!drop && line.find("libblackbox") != std::string::npos) drop = true;
        if (drop) continue;

        out += line;
        out += '\n';
    }
    return out;
}

int scrubbedOpen(const char* path) {
    if (strstr(path, "cmdline")) {
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

    bool statusMode = strstr(path, "status") != nullptr;
    return memfdFor(sanitize(raw, statusMode));
}

// ---------------------------------------------------------------------------
// hooks
// ---------------------------------------------------------------------------
typedef int (*propGetFn)(const char*, char*);
typedef int (*statFn)(const char*, struct stat*);
typedef int (*accessFn)(const char*, int);
typedef int (*openFn)(const char*, int, ...);
typedef int (*openatFn)(int, const char*, int, ...);
typedef FILE* (*fopenFn)(const char*, const char*);

propGetFn origPropGet;
statFn    origStat, origLstat;
accessFn  origAccess;
openFn    origOpen;
openatFn  origOpenat;
fopenFn   origFopen;

int hookPropGet(const char* key, char* out) {
    if (!key) return origPropGet ? origPropGet(key, out) : 0;
    for (const char* h : kHiddenProps) {
        if (strcmp(key, h) == 0) { if (out) out[0] = '\0'; return 0; }
    }
    for (const auto& p : kProps) {
        if (strcmp(key, p[0]) == 0) {
            trace("prop", key);
            size_t n = strlen(p[1]);
            if (out) memcpy(out, p[1], n + 1);
            return (int)n;
        }
    }
    if (strncmp(key, "ro.", 3) == 0 || strncmp(key, "init.svc.", 9) == 0 ||
        strncmp(key, "gsm.", 4) == 0 || strncmp(key, "persist.", 8) == 0) {
        trace("prop", key);
    }
    return origPropGet ? origPropGet(key, out) : 0;
}

int hookStat(const char* p, struct stat* b) {
    if (hiddenPath(p)) { errno = ENOENT; return -1; }
    return origStat(p, b);
}
int hookLstat(const char* p, struct stat* b) {
    if (hiddenPath(p)) { errno = ENOENT; return -1; }
    return origLstat(p, b);
}
int hookAccess(const char* p, int m) {
    if (hiddenPath(p)) { errno = ENOENT; return -1; }
    return origAccess(p, m);
}

int hookOpen(const char* p, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
    if (procTarget(p)) {
        trace("open", p);
        int fd = scrubbedOpen(p);
        if (fd >= 0) return fd;
        errno = EACCES;
        return -1;
    }
    if (hiddenPath(p)) { errno = ENOENT; return -1; }
    return origOpen(p, flags, mode);
}

int hookOpenat(int dirfd, const char* p, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
    if (procTarget(p)) {
        trace("openat", p);
        int fd = scrubbedOpen(p);
        if (fd >= 0) return fd;
        errno = EACCES;
        return -1;
    }
    if (hiddenPath(p)) { errno = ENOENT; return -1; }
    return origOpenat(dirfd, p, flags, mode);
}

FILE* hookFopen(const char* p, const char* mode) {
    if (procTarget(p)) {
        trace("fopen", p);
        int fd = scrubbedOpen(p);
        if (fd < 0) { errno = EACCES; return nullptr; }
        return fdopen(fd, "r");
    }
    if (hiddenPath(p)) { errno = ENOENT; return nullptr; }
    return origFopen(p, mode);
}

void patch(const char* name, void* replace, void** orig, const char* tag) {
    void* target = dlsym(RTLD_DEFAULT, name);
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
        out.swap(g_trace);
    }
    if (out.empty()) return nullptr;
    return env->NewStringUTF(out.c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_top_niunaijun_blackbox_core_NativeCore_ofxSetGuestPackage(JNIEnv *env, jclass, jstring pkg) {
    if (!pkg) return;
    const char* c = env->GetStringUTFChars(pkg, nullptr);
    if (!c) return;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        strncpy(g_pkg, c, sizeof(g_pkg) - 1);
        g_pkg[sizeof(g_pkg) - 1] = '\0';
    }
    env->ReleaseStringUTFChars(pkg, c);

    if (g_installed.exchange(true)) return;

    nlogRaw("install", g_pkg);
    patch("__system_property_get", (void*)hookPropGet, (void**)&origPropGet, "prop");
    patch("stat", (void*)hookStat, (void**)&origStat, "stat");
    patch("lstat", (void*)hookLstat, (void**)&origLstat, "lstat");
    patch("access", (void*)hookAccess, (void**)&origAccess, "access");
    patch("open", (void*)hookOpen, (void**)&origOpen, "open");
    patch("openat", (void*)hookOpenat, (void**)&origOpenat, "openat");
    patch("fopen", (void*)hookFopen, (void**)&origFopen, "fopen");
    nlogRaw("done", "hooks installed");
    HLOG("hardening installed for %s", g_pkg);
}
