// harden.cpp — real libc-level anti-detection for the BlackBox container.
//
// BlackBox ships Utils/AntiDetection.cpp, but its install_file_hooks() opens
// libc.so and closes it without ever patching a symbol — the file hooks are
// dead code. This file does the work for real, via Dobby (already vendored).
//
// Covered:
//   __system_property_get / __system_property_find   emulator + root props
//   stat / lstat / access                            root + container markers
//   open / openat / fopen                            /proc/self/maps|smaps|cmdline
//   uname                                            kernel banner
//   readdir                                          marker names in listings
//   execve / ptrace                                  su spawn, debugger attach
//
// Scrubbed /proc content is served from an anonymous memfd: no path exists on
// disk, nothing to find, and the fd is CLOEXEC.

#include <jni.h>
#include <android/log.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/ptrace.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>
#include <cerrno>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <string>
#include <atomic>

#include "Dobby/dobby.h"

#define HLOG(...) __android_log_print(ANDROID_LOG_INFO, "ofx-harden", __VA_ARGS__)

namespace {

std::atomic<bool> g_installed{false};

struct PropEntry { const char* key; const char* value; };

const PropEntry kProps[] = {
    {"ro.hardware",                "qcom"},
    {"ro.kernel.qemu",             ""},
    {"ro.kernel.qemu.gles",        ""},
    {"ro.boot.qemu",               ""},
    {"ro.product.model",           "SM-S918B"},
    {"ro.product.manufacturer",    "samsung"},
    {"ro.product.brand",           "samsung"},
    {"ro.product.device",          "dm3q"},
    {"ro.product.name",            "dm3qxx"},
    {"ro.product.board",           "kalama"},
    {"ro.build.tags",              "release-keys"},
    {"ro.build.type",              "user"},
    {"ro.build.host",              "r13"},
    {"ro.build.user",              "dpi"},
    {"ro.build.flavor",            "dm3qxx-user"},
    {"ro.build.version.release",   "14"},
    {"ro.build.version.sdk",       "34"},
    {"ro.build.fingerprint",       "samsung/dm3qxx/dm3q:14/UP1A.231005.007/S918BXXS5CWH6:user/release-keys"},
    {"ro.debuggable",              "0"},
    {"ro.secure",                  "1"},
    {"ro.adb.secure",              "1"},
    {"ro.boot.verifiedbootstate",  "green"},
    {"ro.boot.flash.locked",       "1"},
    {"ro.boot.vbmeta.device_state","locked"},
    {"ro.boot.veritymode",         "enforcing"},
    {"ro.sys.safemode",            "0"},
    {"ro.dalvik.vm.native.bridge", "0"},
    {"ro.enable.native.bridge.exec","0"},
    {"sys.oem_unlock_allowed",     "0"},
    {"ro.boot.warranty_bit",       "0"},
    {"ro.warranty_bit",            "0"},
    {"service.adb.root",           "0"},
    {"init.svc.vendor.qemu-props", ""},
};

const char* kHiddenProps[] = {
    "persist.magisk.hide",
    "ro.virtual",
    "ro.debuggable.qemu",
};

// Anything containing these is treated as a container fingerprint.
const char* kMarks[] = {
    "virtualapp", "vspace", "blackbox", "xposed", "magisk",
    "frida", "gum-js", "substrate", "tcpdump", "lspd",
    "multiapp", "dualapp", "parallel.",
};

const char* kPaths[] = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
    "/data/adb", "/system/app/Superuser.apk", "/dev/socket/su",
    "/system/lib/libdvm.so", "/system/lib64/libdvm.so",
    "/system/lib/libc_malloc_debug.so",
};

bool selfPath(const char* p) {
    return p && (strstr(p, "top.niunaijun.blackbox") != nullptr
              || strstr(p, "/data/app/") != nullptr);
}

bool hiddenPath(const char* p) {
    if (!p) return false;
    if (selfPath(p)) return false;
    for (const char* x : kPaths) if (strstr(p, x)) return true;
    for (const char* m : kMarks) if (strstr(p, m)) return true;
    return false;
}

// ---------------------------------------------------------------------------
// memfd-backed scrubbed file
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

bool procTarget(const char* p) {
    if (!p) return false;
    return strstr(p, "/proc/self/maps") || strstr(p, "/proc/self/smaps")
        || strstr(p, "/proc/self/task/") || strstr(p, "/proc/self/map_files")
        || strstr(p, "/proc/self/cmdline");
}

int scrubbedOpen(const char* path) {
    if (strstr(path, "cmdline")) {
        // Report the host process name; never recurse into fopen (hooked).
        std::string s = "top.niunaijun.blackbox";
        s.push_back('\0');
        return memfdFor(s);
    }

    int in = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
    if (in < 0) return in;

    std::string raw;
    char buf[8192];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) raw.append(buf, (size_t)n);
    close(in);

    std::string out;
    out.reserve(raw.size() + 64);
    size_t pos = 0;
    while (pos < raw.size()) {
        size_t nl = raw.find('\n', pos);
        if (nl == std::string::npos) nl = raw.size();
        std::string line = raw.substr(pos, nl - pos);
        pos = nl + 1;

        bool drop = false;
        for (const char* m : kMarks) if (line.find(m) != std::string::npos) { drop = true; break; }
        if (!drop && line.find("memfd:") != std::string::npos) drop = true;
        if (!drop && line.find("/dev/ashmem/") != std::string::npos) drop = true;
        if (!drop && line.find("/data/app/") != std::string::npos
            && line.find("base.apk!") != std::string::npos) drop = true;
        if (!drop) { out += line; out += '\n'; }
    }
    return memfdFor(out);
}

// ---------------------------------------------------------------------------
// hooks
// ---------------------------------------------------------------------------
typedef int (*propGetFn)(const char*, char*);
typedef const void* (*propFindFn)(const char*);
typedef int (*statFn)(const char*, struct stat*);
typedef int (*accessFn)(const char*, int);
typedef int (*openFn)(const char*, int, ...);
typedef int (*openatFn)(int, const char*, int, ...);
typedef FILE* (*fopenFn)(const char*, const char*);
typedef int (*unameFn)(struct utsname*);
typedef struct dirent* (*readdirFn)(DIR*);
typedef int (*execveFn)(const char*, char* const[], char* const[]);
typedef long (*ptraceFn)(int, pid_t, void*, void*);

propGetFn  origPropGet;
propFindFn origPropFind;
statFn     origStat, origLstat;
accessFn   origAccess;
openFn     origOpen;
openatFn   origOpenat;
fopenFn    origFopen;
unameFn    origUname;
readdirFn  origReaddir;
execveFn   origExecve;
ptraceFn   origPtrace;

int hookPropGet(const char* key, char* out) {
    if (!key) return origPropGet ? origPropGet(key, out) : 0;
    for (const auto& p : kProps) {
        if (strcmp(key, p.key) == 0) {
            size_t n = strlen(p.value);
            if (out) memcpy(out, p.value, n + 1);
            return (int)n;
        }
    }
    for (const char* h : kHiddenProps) {
        if (strcmp(key, h) == 0) { if (out) out[0] = '\0'; return 0; }
    }
    return origPropGet ? origPropGet(key, out) : 0;
}

const void* hookPropFind(const char* key) {
    if (key) {
        for (const char* h : kHiddenProps) if (strcmp(key, h) == 0) return nullptr;
        for (const char* m : kMarks) if (strstr(key, m)) return nullptr;
    }
    return origPropFind ? origPropFind(key) : nullptr;
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
        int fd = scrubbedOpen(p);
        if (fd >= 0) return fd;
        errno = EACCES; return -1;
    }
    if (hiddenPath(p)) { errno = ENOENT; return -1; }
    return origOpen(p, flags, mode);
}

int hookOpenat(int dirfd, const char* p, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
    if (procTarget(p)) {
        int fd = scrubbedOpen(p);
        if (fd >= 0) return fd;
        errno = EACCES; return -1;
    }
    if (hiddenPath(p)) { errno = ENOENT; return -1; }
    return origOpenat(dirfd, p, flags, mode);
}

FILE* hookFopen(const char* p, const char* mode) {
    if (procTarget(p)) {
        int fd = scrubbedOpen(p);
        if (fd < 0) { errno = EACCES; return nullptr; }
        return fdopen(fd, "r");
    }
    if (hiddenPath(p)) { errno = ENOENT; return nullptr; }
    return origFopen(p, mode);
}

int hookUname(struct utsname* u) {
    int r = origUname(u);
    if (r == 0) {
        snprintf(u->release, sizeof(u->release), "5.15.94-android13-8-31341897-abS918BXXS5CWH6");
        snprintf(u->version, sizeof(u->version), "#1 SMP PREEMPT Sat Jul 20 02:14:21 KST 2024");
        snprintf(u->machine, sizeof(u->machine), "aarch64");
    }
    return r;
}

struct dirent* hookReaddir(DIR* d) {
    struct dirent* e;
    while ((e = origReaddir(d)) != nullptr) {
        bool skip = false;
        for (const char* m : kMarks) if (strstr(e->d_name, m)) { skip = true; break; }
        if (!skip) return e;
    }
    return nullptr;
}

int hookExecve(const char* p, char* const argv[], char* const envp[]) {
    if (p && (hiddenPath(p) || strstr(p, "/su"))) { errno = ENOENT; return -1; }
    return origExecve(p, argv, envp);
}

long hookPtrace(int req, pid_t pid, void* addr, void* data) {
    if (req == PTRACE_ATTACH || req == PTRACE_SEIZE) { errno = EPERM; return -1; }
    return origPtrace(req, pid, addr, data);
}

void patch(const char* name, void* replace, void** orig) {
    void* target = dlsym(RTLD_DEFAULT, name);
    if (!target) { HLOG("missing: %s", name); return; }
    if (DobbyHook(target, replace, orig) != 0) HLOG("hook failed: %s", name);
}

} // namespace

extern "C" void ofx_install_hardening() {
    if (g_installed.exchange(true)) return;

    patch("__system_property_get", (void*)hookPropGet, (void**)&origPropGet);
    patch("__system_property_find", (void*)hookPropFind, (void**)&origPropFind);
    patch("stat", (void*)hookStat, (void**)&origStat);
    patch("lstat", (void*)hookLstat, (void**)&origLstat);
    patch("access", (void*)hookAccess, (void**)&origAccess);
    patch("open", (void*)hookOpen, (void**)&origOpen);
    patch("openat", (void*)hookOpenat, (void**)&origOpenat);
    patch("fopen", (void*)hookFopen, (void**)&origFopen);
    patch("uname", (void*)hookUname, (void**)&origUname);
    patch("readdir", (void*)hookReaddir, (void**)&origReaddir);
    patch("execve", (void*)hookExecve, (void**)&origExecve);
    patch("ptrace", (void*)hookPtrace, (void**)&origPtrace);

    HLOG("hardening installed");
}
