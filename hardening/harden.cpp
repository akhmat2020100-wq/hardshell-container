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
// Hook-select (bisect one hook group at a time, masks off):
//   If ANY of 128..2048 is set, ONLY those groups are installed.
//   If none is set, all hooks are installed (old behaviour: 0, 31, ...).
//  128  PROP group: __system_property_get, __system_property_find
//  256  OPEN group: open, openat, fopen, __open_2, __openat_2
//  512  STAT group: stat, lstat, access
// 1024  MISC group: uname, execve, readlink
// 2048  DL group: dl_iterate_phdr
// Examples (masks off, trampoline only): 128, 256, 512, 1024, 2048
//
// Everything is written straight into the append-mode fd the Java side hands
// over, so a native crash cannot swallow the trace. A SIGSEGV handler logs the
// faulting pc plus the /proc/self/maps line it belongs to; a heartbeat thread
// proves the process was alive and when it stopped being alive.

#include <jni.h>
#include <android/log.h>
#include <signal.h>
#include <ucontext.h>
#include <unwind.h>
#include <pthread.h>
#include <link.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/utsname.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <android/dlext.h>
#include <cerrno>
#include <cstring>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <string>
#include <vector>
#include <algorithm>
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
    M_UID       = 4096,   // native getuid/geteuid -> guest app uid
    M_NMS       = 8192,   // block libnms.so + trace dlopen names
    M_DLTRACE   = 16384,  // trace dlopen names only, nothing blocked
    M_NOLOG     = 32768,  // do not mirror liblog into hardbox-log.txt
    M_KILLTRACE = 65536,  // hook kill/tgkill/sigqueue, log the caller and its stack
    M_NOKILL    = 131072, // ...and swallow a self-directed SIGKILL instead of dying
    M_NOEXIT    = 262144, // swallow self exit()/_exit(), the verdict's second act
    M_PROPTRACE = 524288, // log every ro.* property and prop_info the guest asks for
    M_SYS       = 1048576,// trace libc syscall() calls made by the packer library
    M_SECCOMP   = 2097152,// seccomp-BPF: trap inline `svc` process/thread kills
    H_PROP      = 128,
    H_OPEN      = 256,
    H_STAT      = 512,
    H_MISC      = 1024,
    H_DL        = 2048,
};


std::atomic<bool> g_installed{false};
std::atomic<int>  g_budget{30000};
std::atomic<int>  g_lcatBudget{60000};
// One-shot: the first time the SDK logs its package verdict, photograph the
// stack that asked for it. Reading the client tells us nothing; the caller does.
std::atomic<bool> g_dexDump{false};
std::atomic<bool> g_hbStop{false};

int  g_logFd = -1;
int  g_mode  = 0;
int  g_guestUid = -1;
char g_pkg[128] = {0};
JavaVM* g_vm = nullptr;
std::mutex g_mtx;
std::string g_buf;

bool modeOn(int bit) { return (g_mode & bit) != 0; }

bool hookOn(int group) {
    const int any = H_PROP | H_OPEN | H_STAT | H_MISC | H_DL;
    if ((g_mode & any) == 0) return true;  // no selection: old behaviour, all hooks
    return (g_mode & group) != 0;
}

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

// Terminal-path records must never be dropped by the trace budget: an empty
// killblock line is indistinguishable from "the hook was never reached".
void nlogCrit(const char* tag, const char* detail) {
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

// Resolve which .so contains an address, using /proc/self/maps read through a
// raw syscall so the hook chain is never re-entered.
const char* libOf(void* addr, char* out, size_t cap) {
    if (cap == 0) return out;
    out[0] = '\0';
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return out;
    std::string data;
    char buf[8192];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) data.append(buf, (size_t)n);
    close(fd);
    uintptr_t a = (uintptr_t)addr;
    size_t pos = 0;
    while (pos < data.size()) {
        size_t nl = data.find('\n', pos);
        if (nl == std::string::npos) nl = data.size();
        std::string line = data.substr(pos, nl - pos);
        pos = nl + 1;
        unsigned long s = 0, e = 0, off = 0, ino = 0;
        char perms[8] = {0}, dev[16] = {0};
        int pathoff = 0;
        int got = sscanf(line.c_str(), "%lx-%lx %7s %lx %15s %lu %n",
                         &s, &e, perms, &off, dev, &ino, &pathoff);
        if (got >= 5 && a >= s && a < e) {
            const char* p = line.c_str() + pathoff;
            if (*p) {
                strncpy(out, p, cap - 1);
                out[cap - 1] = '\0';
            }
            return out;
        }
    }
    return out;
}

void traceLib(const char* tag, const char* s, void* ret) {
    if (!s || !firstTime(s)) return;
    char lib[200];
    libOf(ret, lib, sizeof(lib));
    char b[512];
    snprintf(b, sizeof(b), "%s @%s", s, lib[0] ? lib : "?");
    nlogRaw(tag, b);
}

// ---------------------------------------------------------------------------
// Raw-syscall observer for the packer.
//
// libloader.so imports libc's syscall() and reaches the filesystem through it:
// across three runs and 100k+ intercepted JNI calls, not one open/stat/access
// from that library ever reached the libc hooks - while the same library calls
// __system_property_get straight through the PLT, so the hooks do see it. A
// protector that owns syscall() can read /proc/self/maps, /proc/self/status or
// any /data path without a single interceptable libc frame, which is exactly
// the blind spot every file hook so far has been shouting about.
//
// The hook sits on libc's syscall() itself, attributes the call by return
// address and records the path argument where the syscall carries one.
// Nothing is rewritten in this build: it measures.
// ---------------------------------------------------------------------------
typedef long (*syscallFn)(long, ...);
static syscallFn g_origSyscall = nullptr;
static thread_local int t_inSyscall = 0;
std::atomic<int> g_sysSeen{0};

// Syscalls that carry a path pointer, and where that pointer sits.
static bool sysHasPath(long nr) {
    switch (nr) {
        case 56:   // openat(dirfd, path, flags, mode)
        case 48:   // faccessat(dirfd, path, mode)
        case 439:  // faccessat2(dirfd, path, mode, flags)
        case 437:  // openat2(dirfd, path, how, size)
        case 78:   // readlinkat(dirfd, path, buf, size)
        case 79:   // newfstatat(dirfd, path, statbuf, flags)
        case 291:  // statx(dirfd, path, flags, mask, buf)
        case 281:  // execveat(dirfd, path, argv, envp, flags)
        case 221:  // execve(path, argv, envp)
            return true;
        default:
            return false;
    }
}

// Numbers worth one line even without a path: directory walks and the three
// ways to end a process are how a scan and its verdict look from down here.
static bool sysInteresting(long nr) {
    switch (nr) {
        case 61:   // getdents64
        case 129:  // kill
        case 131:  // tgkill
        case 117:  // ptrace
            return true;
        default:
            return sysHasPath(nr);
    }
}

static long hookSyscall(long nr, ...) {
    va_list ap;
    va_start(ap, nr);
    long a[6];
    for (int i = 0; i < 6; i++) a[i] = va_arg(ap, long);
    va_end(ap);

    if (!g_origSyscall) return -1;
    if (t_inSyscall || !sysInteresting(nr))
        return g_origSyscall(nr, a[0], a[1], a[2], a[3], a[4], a[5]);

    t_inSyscall = 1;
    char lib[140];
    libOf(__builtin_return_address(0), lib, sizeof(lib));
    if (strstr(lib, "libloader") != nullptr) {
        const char* p = nullptr;
        if (sysHasPath(nr)) p = (const char*) (nr == 221 ? a[0] : a[1]);
        char key[320];
        if (p) snprintf(key, sizeof(key), "s%d|%.240s", (int) nr, p);
        else   snprintf(key, sizeof(key), "s%d|%ld|%ld", (int) nr, a[0], a[1]);
        if (firstTime(key)) {
            g_sysSeen.fetch_add(1);
            char b[460];
            if (p) snprintf(b, sizeof(b), "nr=%d %.230s @%s", (int) nr, p, lib);
            else   snprintf(b, sizeof(b), "nr=%d a0=%ld a1=%ld @%s",
                            (int) nr, a[0], a[1], lib);
            nlogCrit("sys", b);
        }
    }
    t_inSyscall = 0;

    return g_origSyscall(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
}

void logJavaStack();
void nativeStack();

// prio is ANDROID_LOG_*: UNKNOWN=0, DEFAULT=1, VERBOSE=2, DEBUG=3,
// INFO=4, WARN=5, ERROR=6, FATAL=7. The old table indexed from 0 and
// turned every DEBUG line into W.
static char prioChar(int prio) {
    switch (prio) {
        case 2: return 'V';
        case 3: return 'D';
        case 4: return 'I';
        case 5: return 'W';
        case 6: return 'E';
        case 7: return 'F';
        default: return '?';
    }
}

void emitLogLine(int prio, const char* tag, const char* msg) {
    if (!tag || !msg) return;
    if (strncmp(tag, "ofx-harden", 10) == 0) return;
    // Kumiho is Samsung's graphics decoder (/system/lib64/libkumiho.so), not
    // the guest's anti-tamper: it logs the host package because it lives in
    // the host process and asks who it is running under. Its policy file
    // (/system/etc/kumiho/Kumiho.policy) is a list of social apps to optimise.
    // Taking that line as the leak sent several builds after the wrong thing.
    if (g_lcatBudget.fetch_sub(1) <= 0) return;
    size_t n = strlen(msg);
    if (n > 300) n = 300;
    char b[420];
    int w = snprintf(b, sizeof(b), "%d log %c/%s: %.*s\n", (int)getpid(),
                     prioChar(prio), tag, (int)n, msg);
    if (w > 0) rawWrite(b, (size_t)(w > (int)sizeof(b) - 1 ? sizeof(b) - 1 : w));
}

// ---------------------------------------------------------------------------
// liblog mirror: the anti-cheat reports its own reasons through logd
// ---------------------------------------------------------------------------
typedef int (*logPrintFn)(int, const char*, const char*, ...);
typedef int (*logWriteFn)(int, const char*, const char*);
typedef int (*logVprintFn)(int, const char*, const char*, va_list);

logPrintFn  origLogPrint  = nullptr;
logWriteFn  origLogWrite  = nullptr;
logVprintFn origLogVprint = nullptr;

int hookLogWrite(int prio, const char* tag, const char* msg) {
    emitLogLine(prio, tag, msg);
    return origLogWrite ? origLogWrite(prio, tag, msg) : 0;
}

int hookLogPrint(int prio, const char* tag, const char* fmt, ...) {
    if (!fmt) return 0;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    emitLogLine(prio, tag, buf);
    return origLogWrite ? origLogWrite(prio, tag, buf) : 0;
}

int hookLogVprint(int prio, const char* tag, const char* fmt, va_list ap) {
    if (!fmt) return 0;
    char buf[512];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    emitLogLine(prio, tag, buf);
    return origLogWrite ? origLogWrite(prio, tag, buf) : 0;
}

// ---------------------------------------------------------------------------
// uid: Java Process.myUid() is already faked by the container, the raw libc
// call is not. Any anti-cheat can compare the two.
// ---------------------------------------------------------------------------
typedef uid_t (*uidFn)(void);
uidFn origGetuid = nullptr;
uidFn origGeteuid = nullptr;

uid_t hookGetuid() {
    if (g_guestUid >= 0) return (uid_t)g_guestUid;
    return origGetuid ? origGetuid() : (uid_t)-1;
}

uid_t hookGeteuid() {
    if (g_guestUid >= 0) return (uid_t)g_guestUid;
    return origGeteuid ? origGeteuid() : (uid_t)-1;
}

// ---------------------------------------------------------------------------
// dlopen: see every library the guest pulls in, optionally refuse the
// NetEase security module so the game has to continue without its verdict
// ---------------------------------------------------------------------------
typedef void* (*dlopenFn)(const char*, int);
typedef void* (*dlopenExtFn)(const char*, int, const void*);
dlopenFn origDlopen = nullptr;
dlopenExtFn origDlopenExt = nullptr;

bool nmsName(const char* n) {
    if (!n) return false;
    return strstr(n, "libnms.so") || strstr(n, "libpglarmor.so");
}

// Experiment switch, read once at boot from shared storage:
//   /storage/emulated/0/Download/hardbox-nofb.txt
// With the marker present, libFirebaseCppApp is denied at dlopen. If the engine
// is waiting on a Firebase call, the P/Invoke now throws instead of hanging and
// the game either handles it or falls over - both answers are worth having
// without another fifteen-minute build.
bool g_noFirebase = false;

// Every measurement added in v46 is behind a marker now. The v46 guest started
// dying 5 ms after Activity.onCreate at a fixed instruction inside
// libbinder_ndk, and v45 - which had none of this - did not. Until the new
// instrumentation is proven innocent, the default build is the v45 behaviour
// plus a real backtrace, and the probe comes back by dropping
//   /storage/emulated/0/Download/hardbox-probe.txt
bool g_probe = false;

bool noFbName(const char* n) {
    return n && strstr(n, "FirebaseCppApp");
}

std::atomic<int> g_dlFail{0};

// A dlopen that never returns and a dlopen that returns null look identical in
// a trace that only prints the name. Print the answer for the libraries the
// guest's engine actually needs, and for every failure.
//
// Note: never call dlerror() here. dlerror() is a one-shot queue - reading it
// clears it, so the caller that lost the library would later get nullptr where
// it expected a message. That is a null dereference planted inside ART.
void noteDl(const char* name, void* h) {
    if (!h) {
        int n = g_dlFail.fetch_add(1);
        if (name && n < 300) {
            char b[420];
            snprintf(b, sizeof(b), "FAIL %s", name);
            nlogCrit("dl", b);
        }
        return;
    }
    if (name && (strstr(name, "Firebase") || strstr(name, "libunity") ||
                 strstr(name, "libil2cpp") || strstr(name, "libmain") ||
                 strstr(name, "libloader"))) {
        char b[420];
        snprintf(b, sizeof(b), "OK %s h=%p", name, h);
        nlogCrit("dl", b);
    }
}

// Load a library explicitly into the linker's default namespace. A plain
// dlopen() resolves in the caller's namespace, which for code running out
// of libblackbox.so is the classloader namespace clns-9 - system libraries
// are not accessible there, so the lookup fails even for a library that is
// already loaded in the default namespace.
//
// Two ways, each logged so the next log shows exactly which step failed:
// (1) android_dlopen_ext with ANDROID_DLEXT_USE_NAMESPACE pointing at the
// exported "default" namespace (resolved with dlsym - the CI NDK stub does
// not export it for linking). (2) __loader_dlopen with a caller address
// inside the linker itself, so the linker derives the default namespace
// from that address.
void* dlopenRtDefaultNs(const char* path, int flags) {
    if (origDlopenExt) {
        typedef android_namespace_t* (*getExportedNsFn)(const char*);
        getExportedNsFn getNs = (getExportedNsFn)dlsym(RTLD_DEFAULT,
                                                        "android_get_exported_namespace");
        if (!getNs) {
            nlogCrit("dl", "RT-NS dlsym=null");
        } else {
            android_namespace_t* ns = getNs("default");
            if (!ns) {
                nlogCrit("dl", "RT-NS ns=null");
            } else {
                android_dlextinfo ext{};
                ext.flags = ANDROID_DLEXT_USE_NAMESPACE;
                ext.library_namespace = ns;
                void* h = origDlopenExt(path, flags, &ext);
                if (h) return h;
                nlogCrit("dl", "RT-NS ext=null");
            }
        }
    }
    typedef void* (*loaderDlopenFn)(const char*, int, const void*);
    loaderDlopenFn loaderDlopen = (loaderDlopenFn)dlsym(RTLD_DEFAULT, "__loader_dlopen");
    if (!loaderDlopen) {
        nlogCrit("dl", "RT-LOADER dlsym=null");
        return nullptr;
    }
    void* h = loaderDlopen(path, flags, (const void*)loaderDlopen);
    nlogCrit("dl", h ? "RT-LOADER OK" : "RT-LOADER FAIL");
    return h;
}

void* hookDlopen(const char* name, int flags) {
    if (name) trace("dlopen", name);
    if (g_noFirebase && noFbName(name)) {
        nlogCrit("blocked", name);
        errno = ENOENT;
        return nullptr;
    }
    if (modeOn(M_NMS) && nmsName(name)) {
        nlogRaw("blocked", name);
        errno = ENOENT;
        return nullptr;
    }
    void* r = origDlopen ? origDlopen(name, flags) : nullptr;
    // v55: the v54 retry by absolute path failed too - the linker log says
    // why. The dlopen is re-invoked from libblackbox.so, which lives in the
    // classloader namespace clns-9 (only the app's own lib dirs, permitted
    // paths /data), where /system/lib64/libandroid_runtime.so is not
    // accessible. The library IS loaded in the default namespace (its JNI
    // calls run fine all over the log). Load it explicitly into the default
    // namespace instead of relying on the caller's namespace.
    if (!r && name && strcmp(name, "libandroid_runtime.so") == 0) {
        r = dlopenRtDefaultNs("/system/lib64/libandroid_runtime.so", flags);
        if (!r) r = dlopenRtDefaultNs("/apex/com.android.runtime/lib64/libandroid_runtime.so", flags);
        nlogCrit("dl", r ? "RT-RETRY OK default-ns" : "RT-RETRY FAIL default-ns");
    }
    noteDl(name, r);
    return r;
}

void* hookDlopenExt(const char* name, int flags, const void* info) {
    if (name) trace("dlopen", name);
    if (g_noFirebase && noFbName(name)) {
        nlogCrit("blocked", name);
        errno = ENOENT;
        return nullptr;
    }
    if (modeOn(M_NMS) && nmsName(name)) {
        nlogRaw("blocked", name);
        errno = ENOENT;
        return nullptr;
    }
    void* r = origDlopenExt ? origDlopenExt(name, flags, info) : nullptr;
    // v55: same default-namespace retry as hookDlopen.
    if (!r && name && strcmp(name, "libandroid_runtime.so") == 0) {
        r = dlopenRtDefaultNs("/system/lib64/libandroid_runtime.so", flags);
        if (!r) r = dlopenRtDefaultNs("/apex/com.android.runtime/lib64/libandroid_runtime.so", flags);
        nlogCrit("dl", r ? "RT-RETRY OK default-ns" : "RT-RETRY FAIL default-ns");
    }
    noteDl(name, r);
    return r;
}

// ---------------------------------------------------------------------------
// kill: when the SDK decides the box is dirty it does not crash - it calls
// android.os.Process.sendSignal(myPid, 9) and the process evaporates without a
// single line of evidence. Catch the call, name the caller, keep the stack.
// ---------------------------------------------------------------------------
typedef int (*killFn)(pid_t, int);
typedef int (*tgkillFn)(pid_t, pid_t, int);
typedef int (*sigqueueFn)(pid_t, int, const union sigval);
killFn origKill = nullptr;
tgkillFn origTgkill = nullptr;
sigqueueFn origSigqueue = nullptr;

// A native stack only says "libart.so called kill". The Java stack says which
// class decided we were a threat - so pull it out of the VM while we're still
// alive to tell the story.
void logJavaStack() {
    if (!g_vm) return;
    JNIEnv* env = nullptr;
    if (g_vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK || !env) return;
    if (env->PushLocalFrame(96) != 0) return;
    jclass tcls = env->FindClass("java/lang/Throwable");
    if (tcls) {
        jmethodID ctor = env->GetMethodID(tcls, "<init>", "()V");
        jmethodID st = env->GetMethodID(tcls, "getStackTrace",
                                        "()[Ljava/lang/StackTraceElement;");
        if (ctor && st) {
            jobject t = env->NewObject(tcls, ctor);
            if (t) {
                jobjectArray arr = (jobjectArray)env->CallObjectMethod(t, st);
                if (arr) {
                    jsize n = env->GetArrayLength(arr);
                    for (jsize i = 0; i < n && i < 14; i++) {
                        jobject el = env->GetObjectArrayElement(arr, i);
                        if (!el) continue;
                        jclass elc = env->GetObjectClass(el);
                        jmethodID ts = elc ? env->GetMethodID(elc, "toString",
                                                              "()Ljava/lang/String;") : nullptr;
                        if (ts) {
                            jstring s = (jstring)env->CallObjectMethod(el, ts);
                            if (s) {
                                const char* c = env->GetStringUTFChars(s, nullptr);
                                if (c) {
                                    char b[360];
                                    snprintf(b, sizeof(b), "#%d %s", (int)i, c);
                                    nlogRaw("javabt", b);
                                    env->ReleaseStringUTFChars(s, c);
                                }
                                env->DeleteLocalRef(s);
                            }
                        }
                        if (elc) env->DeleteLocalRef(elc);
                        env->DeleteLocalRef(el);
                    }
                }
            }
        }
    }
    env->ExceptionClear();
    env->PopLocalFrame(nullptr);
}

// Same idea one layer down: which .so actually emitted the Kumiho line. The
// Java stack showed Unity's BitmapFactory, so the caller is native - this
// names the library and the offset inside it.
struct NTrace {
    int depth;
};

static _Unwind_Reason_Code ntCb(struct _Unwind_Context* ctx, void* arg) {
    NTrace* st = (NTrace*) arg;
    uintptr_t pc = (uintptr_t) _Unwind_GetIP(ctx);
    if (!pc) return _URC_NO_REASON;
    char lib[120];
    libOf((void*) pc, lib, sizeof(lib));
    char b[220];
    snprintf(b, sizeof(b), "nbt #%d %p @%s", st->depth, (void*) pc,
             lib[0] ? lib : "?");
    trace("nbt", b);
    st->depth++;
    return st->depth >= 12 ? _URC_END_OF_STACK : _URC_NO_REASON;
}

void nativeStack() {
    NTrace st = {0};
    _Unwind_Backtrace(ntCb, &st);
}

struct BtState {
    int depth;
};

static _Unwind_Reason_Code btCb(struct _Unwind_Context* ctx, void* arg) {
    BtState* st = (BtState*)arg;
    uintptr_t pc = (uintptr_t)_Unwind_GetIP(ctx);
    if (pc) {
        char lib[200];
        libOf((void*)pc, lib, sizeof(lib));
        char b[280];
        snprintf(b, sizeof(b), "#%d %p @%s", st->depth, (void*)pc, lib[0] ? lib : "?");
        nlogRaw("killbt", b);
    }
    st->depth++;
    return (st->depth >= 8) ? _URC_END_OF_STACK : _URC_NO_REASON;
}

// ---------------------------------------------------------------------------
// pthread_exit: the quiet way out.
//
// A thread that vanishes while the process lives can also end itself:  return
// from its start routine, or call pthread_exit directly. Unity's render thread
// leaves nativeRender and the pthread trampoline fires pthread_exit. Hook it
// and the log finally names the thread and the stack that ended it.
// ---------------------------------------------------------------------------
typedef void (*pthreadExitFn)(void*);
pthreadExitFn origPthreadExit = nullptr;

// forward decl: hookPthreadExit fires long before the dump below is seen
void dumpFpBacktrace(uintptr_t fp);

void hookPthreadExit(void* retval) {
    char lib[140];
    libOf(__builtin_return_address(0), lib, sizeof(lib));
    char b[220];
    snprintf(b, sizeof(b), "pthread_exit retval=%p @%s", retval,
             lib[0] ? lib : "?");
    nlogCrit("THREXIT", b);
    // v50: an unwind() call inside a thread that is tearing itself down can
    // recurse into the very unwinder the loader is unloading (v47 evidence).
    // The frame-pointer walk needs no library and answers the same question.
    uintptr_t fp = 0;
#if defined(__aarch64__)
    __asm__ volatile("mov %0, x29" : "=r"(fp));
#elif defined(__arm__)
    __asm__ volatile("mov %0, r11" : "=r"(fp));
#endif
    if (fp) dumpFpBacktrace(fp);
    if (origPthreadExit) origPthreadExit(retval);
}

// ---------------------------------------------------------------------------
// The verdict lives in a dex that is decrypted into memory, so it is nowhere
// on disk and no string scan of the APK can reach it. Find the dex magic in
// our own address space and write the whole thing out; the strings inside
// spell out exactly what the check looks at.
// ---------------------------------------------------------------------------
void writeDump(const char* dir, int idx, const unsigned char* p, size_t len) {
    char path[400];
    const char* dirs[3] = {dir, "/storage/emulated/0/Download", "/data/local/tmp"};
    int fd = -1;
    int err = 0;
    for (int i = 0; i < 3 && fd < 0; i++) {
        snprintf(path, sizeof(path), "%s/ofxdex_%d.dex", dirs[i], idx);
        fd = (int)syscall(SYS_openat, AT_FDCWD, path,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
        err = errno;
    }
    if (fd < 0) {
        // Every path outside the sandbox is walled off; the one handle we know
        // is writable is the log fd. Embed the dex behind a marker line and
        // carve it back out on the other side.
        char b[220];
        snprintf(b, sizeof(b), "all opens failed errno=%d (%s)", err, path);
        nlogRaw("DUMP", b);
        char h[64];
        int hl = snprintf(h, sizeof(h), "OFXDEX %d %zu\n", idx, len);
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            rawWrite(h, (size_t)hl);
            rawWrite((const char*)p, len);
            rawWrite("\n", 1);
        }
        nlogRaw("DUMP", "embedded");
        return;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, p + off, len - off);
        if (w <= 0) break;
        off += (size_t)w;
    }
    close(fd);
    char b[420];
    snprintf(b, sizeof(b), "%s len=%zu", path, len);
    nlogRaw("DUMP", b);
}

void writeNamed(const char* dir, const char* name, const void* p, size_t len) {
    char path[400];
    const char* dirs[3] = {dir, "/storage/emulated/0/Download", "/data/local/tmp"};
    int fd = -1;
    for (int i = 0; i < 3 && fd < 0; i++) {
        snprintf(path, sizeof(path), "%s/%s", dirs[i], name);
        fd = (int)syscall(SYS_openat, AT_FDCWD, path,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    }
    if (fd < 0) { nlogRaw("DUMP", "writeNamed open failed"); return; }
    const unsigned char* q = (const unsigned char*)p;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, q + off, len - off);
        if (w <= 0) break;
        off += (size_t)w;
    }
    close(fd);
    char b[220];
    snprintf(b, sizeof(b), "%s len=%zu", path, len);
    nlogRaw("DUMP", b);
}

// ---------------------------------------------------------------------------
// The verdict lives in a dex decrypted into the guest heap, so it is nowhere
// on disk. Read it through process_vm_readv: unlike a raw pointer walk, a
// hole in the heap returns EFAULT instead of taking the process down with
// SIGSEGV/SIGBUS — which is exactly how the first scanner killed itself.
// A candidate only counts once the whole dex header checks out, and the
// string table decides which one is worth keeping.
// ---------------------------------------------------------------------------
static std::atomic<int> g_vmMode{-1};   // -1 untried, 0 process_vm_readv, 1 /proc/self/mem
static int g_memFd = -1;

static ssize_t vmRead(void* dst, uintptr_t src, size_t len) {
    if (!len) return 0;
    if (g_vmMode.load() != 1) {
        struct iovec li;
        struct iovec ri;
        li.iov_base = dst;
        li.iov_len = len;
        ri.iov_base = (void*)src;
        ri.iov_len = len;
        long r = syscall(SYS_process_vm_readv, getpid(), &li, 1, &ri, 1, 0);
        if (r >= 0) {
            g_vmMode.store(0);
            return (ssize_t)r;
        }
        if (g_vmMode.load() == 0) return -1;   // worked before: real hole
    }
    if (g_memFd < 0) {
        g_memFd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/mem",
                               O_RDONLY | O_CLOEXEC);
        if (g_memFd < 0) return -1;
    }
    g_vmMode.store(1);
    return (ssize_t)syscall(SYS_pread64, g_memFd, dst, len, (off_t)src);
}

// Best-effort read: a bad page is zero-filled instead of ending the sweep.
static void readLoose(uintptr_t addr, unsigned char* dst, size_t len) {
    size_t got = 0;
    while (got < len) {
        size_t want = len - got;
        if (want > (size_t)(64 * 1024)) want = (size_t)(64 * 1024);
        ssize_t r = vmRead(dst + got, addr + got, want);
        if (r == (ssize_t)want) { got += want; continue; }
        if (r > 0) { got += (size_t)r; want -= (size_t)r; }
        size_t p = 0;
        while (p < want) {
            size_t n2 = want - p;
            if (n2 > 4096) n2 = 4096;
            if (vmRead(dst + got + p, addr + got + p, n2) != (ssize_t)n2)
                memset(dst + got + p, 0, n2);
            p += n2;
        }
        got += want;
    }
}

struct DexHead {
    uint32_t fileSize;
    uint32_t headerSize;
    uint32_t endian;
    uint32_t stringIdsSize;
    uint32_t stringIdsOff;
    uint32_t typeIdsSize;
    uint32_t typeIdsOff;
    uint32_t classDefsSize;
    uint32_t classDefsOff;
};

static bool dexHeadOk(uintptr_t addr, DexHead* out) {
    unsigned char h[0x70];
    readLoose(addr, h, sizeof(h));
    if (memcmp(h, "dex\n", 4) != 0) return false;
    if (h[7] != 0) return false;
    for (int i = 4; i < 7; i++)
        if (h[i] < '0' || h[i] > '9') return false;
    DexHead d;
    memset(&d, 0, sizeof(d));
    memcpy(&d.fileSize, h + 0x20, 4);
    memcpy(&d.headerSize, h + 0x24, 4);
    memcpy(&d.endian, h + 0x28, 4);
    memcpy(&d.stringIdsSize, h + 0x38, 4);
    memcpy(&d.stringIdsOff, h + 0x3C, 4);
    memcpy(&d.typeIdsSize, h + 0x40, 4);
    memcpy(&d.typeIdsOff, h + 0x44, 4);
    memcpy(&d.classDefsSize, h + 0x60, 4);
    memcpy(&d.classDefsOff, h + 0x64, 4);
    if (d.endian != 0x12345678u) return false;
    if (d.headerSize != 0x70u) return false;
    if (d.fileSize < 0x70u || d.fileSize > (64u << 20)) return false;
    if (d.stringIdsSize == 0) return false;
    if (d.stringIdsOff >= d.fileSize) return false;
    if ((uint64_t)d.stringIdsOff + (uint64_t)d.stringIdsSize * 4 > d.fileSize) return false;
    if (d.typeIdsSize &&
        (uint64_t)d.typeIdsOff + (uint64_t)d.typeIdsSize * 4 > d.fileSize) return false;
    if (d.classDefsSize &&
        (uint64_t)d.classDefsOff + (uint64_t)d.classDefsSize * 32 > d.fileSize) return false;
    *out = d;
    return true;
}

// How many entries of the dex string table mention the verdict classes.
static int dexNeedles(const unsigned char* d, size_t n, const DexHead& h) {
    int m = 0;
    uint32_t cap = h.stringIdsSize;
    if (cap > 120000) cap = 120000;
    for (uint32_t i = 0; i < cap; i++) {
        uint32_t off;
        memcpy(&off, d + h.stringIdsOff + (size_t)i * 4, 4);
        if (off >= n) continue;
        size_t p = off;
        uint32_t slen = 0;
        int shift = 0;
        for (int k = 0; k < 5 && p < n; k++) {
            unsigned char b = d[p++];
            slen |= (uint32_t)(b & 0x7f) << shift;
            shift += 7;
            if (!(b & 0x80)) break;
        }
        size_t avail = n - p;
        if (slen < avail) avail = slen;        // ASCII: uleb length == byte length
        if (avail > 400) avail = 400;
        const unsigned char* s = d + p;
        if (memmem(s, avail, "qnxUk1", 6) ||
            memmem(s, avail, "LqnxUk1", 7) ||
            memmem(s, avail, "Kumiho", 6)) m++;
    }
    return m;
}

// Compact dex: same header prefix, magic cdex00N. String ids sit where the
// standard dex keeps them, but the payload is usually copied, so match raw.
static bool cdexHeadOk(uintptr_t addr, DexHead* out) {
    unsigned char h[0x70];
    readLoose(addr, h, sizeof(h));
    if (memcmp(h, "cdex", 4) != 0) return false;
    if (h[7] != 0) return false;
    DexHead d;
    memset(&d, 0, sizeof(d));
    memcpy(&d.fileSize, h + 0x20, 4);
    memcpy(&d.headerSize, h + 0x24, 4);
    if (d.fileSize < 0x28u || d.fileSize > (64u << 20)) return false;
    if (d.headerSize < 0x28u || d.headerSize > 0x400u) return false;
    *out = d;
    return true;
}

static int rawNeedles(const unsigned char* d, size_t n) {
    int m = 0;
    if (memmem(d, n, "qnxUk1", 6)) m++;
    if (memmem(d, n, "LqnxUk1", 7)) m++;
    if (memmem(d, n, "Kumiho", 6)) m++;
    return m;
}

void dumpDecryptedDex() {
    if (g_dexDump.exchange(true)) return;
    nlogRaw("DUMP", "start v2");

    char dir[256] = {0};
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", g_logFd);
    ssize_t ln = (ssize_t)syscall(SYS_readlinkat, AT_FDCWD, link, dir, sizeof(dir) - 1);
    if (ln > 0) {
        dir[ln] = 0;
        char* slash = strrchr(dir, '/');
        if (slash) *slash = 0;
    }
    if (!dir[0]) snprintf(dir, sizeof(dir), "/storage/emulated/0/Download");
    nlogRaw("DUMP", dir);

    int mfd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (mfd < 0) { nlogRaw("DUMP", "maps open failed"); return; }
    std::string mbS;
    {
        char buf[8192];
        ssize_t n;
        while ((n = syscall(SYS_read, mfd, buf, sizeof(buf))) > 0)
            mbS.append(buf, (size_t)n);
    }
    syscall(SYS_close, mfd);
    if (mbS.empty()) { nlogRaw("DUMP", "maps read failed"); return; }
    writeNamed(dir, "ofxmaps.txt", mbS.data(), mbS.size());

    const size_t CHUNK = (size_t)1 << 20;
    const size_t OVER = 16;
    const size_t SCAN_CAP = (size_t)2560 << 20;
    const size_t REG_CAP = (size_t)512 << 20;

    unsigned char* buf = (unsigned char*)malloc(CHUNK + OVER);
    if (!buf) { nlogRaw("DUMP", "no scan buffer"); return; }

    // Regions are ranked, not walked in maps order: a 900 MB budget dies in
    // dalvik-main space long before the 4 MB [anon:dalvik-DEX data] mapping
    // that actually holds the decrypted payload. Dex-bearing mappings first.
    struct Reg {
        uintptr_t s, e;
        size_t len;
        int score;
        char path[160];
    };
    std::vector<Reg> regs;
    {
        const char* mb0 = mbS.c_str();
        size_t p0 = 0, n0 = mbS.size();
        while (p0 < n0) {
            const char* ls = mb0 + p0;
            const char* nl = strchr(ls, '\n');
            size_t llen = nl ? (size_t)(nl - ls) : (n0 - p0);
            std::string line(ls, llen);
            size_t dash = line.find('-');
            size_t sp = line.find(' ');
            if (dash != std::string::npos && sp != std::string::npos) {
                Reg r;
                memset(&r, 0, sizeof(r));
                r.s = (uintptr_t)strtoull(line.c_str(), nullptr, 16);
                r.e = (uintptr_t)strtoull(line.c_str() + dash + 1, nullptr, 16);
                size_t tsp = sp;
                while (tsp < line.size() && line[tsp] == ' ') tsp++;
                size_t pe = line.find(' ', tsp);
                if (pe == std::string::npos) pe = line.size();
                char perms[8] = {0};
                size_t pc = pe - tsp;
                if (pc > 7) pc = 7;
                memcpy(perms, line.data() + tsp, pc);
                size_t q = pe;
                for (int t = 0; t < 3; t++) {
                    while (q < line.size() && line[q] == ' ') q++;
                    while (q < line.size() && line[q] != ' ') q++;
                }
                while (q < line.size() && line[q] == ' ') q++;
                if (q < line.size()) {
                    size_t pl = line.size() - q;
                    if (pl > sizeof(r.path) - 1) pl = sizeof(r.path) - 1;
                    memcpy(r.path, line.c_str() + q, pl);
                    r.path[pl] = 0;
                }
                bool anon = (r.path[0] == 0) || (r.path[0] == '[');
                r.len = (r.e > r.s) ? (size_t)(r.e - r.s) : 0;
                if (perms[0] == 'r' && anon && r.len) {
                    const char* pth = r.path;
                    if (strstr(pth, "dalvik-DEX")) {
                        r.score = 0;
                    } else if (strstr(pth, "memfd")) {
                        r.score = 1;
                    } else if (strstr(pth, ".dex")) {
                        r.score = 2;
                    } else if (strstr(pth, "dalvik")) {
                        // jit / gc / allocator spaces never hold a dex image.
                        if (strstr(pth, "jit") || strstr(pth, "zygote") ||
                            strstr(pth, "alloc") || strstr(pth, "free-list") ||
                            strstr(pth, "mark-stack") || strstr(pth, "rosalloc") ||
                            strstr(pth, "non-moving") || strstr(pth, "indirect") ||
                            strstr(pth, "stack_and_tls")) {
                            r.score = 9;
                        } else {
                            r.score = 3;
                        }
                    } else {
                        // Bare anon rw-p of dex size is the likeliest home for a
                        // decrypted InMemoryDexClassLoader payload.
                        if (pth[0] == 0 && r.len >= (1u << 20) && r.len <= (64u << 20))
                            r.score = 2;
                        else
                            r.score = (pth[0] == 0) ? 3 : 4;
                    }
                    regs.push_back(r);
                }
            }
            if (!nl) break;
            p0 += (size_t)(nl - ls) + 1;
        }
    }
    std::stable_sort(regs.begin(), regs.end(),
                     [](const Reg& a, const Reg& b) { return a.score < b.score; });
    {
        char b[128];
        snprintf(b, sizeof(b), "regions ranked=%zu total=%zu", regs.size(), mbS.size());
        nlogRaw("DUMP", b);
    }

    int regions = 0, cands = 0, otherDumps = 0, matchDumps = 0;
    size_t scanned = 0;

    for (size_t ri = 0; ri < regs.size() && scanned < SCAN_CAP; ri++) {
        Reg& r = regs[ri];
        if (r.score >= 8) break;
        size_t len = r.len;
        if (len > REG_CAP) len = REG_CAP;
        regions++;
        if (r.score <= 2) {
            char rb[220];
            snprintf(rb, sizeof(rb), "hit region score=%d len=%zu %s", r.score, len, r.path);
            nlogRaw("DUMP", rb);
        }
        size_t rp = 0;
        while (rp < len && scanned < SCAN_CAP) {
            size_t want = len - rp;
            if (want > CHUNK + OVER) want = CHUNK + OVER;
            readLoose(r.s + rp, buf, want);
            size_t off = 0;
            while (off + 8 <= want) {
                unsigned char* md = (unsigned char*)memmem(buf + off, want - off, "dex\n", 4);
                unsigned char* mc = (unsigned char*)memmem(buf + off, want - off, "cdex", 4);
                unsigned char* m = md;
                bool compact = false;
                if (!m || (mc && mc < m)) {
                    m = mc;
                    compact = true;
                }
                if (!m) break;
                size_t i = (size_t)(m - buf);
                uintptr_t ca = r.s + rp + i;
                DexHead h;
                bool ok = compact ? cdexHeadOk(ca, &h) : dexHeadOk(ca, &h);
                if (ok) {
                    cands++;
                    unsigned char* dex = (unsigned char*)malloc(h.fileSize);
                    if (dex) {
                        readLoose(ca, dex, h.fileSize);
                        int mcount = compact ? rawNeedles(dex, h.fileSize)
                                             : dexNeedles(dex, h.fileSize, h);
                        char b[300];
                        snprintf(b, sizeof(b),
                                 "cand addr=0x%llx size=%u cdex=%d match=%d @%s",
                                 (unsigned long long)ca, h.fileSize, compact ? 1 : 0,
                                 mcount, r.path[0] ? r.path : "(anon)");
                        nlogRaw("DUMP", b);
                        if (mcount > 0) {
                            if (matchDumps < 4) {
                                char nm[48];
                                snprintf(nm, sizeof(nm), "ofxqnx_%d.dex", matchDumps);
                                writeNamed(dir, nm, dex, h.fileSize);
                                matchDumps++;
                            }
                        } else if (otherDumps < 3) {
                            char nm[48];
                            snprintf(nm, sizeof(nm), "ofxother_%d.dex", otherDumps);
                            writeNamed(dir, nm, dex, h.fileSize);
                            otherDumps++;
                        }
                        free(dex);
                    }
                }
                off = i + 4;
            }
            rp += CHUNK;
            scanned += want;
        }
        if (matchDumps > 0) break;
    }
    free(buf);

    char b[260];
    snprintf(b, sizeof(b), "done regions=%d cands=%d matchDumps=%d other=%d scanned=%zu mode=%d",
             regions, cands, matchDumps, otherDumps, scanned, g_vmMode.load());
    nlogRaw("DUMP", b);
}

__attribute__((noinline))
void killTrace(const char* fn, pid_t pid, int sig) {
    const bool self = (pid == getpid() || pid == 0);
    char lib[200];
    libOf(__builtin_return_address(0), lib, sizeof(lib));
    const bool fromLoader = strstr(lib, "libloader") != nullptr;

    // ART cycles threads with SIGURG/SIGSTOP all day long; those stay quiet
    // unless the packer library itself is the caller, which never happens by
    // accident. SIGKILL/SIGABRT always get a line.
    if (sig != SIGKILL && sig != SIGABRT && !fromLoader) return;
    char b[320];
    snprintf(b, sizeof(b), "%s pid=%d sig=%d self=%d @%s", fn, (int)pid, sig,
             self ? 1 : 0, lib[0] ? lib : "?");
    nlogRaw("KILL", b);
    if (self && sig == SIGKILL) {
        logJavaStack();
        BtState st = {0};
        _Unwind_Backtrace(btCb, &st);
        // The sweep touches the whole guest heap; keep it off the thread the
        // app is waiting on so a slow scan cannot turn into an ANR.
        pthread_t th;
        if (pthread_create(&th, nullptr,
                           [](void*) -> void* { dumpDecryptedDex(); return nullptr; },
                           nullptr) == 0) {
            pthread_detach(th);
        } else {
            dumpDecryptedDex();
        }
    }
}

bool selfKill(pid_t pid, int sig) {
    return (pid == getpid() || pid == 0) && sig == SIGKILL;
}

int hookKill(pid_t pid, int sig) {
    killTrace("kill", pid, sig);
    if (modeOn(M_NOKILL) && selfKill(pid, sig)) {
        nlogRaw("killblock", "self SIGKILL swallowed");
        return 0;
    }
    return origKill ? origKill(pid, sig) : -1;
}

int hookTgkill(pid_t tgid, pid_t tid, int sig) {
    killTrace("tgkill", tgid, sig);
    if (modeOn(M_NOKILL) && selfKill(tgid, sig)) {
        nlogRaw("killblock", "self SIGKILL swallowed (tgkill)");
        return 0;
    }
    return origTgkill ? origTgkill(tgid, tid, sig) : -1;
}

int hookSigqueue(pid_t pid, int sig, const union sigval val) {
    killTrace("sigqueue", pid, sig);
    if (modeOn(M_NOKILL) && selfKill(pid, sig)) {
        nlogRaw("killblock", "self SIGKILL swallowed (sigqueue)");
        return 0;
    }
    return origSigqueue ? origSigqueue(pid, sig, val) : -1;
}

// ---------------------------------------------------------------------------
// crash handler: sig + faulting pc + the maps line that owns it
//
// v46 used a 64 KB static buffer and a single read(), which is enough for a
// toy process and nowhere near enough for this one - the guest maps a 900 MB
// APK, three Unity data packs and every framework library, so the read came
// back truncated and the faulting pc resolved to nothing. Stream the file in
// 4 KB chunks instead and parse line by line; no size limit, no BSS bloat, and
// the range prefix survives truncation of an absurdly long pathname.
// ---------------------------------------------------------------------------
void mapsScan(uintptr_t pc) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;

    char buf[4096];
    char line[512];
    size_t len = 0;
    bool truncated = false;

    auto flush = [&]() {
        if (len == 0) return true;
        line[len] = '\0';
        unsigned long a = 0, b = 0;
        if (sscanf(line, "%lx-%lx", &a, &b) == 2 && pc >= a && pc < b) {
            nlogCrit("crashmap", line);
            return false;
        }
        return true;
    };

    bool keepGoing = true;
    for (;;) {
        ssize_t n = (ssize_t)syscall(SYS_read, fd, buf, sizeof(buf));
        if (n <= 0) break;
        for (ssize_t i = 0; i < n && keepGoing; i++) {
            char c = buf[i];
            if (c == '\n') {
                keepGoing = flush();
                len = 0;
                truncated = false;
            } else if (!truncated) {
                if (len < sizeof(line) - 1) {
                    line[len++] = c;
                } else {
                    truncated = true;
                }
            }
        }
        if (!keepGoing) break;
    }
    if (keepGoing) flush();

    syscall(SYS_close, fd);
}

// ---------------------------------------------------------------------------
// stack walk on the thread that is dying
//
// _Unwind_Backtrace returned zero frames inside the v48 guest: the lazy
// libunwind the walk needs is not in the guest's linker namespace, so the log
// stayed at "pc + silence". This walks the frame-pointer chain instead. Every
// arm64 frame compiled with frame pointers saves {x29, x30} as a pair at
// [fp], so from the crashing context's x29 the whole chain is (next_fp,
// caller_pc) pairs that pread64 from /proc/self/mem answers without any
// unwinder library. A null, backwards, oversized or misaligned link simply
// ends the walk - a garbage frame is a refused order, never a hang.
// ---------------------------------------------------------------------------
void logBtFrame(const char* tag, int n, uintptr_t pc) {
    // libOf reads /proc/self/maps, which answers inside a crash handler where
    // dladdr does not resolve guest-mapped libraries
    char lib[240];
    libOf((void*) pc, lib, sizeof(lib));
    char line[360];
    if (lib[0]) {
        snprintf(line, sizeof(line), "#%d %s pc=%p", n, lib, (void*)pc);
    } else {
        snprintf(line, sizeof(line), "#%d ?pc=%p", n, (void*)pc);
    }
    nlogCrit(tag, line);
}

// A stack full of garbage looks like a walk to nowhere. The fp-walk above
// assumed the crash thread was walking its own chain; v51 proved the chain
// was already torn - every entry that did resolve landed in libc's raise,
// which is our own handler's call. Scan the stack by address instead: read
// 8 KB above sp and print every word that libOf resolves to a library the
// guest actually loaded. The caller of libbinder_ndk+0x14bd4 is in there
// whether or not its frame pointer survived.
//
// v52 scanned BELOW sp and would have found nothing: on arm64 the stack
// grows down, so the caller's frame - saved return addresses included -
// lives at HIGHER addresses than the faulting sp. The v51 crashes prove
// it: x29 == sp there, and the word at [sp+8] held lr, i.e. live frame
// data sits at sp and above, not below it.
void dumpStackScan(uintptr_t sp) {
    static std::atomic<int> g_scanIn{0};
    if (g_scanIn.exchange(1)) {
        nlogCrit("scan", "re-entrant skipped");
        return;
    }
    char head[72];
    snprintf(head, sizeof(head), "sp=%p", (void*)sp);
    nlogCrit("scan", head);
    if (!sp) {
        g_scanIn.exchange(0);
        return;
    }
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/mem",
                          O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        g_scanIn.exchange(0);
        return;
    }
    // one page above the fault's sp, one word at a time: the caller frames
    // are above sp on arm64 (see comment above). pread64 past the top of
    // the stack mapping just returns short and is skipped.
    const int words = 1024;
    for (int i = 0; i < words; i++) {
        uintptr_t addr = sp + (uintptr_t)i * 8;
        uintptr_t val = 0;
        long n = (long)syscall(SYS_pread64, fd, &val, sizeof(val),
                               (off_t) addr);
        if (n != (long)sizeof(val)) continue;
        // a code address is usually page-aligned-ish and never tiny
        if (val < 0x4000) continue;
        char lib[220];
        libOf((void*) val, lib, sizeof(lib));
        if (!lib[0]) continue;
        // skip our own library and the peel libc: they are the handler, not
        // the caller. Everything else is a live suspect.
        if (strstr(lib, "blackbox") || strstr(lib, "harden")) continue;
        if (val == 0x73cc96a184 || val == 0x73cc95b450) continue;
        char line[360];
        snprintf(line, sizeof(line), "#%d %p %s", i, (void*) val, lib);
        nlogCrit("sbt", line);
    }
    syscall(SYS_close, fd);
    g_scanIn.exchange(0);
}

void dumpFpBacktrace(uintptr_t fp) {
    // a second fault arriving while the walk is running must not recurse:
    // the handler is not async-signal-safe against itself, one guard flag
    // makes a re-entrant call a one-line log instead of a nested death
    static std::atomic<int> g_btIn{0};
    if (g_btIn.exchange(1)) {
        nlogCrit("fbt", "re-entrant walk skipped");
        return;
    }
    char seed[80];
    snprintf(seed, sizeof(seed), "fp=%p", (void*)fp);
    nlogCrit("fbtseed", seed);
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/mem",
                          O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        g_btIn.exchange(0);
        return;
    }
    if (!fp) {
        nlogCrit("fbt", "no frame pointer in context");
    }
    for (int i = 0; fp && i < 28; i++) {
        uintptr_t dp[2] = {0, 0};
        long n = (long)syscall(SYS_pread64, fd, dp, sizeof(dp), (off_t)fp);
        if (n < (long)sizeof(dp)) break;
        uintptr_t savedFp = dp[0];
        uintptr_t caller  = dp[1];
        if (caller) logBtFrame("fbt", i, caller);
        // stop the chain the moment it stops looking like a chain
        if (!savedFp) break;
        if (savedFp <= fp) break;
        if ((savedFp - fp) > 0x100000) break;
        if (savedFp % 8) break;
        fp = savedFp;
    }
    syscall(SYS_close, fd);
    g_btIn.exchange(0);
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
    char b[512];
    int n = snprintf(b, sizeof(b), "sig=%d addr=%p pc=%p lr=%p sp=%p x29=%p",
             sig, si ? si->si_addr : nullptr, (void*)pc, (void*)lr, (void*)sp,
#if defined(__aarch64__)
             u ? (void*)(uintptr_t)u->uc_mcontext.regs[29] : 0);
#else
             nullptr);
#endif
#if defined(__aarch64__)
    // The faulting call's arguments. x0 is the null object the libbinder_ndk
    // instruction dereferenced (addr=0x8 means x0 itself was 0); x1-x7 may
    // still name what the call was for.
    if (u && n > 0 && (size_t)n < sizeof(b)) {
        snprintf(b + n, sizeof(b) - (size_t)n,
                 " x0=%p x1=%p x2=%p x3=%p x4=%p x5=%p x6=%p x7=%p",
                 (void*)(uintptr_t)u->uc_mcontext.regs[0],
                 (void*)(uintptr_t)u->uc_mcontext.regs[1],
                 (void*)(uintptr_t)u->uc_mcontext.regs[2],
                 (void*)(uintptr_t)u->uc_mcontext.regs[3],
                 (void*)(uintptr_t)u->uc_mcontext.regs[4],
                 (void*)(uintptr_t)u->uc_mcontext.regs[5],
                 (void*)(uintptr_t)u->uc_mcontext.regs[6],
                 (void*)(uintptr_t)u->uc_mcontext.regs[7]);
    }
#endif
    nlogCrit("CRASH", b);
    if (pc) mapsScan(pc);
#if defined(__aarch64__)
    if (u) dumpFpBacktrace((uintptr_t)u->uc_mcontext.regs[29]);
    if (u) dumpStackScan(sp);
#elif defined(__arm__)
    if (u) dumpFpBacktrace((uintptr_t)u->uc_mcontext.arm_fp);
    if (u) dumpStackScan(sp);
#endif
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
// seccomp: the one hook that sees an inline `svc #0`.
//
// A thread that dies while the whole process keeps running is the signature of
// tgkill(tgid=self, tid=target, SIGKILL). SIGKILL addressed to a single tid
// kills only that thread. Every libc wrapper in this file stays silent for it,
// because the packer loads x8 and issues `svc` directly. seccomp-BPF runs below
// libc, so the filter sees it anyway.
//
// The filter is argument-scoped: only the fatals trap, so ART's constant
// SIGURG/SIGSTOP thread bookkeeping (also tgkill) passes through untouched.
//   tgkill(tgid, tid, SIGKILL)
//   kill(pid, SIGKILL)
//   exit_group(status) / exit(status)
// The handler logs the trap and returns -EPERM from the syscall. The thread
// lives, the process lives, and the log names the exact call.
// ---------------------------------------------------------------------------
std::atomic<int> g_seccompArmed{0};

void sigSysHandler(int sig, siginfo_t* si, void* uc) {
    (void)sig;
    const int nr = si ? si->si_syscall : -1;
    ucontext_t* u = (ucontext_t*)uc;
#if defined(__aarch64__)
    if (u) {
        unsigned long long* r = (unsigned long long*)u->uc_mcontext.regs;
        char b[200];
        snprintf(b, sizeof(b), "trap nr=%d a0=%llu a1=%llu a2=%llu self=%d",
                 nr, r[0], r[1], r[2], (int)getpid());
        nlogRaw("SECCOMP", b);
        r[0] = (unsigned long long)(long long)-EPERM;
        return;
    }
#elif defined(__arm__)
    if (u) {
        char b[200];
        snprintf(b, sizeof(b), "trap nr=%d a0=%lu a1=%lu a2=%lu self=%d",
                 nr, (unsigned long)u->uc_mcontext.arm_r0,
                 (unsigned long)u->uc_mcontext.arm_r1,
                 (unsigned long)u->uc_mcontext.arm_r2, (int)getpid());
        nlogRaw("SECCOMP", b);
        u->uc_mcontext.arm_r0 = (unsigned long)(int)-EPERM;
        return;
    }
#endif
    // Not a seccomp trap: give SIGSYS back to the default action.
    signal(SIGSYS, SIG_DFL);
    raise(SIGSYS);
}

int installSeccomp() {
#if defined(__aarch64__)
    const uint32_t kArch = AUDIT_ARCH_AARCH64;
#elif defined(__arm__)
    const uint32_t kArch = AUDIT_ARCH_ARM;
#else
    return -1;
#endif

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigSysHandler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, nullptr) != 0) {
        nlogCrit("SECCOMP", "sigaction(SIGSYS) failed");
        return -1;
    }

    // 0  load arch
    // 1  arch == ours ? -> 3 : -> 2
    // 2  ALLOW
    // 3  load nr
    // 4  nr == exit_group ? -> 23 : fall through
    // 5  nr == exit       ? -> 24 : fall through
    // 6  nr == kill       ? -> 9  : fall through
    // 7  nr == tgkill     ? -> 16 : fall through
    // 8  ALLOW
    // 9  kill:   load args[0] (pid)
    // 10 pid == self ? -> 12 : -> 11
    // 11 ALLOW
    // 12 kill:   load args[1] (sig)
    // 13 sig == SIGKILL ? -> 15 : -> 14
    // 14 ALLOW
    // 15 TRAP
    // 16 tgkill: load args[0] (tgid)
    // 17 tgid == self ? -> 19 : -> 18
    // 18 ALLOW
    // 19 tgkill: load args[2] (sig)
    // 20 sig == SIGKILL ? -> 22 : -> 21
    // 21 ALLOW
    // 22 TRAP
    // 23 TRAP (exit_group)
    // 24 TRAP (exit)
    std::vector<struct sock_filter> p;
    auto put = [&](uint16_t code, uint32_t k) {
        struct sock_filter ins;
        memset(&ins, 0, sizeof(ins));
        ins.code = code; ins.k = k;
        p.push_back(ins);
        return (int)p.size() - 1;
    };
    auto branch = [&](uint16_t cmp, uint32_t k) {
        struct sock_filter ins;
        memset(&ins, 0, sizeof(ins));
        ins.code = (uint16_t)(BPF_JMP | cmp); ins.k = k;
        p.push_back(ins);
        return (int)p.size() - 1;
    };
    auto fix = [&](int at, int target, bool onTrue) {
        int d = target - at - 1;
        if (d < 0 || d > 255) { nlogCrit("SECCOMP", "branch out of range"); return; }
        if (onTrue) p[at].jt = (uint8_t)d;
        else        p[at].jf = (uint8_t)d;
    };

    const uint32_t self = (uint32_t)getpid();

    put(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    const int jArch   = branch(BPF_JEQ | BPF_K, kArch);
    const int iAllow0 = put(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    put(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
    const int jEg     = branch(BPF_JEQ | BPF_K, __NR_exit_group);
    const int jEx     = branch(BPF_JEQ | BPF_K, __NR_exit);
    const int jKill   = branch(BPF_JEQ | BPF_K, __NR_kill);
    const int jTg     = branch(BPF_JEQ | BPF_K, __NR_tgkill);
    const int iAllow1 = put(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    put(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]));
    const int jKillPid = branch(BPF_JEQ | BPF_K, self);
    const int iAllowK0 = put(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    put(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1]));
    const int jKillSig = branch(BPF_JEQ | BPF_K, SIGKILL);
    const int iAllowK1 = put(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    const int iTrapK   = put(BPF_RET | BPF_K, SECCOMP_RET_TRAP);

    put(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]));
    const int jTgTgid  = branch(BPF_JEQ | BPF_K, self);
    const int iAllowT0 = put(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    put(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2]));
    const int jTgSig   = branch(BPF_JEQ | BPF_K, SIGKILL);
    const int iAllowT1 = put(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    const int iTrapT   = put(BPF_RET | BPF_K, SECCOMP_RET_TRAP);

    const int iTrapEg  = put(BPF_RET | BPF_K, SECCOMP_RET_TRAP);
    const int iTrapEx  = put(BPF_RET | BPF_K, SECCOMP_RET_TRAP);

    (void)iAllow0; (void)iAllow1; (void)iAllowK0; (void)iAllowK1;
    (void)iAllowT0; (void)iAllowT1;

    fix(jArch, jEg, true);
    fix(jArch, iAllow0, false);
    fix(jEg, iTrapEg, true);
    fix(jEg, jEx, false);
    fix(jEx, iTrapEx, true);
    fix(jEx, jKill, false);
    fix(jKill, jKillPid, true);
    fix(jKill, jTg, false);
    fix(jKillPid, jKillSig, true);
    fix(jKillPid, iAllowK0, false);
    fix(jKillSig, iTrapK, true);
    fix(jKillSig, iAllowK1, false);
    fix(jTg, jTgTgid, true);
    fix(jTg, iAllow1, false);
    fix(jTgTgid, jTgSig, true);
    fix(jTgTgid, iAllowT0, false);
    fix(jTgSig, iTrapT, true);
    fix(jTgSig, iAllowT1, false);

    struct sock_fprog fp;
    fp.len = (unsigned short)p.size();
    fp.filter = const_cast<struct sock_filter*>(p.data());

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        char b[128];
        snprintf(b, sizeof(b), "PR_SET_NO_NEW_PRIVS errno=%d", errno);
        nlogCrit("SECCOMP", b);
        return -1;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fp) != 0) {
        char b[128];
        snprintf(b, sizeof(b), "PR_SET_SECCOMP errno=%d", errno);
        nlogCrit("SECCOMP", b);
        return -1;
    }
    g_seccompArmed.store(1);
    nlogCrit("SECCOMP", "armed: exit/exit_group/kill(SIGKILL)/tgkill(SIGKILL) -> SIGSYS");
    return 0;
}

// ---------------------------------------------------------------------------
// thread probe: a hang has a shape, and two numbers give it away.
//
// cpu  - ticks burned between beats. A player loop waiting on a socket spends
//        nothing; a retry spin owns a whole core; a deadlock spends nothing and
//        still never finishes, which is why cpu alone is not enough.
// sys  - the kernel's own answer for what the thread is sitting in. futex with
//        a shared address across two threads names a deadlock; ppoll with a
//        timeout names a poll loop; running names a spin.
//
// Read through raw syscalls so the file hooks cannot re-enter themselves.
// ---------------------------------------------------------------------------
struct ThrSlot {
    int  tid;
    long ticks;
};
static ThrSlot g_thr[256];
static int g_thrUsed = 0;

static int rawOpenRO(const char* path) {
    return (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
}

static int rawReadFd(int fd, char* buf, int cap) {
    if (cap <= 1) return 0;
    long n = syscall(SYS_read, fd, buf, (size_t)(cap - 1));
    if (n < 0) n = 0;
    buf[n] = '\0';
    return (int)n;
}

static bool probeWanted(const char* comm) {
    if (!comm[0]) return false;
    if (strstr(comm, "Unity")) return true;
    if (strstr(comm, "RenderThread")) return true;
    if (strstr(comm, "Job.Worker")) return true;
    if (strstr(comm, "ofx")) return false;
    if (strcmp(comm, "main") == 0) return true;
    return false;
}

static void probeOne(int tid) {
    char p[112];
    char comm[64] = {0};

    snprintf(p, sizeof(p), "/proc/self/task/%d/comm", tid);
    int fd = rawOpenRO(p);
    if (fd < 0) return;
    rawReadFd(fd, comm, sizeof(comm));
    syscall(SYS_close, fd);
    char* nl = strchr(comm, '\n');
    if (nl) *nl = '\0';
    if (!comm[0]) snprintf(comm, sizeof(comm), "?");

    long utime = 0, stime = 0;
    char st = '?';
    snprintf(p, sizeof(p), "/proc/self/task/%d/stat", tid);
    fd = rawOpenRO(p);
    if (fd >= 0) {
        char sb[1024];
        int got = rawReadFd(fd, sb, sizeof(sb));
        syscall(SYS_close, fd);
        if (got > 0) {
            char* rp = strrchr(sb, ')');
            if (rp && rp[1] == ' ') {
                sscanf(rp + 2,
                       "%c %*d %*d %*d %*d %*d %*lu %*lu %*lu %*lu %*lu %lu %lu",
                       &st, &utime, &stime);
            }
        }
    }

    long ticks = utime + stime;
    long delta = -1;
    int i = 0;
    for (; i < g_thrUsed; i++) {
        if (g_thr[i].tid == tid) {
            delta = ticks - g_thr[i].ticks;
            g_thr[i].ticks = ticks;
            break;
        }
    }
    if (i == g_thrUsed) {
        if (g_thrUsed < 256) {
            g_thr[g_thrUsed].tid = tid;
            g_thr[g_thrUsed].ticks = ticks;
            g_thrUsed++;
        }
    }

    // 100 jiffies per second on Android: 150 ticks over a 2 s beat is 75% of a core.
    bool hot = delta >= 150;
    bool watched = probeWanted(comm);
    if (!hot && !watched) return;

    char sc[120] = "?";
    snprintf(p, sizeof(p), "/proc/self/task/%d/syscall", tid);
    fd = rawOpenRO(p);
    if (fd >= 0) {
        char sb[200];
        rawReadFd(fd, sb, sizeof(sb));
        syscall(SYS_close, fd);
        char* e = strchr(sb, '\n');
        if (e) *e = '\0';
        sb[110] = '\0';
        snprintf(sc, sizeof(sc), "%s", sb[0] ? sb : "?");
    }

    char line[320];
    snprintf(line, sizeof(line), "THR id=%d name=%s st=%c cpu=%ldtck sys=%s",
             tid, comm, st, delta, sc);
    nlogCrit("probe", line);
}

struct ProbeDent {
    uint64_t       d_ino;
    int64_t        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[320];
};

static void threadProbe() {
    int dfd = rawOpenRO("/proc/self/task");
    if (dfd < 0) return;
    for (;;) {
        char db[4096];
        long n = syscall(SYS_getdents64, dfd, db, sizeof(db));
        if (n <= 0) break;
        for (long off = 0; off + 20 <= n; ) {
            ProbeDent* d = (ProbeDent*)(db + off);
            if (d->d_reclen < 20 || off + (long)d->d_reclen > n) break;
            off += d->d_reclen;
            if (d->d_name[0] < '0' || d->d_name[0] > '9') continue;
            probeOne(atoi(d->d_name));
        }
    }
    syscall(SYS_close, dfd);

    char b[48];
    snprintf(b, sizeof(b), "threads=%d", g_thrUsed);
    nlogCrit("probe", b);
}

// ---------------------------------------------------------------------------
// AAssetManager is deliberately NOT hooked here.
//
// It looked like the obvious door - Unity reads scene data through it and no
// open() ever reaches libc - but an inline hook on a libandroid.so entry point
// is a patch on the one library every AssetManager call in the process goes
// through. v46 put one there and the guest started dying in a loop 60 ms after
// Activity.onCreate, at a fixed pc, before a single asset was ever asked for.
// The measurement is not worth a crash: it comes back only if it can be done
// by patching the guest's own PLT instead of a system library's code.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// heartbeat: proves when the process stopped breathing
// ---------------------------------------------------------------------------
static void jniStrStats(char* out, size_t cap);

void* hbThread(void*) {
    for (int i = 0; i < 300 && !g_hbStop.load(); i++) {
        char b[160];
        if ((i % 5) == 0) {
            snprintf(b, sizeof(b), "hb %d", i);
            nlogRaw("alive", b);
        }
        if (g_probe) threadProbe();
        if ((i % 5) == 4) {
            char s[96];
            jniStrStats(s, sizeof(s));
            snprintf(b, sizeof(b), "%s", s);
            nlogCrit("jni", b);
        }
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
    // Kumiho asks for these two before it walks the package list. Answering
    // them as "disabled" is the documented off-switch for the SDK; an absent
    // prop (getprop returns 0) is what lets it continue into the scan.
    {"persist.kumiho.disabled",     "true"},
    {"persist.thirdparty.disabled", "true"},
};

const char* kHiddenProps[] = {
    "persist.magisk.hide",
    "ro.virtual",
    "ro.debuggable.qemu",
    "init.svc.magisk",
};

const char* kMarks[] = {
    "blackbox", "boxcore", "niunaijun", "sandhook", "virtualapp", "vspace",
    "xposed", "edxposed", "riru", "zygisk", "magisk", "frida", "gum-js",
    "substrate", "lspd", "multiapp", "dualapp", "parallel.", "dobby",
    "libxdl", "memfd:jit-cache", "sandvxposed", "vapp",
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

    // Virtual storage is <hostData>/blackbox/data/user/<n>/<pkg>. Collapse it
    // to what a real install shows, whatever the host package is named.
    static const char* kVirtual = "/blackbox/data/user/";
    size_t k = line.find(kVirtual);
    if (k != std::string::npos) {
        std::string tail = line.substr(k + strlen(kVirtual));
        size_t slash = tail.find('/');
        if (slash != std::string::npos) {
            line = "/data/user/" + tail;
        }
    }
    // Anything else under the container root is not a real app path.
    static const char* kRoots[] = {
        "/data/user/0/top.niunaijun.blackbox/files/blackbox/",
        "/data/data/top.niunaijun.blackbox/files/blackbox/",
        "/data/user/0/top.niunaijun.blackbox/",
        "/data/data/top.niunaijun.blackbox/",
    };
    for (const char* r : kRoots) replaceAll(line, r, app + "/");
    replaceAll(line, "/files/blackbox/", "/");
    replaceAll(line, "/blackbox/", "/");
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
        if (statusMode && line.compare(0, 4, "Uid:") == 0 && g_guestUid >= 0) {
            char u[96];
            snprintf(u, sizeof(u), "Uid:\t%d\t%d\t%d\t%d", g_guestUid, g_guestUid,
                     g_guestUid, g_guestUid);
            out += u;
            out += '\n';
            continue;
        }
        if (statusMode && line.compare(0, 4, "Gid:") == 0 && g_guestUid >= 0) {
            char g[96];
            snprintf(g, sizeof(g), "Gid:\t%d\t%d\t%d\t%d", g_guestUid, g_guestUid,
                     g_guestUid, g_guestUid);
            out += g;
            out += '\n';
            continue;
        }
        if (statusMode && line.compare(0, 10, "TracerPid:") == 0) {
            out += "TracerPid:\t0\n";
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
    if (modeOn(M_PROPTRACE) && strncmp(key, "ro.", 3) == 0) {
        int r = origPropGet ? origPropGet(key, out) : 0;
        char b[340];
        snprintf(b, sizeof(b), "%s=%s", key, out ? out : "");
        traceLib("propval", b, __builtin_return_address(0));
        return r;
    }
    trace("prop", key);
    int rc = -1;
    if (modeOn(M_PROPS)) {
        rc = -2;
        for (const char* h : kHiddenProps) {
            if (strcmp(key, h) == 0) { if (out) out[0] = '\0'; rc = 0; break; }
        }
        if (rc == -2) {
            for (const auto& p : kProps) {
                if (strcmp(key, p[0]) == 0) {
                    size_t n = strlen(p[1]);
                    if (out) memcpy(out, p[1], n + 1);
                    rc = (int) n;
                    break;
                }
            }
        }
        if (rc == -2) rc = origPropGet ? origPropGet(key, out) : 0;
    } else {
        rc = origPropGet ? origPropGet(key, out) : 0;
    }
    // The two Kumiho switches decide whether the SDK proceeds into its scan,
    // so their answered value is worth one line each launch.
    if (strstr(key, "kumiho") || strstr(key, "thirdparty")) {
        char b[200];
        snprintf(b, sizeof(b), "%s=%s rc=%d", key, out ? out : "", rc);
        nlogCrit("prop", b);
    }
    return rc;
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

// The SDK's second act, after the kill signal is refused, is a normal process
// exit. Swallow it for the same reason the signal is swallowed: the verdict
// must not be able to end the process by any route.
typedef void (*exitFn)(int);
exitFn origExit = nullptr;
exitFn origExitRaw = nullptr;
exitFn origExitUpper = nullptr;

void exitCommon(int code, exitFn orig, const char* name) {
    if (modeOn(M_NOEXIT)) {
        char b[160];
        snprintf(b, sizeof(b), "self %s(%d) swallowed", name, code);
        nlogCrit("killblock", b);
        return;
    }
    if (orig) orig(code);
}

void hookExit(int code)      { exitCommon(code, origExit, "exit"); }
void hookExitRaw(int code)   { exitCommon(code, origExitRaw, "_exit"); }
void hookExitUpper(int code) { exitCommon(code, origExitUpper, "_Exit"); }

// libc exit() is the last step. System.exit() first shuts the VM down,
// then calls it: swallowing exit() leaves a dead runtime behind. Stop the
// call at AndroidRuntime::exit / JVM_Exit / JVM_Halt, before the shutdown
// sequence starts.
typedef void (*jvmExitFn)(int);
jvmExitFn origJvmExit = nullptr;
jvmExitFn origJvmHalt = nullptr;
typedef void (*androidRuntimeExitFn)(void*, int);
androidRuntimeExitFn origAndroidRuntimeExit = nullptr;

void hookJvmExit(int code) {
    if (modeOn(M_NOEXIT)) {
        char b[96];
        snprintf(b, sizeof(b), "JVM_Exit(%d) swallowed", code);
        nlogCrit("killblock", b);
        return;
    }
    if (origJvmExit) origJvmExit(code);
}

void hookJvmHalt(int code) {
    if (modeOn(M_NOEXIT)) {
        char b[96];
        snprintf(b, sizeof(b), "JVM_Halt(%d) swallowed", code);
        nlogCrit("killblock", b);
        return;
    }
    if (origJvmHalt) origJvmHalt(code);
}

void hookAndroidRuntimeExit(void* self, int code) {
    if (modeOn(M_NOEXIT)) {
        char b[112];
        snprintf(b, sizeof(b), "AndroidRuntime::exit(%d) swallowed", code);
        nlogCrit("killblock", b);
        return;
    }
    if (origAndroidRuntimeExit) origAndroidRuntimeExit(self, code);
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
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/"))) traceLib("stat", p, __builtin_return_address(0));
    return origStat(p, b);
}
int hookLstat(const char* p, struct stat* b) {
    if (modeOn(M_ROOTPATHS) && hiddenPath(p)) { errno = ENOENT; return -1; }
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/"))) traceLib("lstat", p, __builtin_return_address(0));
    return origLstat(p, b);
}
int hookAccess(const char* p, int m) {
    if (modeOn(M_ROOTPATHS) && hiddenPath(p)) { errno = ENOENT; return -1; }
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/"))) traceLib("access", p, __builtin_return_address(0));
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
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/"))) traceLib("open", p, __builtin_return_address(0));
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
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/"))) traceLib("openat", p, __builtin_return_address(0));
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
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/"))) traceLib("open2", p, __builtin_return_address(0));
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
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/"))) traceLib("openat2", p, __builtin_return_address(0));
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
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/")))
        traceLib("fopen", p, __builtin_return_address(0));
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
    if (p && (strstr(p, "/proc/") || strstr(p, "/sys/"))) traceLib("readlink", p, __builtin_return_address(0));
    if (r > 0 && buf && marked(buf) && modeOn(M_MAPS)) {
        std::string s(buf, (size_t)r);
        rewritePaths(s);
        if (marked(s.c_str())) {
            // Still smells of the container after rewriting: pretend the fd
            // was closed under us instead of handing over the tell.
            errno = ENOENT;
            return -1;
        }
        size_t c = s.size() < n ? s.size() : n;
        memcpy(buf, s.data(), c);
        return (ssize_t)c;
    }
    return r;
}

void* sym(const char* name) { return dlsym(RTLD_DEFAULT, name); }

void* symLib(const char* lib, const char* name) {
    void* h = dlopen(lib, RTLD_NOW);
    return h ? dlsym(h, name) : nullptr;
}

void patch(const char* name, void* replace, void** orig, const char* tag) {
    void* target = sym(name);
    if (!target) { nlogRaw("miss", name); return; }
    if (DobbyHook(target, replace, orig) != 0) { nlogRaw("fail", name); return; }
    nlogRaw("hook", tag ? tag : name);
}

// NDK entry points live in libandroid.so and are not in the default lookup
// scope of a guest process, so they need the handle.
void patchLib(const char* lib, const char* name, void* replace, void** orig,
              const char* tag) {
    void* target = symLib(lib, name);
    if (!target) {
        char b[160];
        snprintf(b, sizeof(b), "miss %s@%s", name, lib);
        nlogRaw("patch", b);
        return;
    }
    if (DobbyHook(target, replace, orig) != 0) {
        char b[160];
        snprintf(b, sizeof(b), "fail %s@%s", name, lib);
        nlogRaw("patch", b);
        return;
    }
    nlogRaw("hook", tag ? tag : name);
}

void logSymbols() {
    char b[256];
    snprintf(b, sizeof(b), "open=%p open2=%p openat=%p openat2=%p prop=%p propfind=%p",
             sym("open"), sym("__open_2"), sym("openat"), sym("__openat_2"),
             sym("__system_property_get"), sym("__system_property_find"));
    nlogRaw("sym", b);
}

// ---------------------------------------------------------------------------
// JNI bridge interception - AppDome / Kumiho native surface
//
// AppDome binds its native methods through RegisterNatives while its library
// loads, so the Java side never references a Java_* export. libart exports no
// C++ symbol for that entry point, but the JNIEnv function table is one
// process-wide struct and its slot order is ABI-fixed. Slot 219 is GetJavaVM:
// probe it first and require it to answer with our own VM before touching the
// neighbouring slot. Only then is slot 215 known to be RegisterNatives.
//
// Threat-state query shape: javaMethod(String[] names) -> boolean[].
// Reporting all-false means "no threat active" for every name the SDK asks
// about, which is what keeps the verdict screen from ever being scheduled.
// ---------------------------------------------------------------------------
typedef jint (*regNativesFn)(JNIEnv*, jclass, const JNINativeMethod*, jint);
static regNativesFn g_origRegNatives = nullptr;
static std::atomic<int> g_jniLog{0};

static void jniClassName(JNIEnv* env, jclass cls, char* out, size_t cap) {
    out[0] = '\0';
    if (!cls) return;
    jclass classClass = env->FindClass("java/lang/Class");
    if (!classClass) { env->ExceptionClear(); return; }
    jmethodID getName = env->GetMethodID(classClass, "getName", "()Ljava/lang/String;");
    if (!getName) { env->ExceptionClear(); env->DeleteLocalRef(classClass); return; }
    jstring s = (jstring) env->CallObjectMethod(cls, getName);
    if (s) {
        const char* c = env->GetStringUTFChars(s, nullptr);
        if (c) {
            snprintf(out, cap, "%s", c);
            env->ReleaseStringUTFChars(s, c);
        }
        env->DeleteLocalRef(s);
    }
    env->DeleteLocalRef(classClass);
    env->ExceptionClear();
}

// Answers "nothing is wrong" for any threat list. Enumeration in ART may hand
// the array back with the length the caller asked for; keep it exact.
static jbooleanArray JNICALL stubThreatState(JNIEnv* env, jclass, jobjectArray names) {
    jsize n = names ? env->GetArrayLength(names) : 0;
    if (n < 0) n = 0;
    jbooleanArray out = env->NewBooleanArray(n > 0 ? n : 1);
    if (!out) return nullptr;
    jboolean zero[64];
    memset(zero, 0, sizeof(zero));
    for (jsize off = 0; off < n; ) {
        jsize chunk = (n - off) > 64 ? 64 : (n - off);
        env->SetBooleanArrayRegion(out, off, chunk, zero);
        off += chunk;
    }
    return out;
}

static jint JNICALL hookRegNatives(JNIEnv* env, jclass cls,
                                   const JNINativeMethod* methods, jint n) {
    if (!g_origRegNatives) return JNI_ERR;
    if (!methods || n <= 0) return g_origRegNatives(env, cls, methods, n);

    char cn[192];
    jniClassName(env, cls, cn, sizeof(cn));

    // Only the decrypted AppDome package may be rewritten. The prefix is
    // stable for this APK build (qnxUk1.* shows up in every kill stack) and
    // rotates with a new Fusion build, not between launches. Anything that
    // looks like a normal vendor/java package is left alone even if the
    // signature matches, so unrelated SDKs keep their own answers.
    static const char* kKeep[] = {
        "android.", "java.", "javax.", "dalvik.", "kotlin.",
        "com.", "org.", "net.", "io.", "androidx."
    };
    bool skip = false;
    for (const char* k : kKeep) {
        if (strncmp(cn, k, strlen(k)) == 0) { skip = true; break; }
    }
    bool appdome = !skip && cn[0] != '\0';

    JNINativeMethod local[64];
    JNINativeMethod* arr = local;
    if (n > 64) {
        arr = (JNINativeMethod*) malloc(sizeof(JNINativeMethod) * (size_t) n);
        if (!arr) return g_origRegNatives(env, cls, methods, n);
    }
    memcpy(arr, methods, sizeof(JNINativeMethod) * (size_t) n);

    int swapped = 0;
    bool announce = (appdome || firstTime(cn)) && g_jniLog.fetch_add(1) < 200;
    for (jint i = 0; i < n; i++) {
        const char* nm  = methods[i].name ? methods[i].name : "?";
        const char* sig = methods[i].signature ? methods[i].signature : "";
        if (announce) {
            char b[360];
            snprintf(b, sizeof(b), "%s %s%s", cn[0] ? cn : "?", nm, sig);
            nlogCrit("jni", b);
        }
        if (appdome && strcmp(sig, "([Ljava/lang/String;)[Z") == 0) {
            arr[i].fnPtr = (void*) stubThreatState;
            swapped++;
        }
    }

    jint rc = g_origRegNatives(env, cls, arr, n);
    if (swapped) {
        char b[240];
        snprintf(b, sizeof(b), "threat-state forced clean n=%d rc=%d class=%s",
                 swapped, (int) rc, cn);
        nlogCrit("jni", b);
    }
    if (arr != local) free(arr);
    return rc;
}

// ---------------------------------------------------------------------------
// Host-package string rewrite at the JNI boundary.
//
// Kumiho logs `getPackageName: top.niunaijun.blackbox` from native code while
// the Java thread sits inside Unity's BitmapFactory call - so the read is a
// JNI call made by AppDome's own library, not a Java-side getPackageName().
// BlackBox already makes every Java surface answer with the guest package, so
// the only way that host string reaches native is the return value of an
// object-returning JNI call. Rewrite exactly that value: if a call hands back
// a java.lang.String equal to the host package, hand back the guest package
// instead. Nothing else is touched - every other return keeps its identity.
//
// Slots used (ABI-fixed JNINativeInterface order, same table as RegisterNatives):
//   35  CallObjectMethodV        36  CallObjectMethodA
//   65  CallNonvirtualObjectMethodV  66  CallNonvirtualObjectMethodA
//   115 CallStaticObjectMethodV  116 CallStaticObjectMethodA
// The variadic CallObjectMethod(...) entry packs into a va_list and forwards to
// slot 35 inside libart, so this covers it too.
// ---------------------------------------------------------------------------
typedef jobject (*callObjVFn)(JNIEnv*, jobject, jmethodID, va_list);
typedef jobject (*callObjAFn)(JNIEnv*, jobject, jmethodID, const jvalue*);
typedef jobject (*callNvObjVFn)(JNIEnv*, jobject, jclass, jmethodID, va_list);
typedef jobject (*callNvObjAFn)(JNIEnv*, jobject, jclass, jmethodID, const jvalue*);
typedef jobject (*callStObjVFn)(JNIEnv*, jclass, jmethodID, va_list);
typedef jobject (*callStObjAFn)(JNIEnv*, jclass, jmethodID, const jvalue*);

static callObjVFn   g_origObjV   = nullptr;
static callObjAFn   g_origObjA   = nullptr;
static callNvObjVFn g_origNvObjV = nullptr;
static callNvObjAFn g_origNvObjA = nullptr;
static callStObjVFn g_origStObjV = nullptr;
static callStObjAFn g_origStObjA = nullptr;
static jclass       g_strCls     = nullptr;
static std::atomic<int> g_strHits{0};
static std::atomic<int> g_strCalls{0};

// Called with a fully-formed return value. Cheap rejects first: null and any
// non-string object leave immediately, so ordinary JNI traffic pays two loads
// and one vtable call, not a UTF conversion.
static inline jstring rewriteHostString(JNIEnv* env, jobject res) {
    if (!res || !g_strCls) return (jstring) res;
    if (g_strCalls.fetch_add(1, std::memory_order_relaxed) >= 2000000) return (jstring) res;
    if (!env->IsInstanceOf(res, g_strCls)) return (jstring) res;
    const char* c = env->GetStringUTFChars((jstring) res, nullptr);
    if (!c) { env->ExceptionClear(); return (jstring) res; }
    bool host = (strcmp(c, "top.niunaijun.blackbox") == 0);
    env->ReleaseStringUTFChars((jstring) res, c);
    if (!host) return (jstring) res;
    const char* guest = guestPkg();
    if (!guest || !guest[0]) return (jstring) res;
    jstring fixed = env->NewStringUTF(guest);
    if (!fixed) { env->ExceptionClear(); return (jstring) res; }
    if (g_strHits.fetch_add(1) < 8) {
        char lib[80];
        libOf(__builtin_return_address(0), lib, sizeof(lib));
        char b[200];
        snprintf(b, sizeof(b), "host string -> %s caller=%s", guest, lib);
        nlogCrit("jni", b);
    }
    return fixed;
}

static jobject JNICALL hookObjV(JNIEnv* env, jobject o, jmethodID m, va_list a) {
    if (!g_origObjV) return nullptr;
    return rewriteHostString(env, g_origObjV(env, o, m, a));
}
static jobject JNICALL hookObjA(JNIEnv* env, jobject o, jmethodID m, const jvalue* a) {
    if (!g_origObjA) return nullptr;
    return rewriteHostString(env, g_origObjA(env, o, m, a));
}
static jobject JNICALL hookNvObjV(JNIEnv* env, jobject o, jclass c, jmethodID m, va_list a) {
    if (!g_origNvObjV) return nullptr;
    return rewriteHostString(env, g_origNvObjV(env, o, c, m, a));
}
static jobject JNICALL hookNvObjA(JNIEnv* env, jobject o, jclass c, jmethodID m, const jvalue* a) {
    if (!g_origNvObjA) return nullptr;
    return rewriteHostString(env, g_origNvObjA(env, o, c, m, a));
}
static jobject JNICALL hookStObjV(JNIEnv* env, jclass c, jmethodID m, va_list a) {
    if (!g_origStObjV) return nullptr;
    return rewriteHostString(env, g_origStObjV(env, c, m, a));
}
static jobject JNICALL hookStObjA(JNIEnv* env, jclass c, jmethodID m, const jvalue* a) {
    if (!g_origStObjA) return nullptr;
    return rewriteHostString(env, g_origStObjA(env, c, m, a));
}

// Read by the heartbeat so one log line tells us whether the object-return
// hooks are in the path at all. calls==0 means native never used these slots
// and the leak reaches Kumiho by some other route.
std::atomic<int> g_identHits{0};

static void jniStrStats(char* out, size_t cap) {
    snprintf(out, cap, "strCalls=%d hits=%d ident=%d sys=%d",
             g_strCalls.load(), g_strHits.load(), g_identHits.load(), g_sysSeen.load());
}

// ---------------------------------------------------------------------------
// Identity-string observer: the slots that actually hand a package name to
// native code.
//
// Kumiho turned out to be Samsung's graphics decoder, so its log line was
// noise. What is still unexplained is how the guest decides we are a
// container. These hooks watch the three ways a native caller can obtain a
// host-looking string without any object-returning call:
//
//   167 NewStringUTF       - string built in C and pushed into Java
//   169 GetStringUTFChars  - string fetched earlier, materialised now
//   95  GetObjectField     - ApplicationInfo.packageName / dataDir / sourceDir
//   145 GetStaticObjectField - ActivityThread.mBoundApplication, Build fields
//
// Matches are logged with the calling library so a hit names its own source.
// Nothing is rewritten here: this run is measurement, not masking.
// ---------------------------------------------------------------------------
typedef jstring (*newStrUtfFn)(JNIEnv*, const char*);
typedef const char* (*getStrUtfFn)(JNIEnv*, jstring, jboolean*);
typedef jobject (*getObjFieldFn)(JNIEnv*, jobject, jfieldID);
typedef jobject (*getStObjFieldFn)(JNIEnv*, jclass, jfieldID);

static newStrUtfFn    g_origNewStrUtf  = nullptr;
static getStrUtfFn    g_origGetStrUtf  = nullptr;
static getObjFieldFn  g_origGetObjFld  = nullptr;
static getStObjFieldFn g_origGetStObjFld = nullptr;

static bool identityish(const char* s) {
    if (!s) return false;
    return strstr(s, "niunaijun") != nullptr ||
           strstr(s, "blackbox")  != nullptr ||
           strstr(s, "Virtualized") != nullptr ||
           strstr(s, "Detected by") != nullptr ||
           strstr(s, "AppDome") != nullptr;
}

static void noteIdentity(const char* where, const char* s, void* ret) {
    if (!identityish(s)) return;
    int n = g_identHits.fetch_add(1);
    if (n >= 300) return;
    char lib[200];
    libOf(ret, lib, sizeof(lib));
    char b[520];
    snprintf(b, sizeof(b), "%s caller=%s val=%.260s", where,
             lib[0] ? lib : "?", s);
    nlogCrit("ident", b);
}

static jstring JNICALL hookNewStrUtf(JNIEnv* env, const char* s) {
    if (!g_origNewStrUtf) return nullptr;
    noteIdentity("NewStringUTF", s, __builtin_return_address(0));
    return g_origNewStrUtf(env, s);
}

static jobject JNICALL hookGetObjFld(JNIEnv* env, jobject o, jfieldID f) {
    if (!g_origGetObjFld) return nullptr;
    jobject r = g_origGetObjFld(env, o, f);
    if (r && g_strCls && env->IsInstanceOf(r, g_strCls)) {
        const char* c = g_origGetStrUtf ? g_origGetStrUtf(env, (jstring) r, nullptr) : nullptr;
        if (c) {
            noteIdentity("GetObjectField", c, __builtin_return_address(0));
            env->ReleaseStringUTFChars((jstring) r, c);
        } else {
            env->ExceptionClear();
        }
    }
    return r;
}

static jobject JNICALL hookGetStObjFld(JNIEnv* env, jclass k, jfieldID f) {
    if (!g_origGetStObjFld) return nullptr;
    jobject r = g_origGetStObjFld(env, k, f);
    if (r && g_strCls && env->IsInstanceOf(r, g_strCls)) {
        const char* c = g_origGetStrUtf ? g_origGetStrUtf(env, (jstring) r, nullptr) : nullptr;
        if (c) {
            noteIdentity("GetStaticObjectField", c, __builtin_return_address(0));
            env->ReleaseStringUTFChars((jstring) r, c);
        } else {
            env->ExceptionClear();
        }
    }
    return r;
}

// ---------------------------------------------------------------------------
// Packer-facing class-name mask.
//
// libloader.so walks the Java stack during bindApplication and reads every
// frame through GetStringUTFChars: BaseInstrumentationDelegate,
// AppInstrumentation, Reflector.callByCaller, BlackReflection$1.invoke,
// BActivityThread.handleBindApplication, HCallbackProxy.handleLaunchActivity.
// That is a sandbox fingerprint made of class names, and the whole BlackBox
// instrumentation chain is in it.
//
// The mask is scoped to callers inside the app's own native directory - the
// same binding calls made by libblackbox.so (our own observer) and the runtime
// keep their real strings, so nothing in the container's machinery changes.
// Returned buffers are heap-owned and ReleaseStringUTFChars is hooked, so the
// caller's release frees our copy instead of the VM's.
// ---------------------------------------------------------------------------
typedef void (*releaseStrUtfFn)(JNIEnv*, jstring, const char*);
static releaseStrUtfFn g_origReleaseStrUtf = nullptr;
static std::mutex g_maskMu;
static const char* g_maskPtrs[512];
static int g_maskCount = 0;
static std::atomic<int> g_maskHits{0};

static bool packerCaller(void* ret) {
    char lib[200];
    libOf(ret, lib, sizeof(lib));
    return strstr(lib, "libloader.so") != nullptr ||
           strstr(lib, "libappdome") != nullptr ||
           strstr(lib, "libfusion") != nullptr;
}

// Class names only. Paths are left alone in this build: a rewritten dataDir
// that libloader later opens would fail for a reason that is not the check.
static bool maskable(const char* s) {
    return s && strncmp(s, "top.niunaijun", 13) == 0;
}

struct MaskRule {
    const char* from;
    const char* to;
};

static const MaskRule kMaskRules[] = {
    {"top.niunaijun.blackbox.app.BActivityThread",       "android.app.ActivityThread"},
    {"top.niunaijun.blackbox.fake.service.HCallbackProxy", "android.os.Handler"},
    {"top.niunaijun.blackbox.fake.service.IActivityManagerProxy", "android.app.ActivityManager"},
    {"top.niunaijun.blackbox.fake.delegate.AppInstrumentation", "android.app.Instrumentation"},
    {"top.niunaijun.blackbox.fake.delegate.BaseInstrumentationDelegate", "android.app.Instrumentation"},
    {"top.niunaijun.blackreflection.",                   "java.lang.reflect."},
    {"top.niunaijun.blackbox.",                          "android.app."},
    {"top.niunaijun.",                                   "android."},
    {"niunaijun",                                        "android"},
    {"blackbox",                                         "android"},
};

static const char* maskCopy(const char* s) {
    size_t n = strlen(s);
    char* out = (char*) malloc(n + 64);
    if (!out) return s;
    size_t o = 0;
    for (size_t i = 0; i < n; ) {
        bool hit = false;
        for (const MaskRule& r : kMaskRules) {
            size_t fl = strlen(r.from);
            if (strncmp(s + i, r.from, fl) == 0) {
                size_t tl = strlen(r.to);
                memcpy(out + o, r.to, tl);
                o += tl;
                i += fl;
                hit = true;
                break;
            }
        }
        if (!hit) out[o++] = s[i++];
    }
    out[o] = 0;
    return out;
}

static void trackMasked(const char* p) {
    std::lock_guard<std::mutex> lk(g_maskMu);
    if (g_maskCount < (int) (sizeof(g_maskPtrs) / sizeof(g_maskPtrs[0]))) {
        g_maskPtrs[g_maskCount++] = p;
    }
}

static bool untrackMasked(const char* p) {
    std::lock_guard<std::mutex> lk(g_maskMu);
    for (int i = 0; i < g_maskCount; i++) {
        if (g_maskPtrs[i] == p) {
            g_maskPtrs[i] = g_maskPtrs[g_maskCount - 1];
            g_maskCount--;
            return true;
        }
    }
    return false;
}

static void JNICALL hookReleaseStrUtf(JNIEnv* env, jstring js, const char* s) {
    if (s && untrackMasked(s)) {
        free((void*) s);
        return;
    }
    if (g_origReleaseStrUtf) g_origReleaseStrUtf(env, js, s);
}

static const char* JNICALL hookGetStrUtf(JNIEnv* env, jstring js, jboolean* isCopy) {
    if (!g_origGetStrUtf) return nullptr;
    const char* r = g_origGetStrUtf(env, js, isCopy);
    if (!r) return nullptr;
    void* ret = __builtin_return_address(0);
    noteIdentity("GetStringUTFChars", r, ret);
    if (maskable(r) && packerCaller(ret)) {
        const char* m = maskCopy(r);
        if (m != r) {
            trackMasked(m);
            int n = g_maskHits.fetch_add(1);
            if (n < 80) {
                char lib[200];
                libOf(ret, lib, sizeof(lib));
                char b[560];
                snprintf(b, sizeof(b), "mask %.200s -> %.200s @%s", r, m, lib);
                nlogCrit("mask", b);
            }
            return m;
        }
    }
    return r;
}

// One page covers every identity slot above (highest is 169); Release lives
// one slot later and gets its own mprotect inside patchSlot.
static bool patchSlot(void** vt, int slot, void* repl, void** save, const char* what) {
    if (vt[slot] == repl) return true;
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) page = 4096;
    uintptr_t addr = (uintptr_t) &vt[slot];
    void* pg = (void*) (addr & ~(uintptr_t) (page - 1));
    if (mprotect(pg, (size_t) page, PROT_READ | PROT_WRITE) != 0) {
        char b[96];
        snprintf(b, sizeof(b), "mprotect %s errno=%d", what, errno);
        nlogCrit("jni", b);
        return false;
    }
    if (save) *save = vt[slot];
    vt[slot] = repl;
    return true;
}

void installJniBridge() {
    if (g_origRegNatives) return;
    JNIEnv* env = nullptr;
    if (!g_vm || g_vm->GetEnv((void**) &env, JNI_VERSION_1_6) != JNI_OK || !env) {
        nlogCrit("jni", "no env at install");
        return;
    }
    void** vt = *(void***) env;
    if (!vt) { nlogCrit("jni", "no function table"); return; }

    typedef jint (*getVmFn)(JNIEnv*, JavaVM**);
    getVmFn gv = (getVmFn) vt[219];
    JavaVM* probe = nullptr;
    if (!gv || gv(env, &probe) != JNI_OK || probe != g_vm) {
        nlogCrit("jni", "table probe failed");
        return;
    }
    if (vt[215] == (void*) hookRegNatives) return;

    // The string class must be a global ref: it outlives any local frame.
    jclass sc = env->FindClass("java/lang/String");
    if (sc) {
        g_strCls = (jclass) env->NewGlobalRef(sc);
        env->DeleteLocalRef(sc);
    }
    if (env->ExceptionCheck()) env->ExceptionClear();

    patchSlot(vt, 215, (void*) hookRegNatives, (void**) &g_origRegNatives,
              "RegisterNatives");

    bool ok = true;
    ok &= patchSlot(vt, 35,  (void*) hookObjV,   (void**) &g_origObjV,   "CallObjectMethodV");
    ok &= patchSlot(vt, 36,  (void*) hookObjA,   (void**) &g_origObjA,   "CallObjectMethodA");
    ok &= patchSlot(vt, 65,  (void*) hookNvObjV, (void**) &g_origNvObjV, "CallNonvirtualObjectMethodV");
    ok &= patchSlot(vt, 66,  (void*) hookNvObjA, (void**) &g_origNvObjA, "CallNonvirtualObjectMethodA");
    ok &= patchSlot(vt, 115, (void*) hookStObjV, (void**) &g_origStObjV, "CallStaticObjectMethodV");
    ok &= patchSlot(vt, 116, (void*) hookStObjA, (void**) &g_origStObjA, "CallStaticObjectMethodA");
    ok &= patchSlot(vt, 167, (void*) hookNewStrUtf,   (void**) &g_origNewStrUtf,   "NewStringUTF");
    ok &= patchSlot(vt, 169, (void*) hookGetStrUtf,   (void**) &g_origGetStrUtf,   "GetStringUTFChars");
    ok &= patchSlot(vt, 170, (void*) hookReleaseStrUtf, (void**) &g_origReleaseStrUtf, "ReleaseStringUTFChars");
    ok &= patchSlot(vt, 95,  (void*) hookGetObjFld,   (void**) &g_origGetObjFld,   "GetObjectField");
    ok &= patchSlot(vt, 145, (void*) hookGetStObjFld, (void**) &g_origGetStObjFld, "GetStaticObjectField");

    nlogCrit("hook", "JNI RegisterNatives");
    char b[200];
    snprintf(b, sizeof(b), "JNI string rewrite strcls=%d ok=%d",
             g_strCls ? 1 : 0, ok ? 1 : 0);
    nlogCrit("hook", b);
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
        size_t len = strlen(c);
        char pre[32];
        int n = snprintf(pre, sizeof(pre), "%d ", (int)getpid());
        if (n > 0) rawWrite(pre, (size_t)n);
        rawWrite(c, len);
        rawWrite("\n", 1);
    }
    env->ReleaseStringUTFChars(msg, c);
}

extern "C" JNIEXPORT void JNICALL
Java_top_niunaijun_blackbox_core_NativeCore_ofxSetGuestPackage(
        JNIEnv *env, jclass, jstring pkg, jint logFd, jint mode, jint uid) {
    if (!pkg) return;
    env->GetJavaVM(&g_vm);
    const char* c = env->GetStringUTFChars(pkg, nullptr);
    if (!c) return;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        strncpy(g_pkg, c, sizeof(g_pkg) - 1);
        g_pkg[sizeof(g_pkg) - 1] = '\0';
        if (logFd >= 0) g_logFd = (int)dup(logFd);
        if (mode >= 0) g_mode = mode;
        if (uid > 0) g_guestUid = (int)uid;
    }
    env->ReleaseStringUTFChars(pkg, c);

    if (g_installed.exchange(true)) return;

    char head[256];
    snprintf(head, sizeof(head), "v56 %s fd=%d mode=%d guestUid=%d realUid=%d realEuid=%d",
             g_pkg, g_logFd, g_mode, g_guestUid, (int)getuid(), (int)geteuid());
    nlogRaw("install", head);

    installCrashHandler();

    // seccomp goes in before AppDome's libloader is mapped: the filter is
    // per-process, so every later thread inherits it.
    if (modeOn(M_SECCOMP) || modeOn(M_NOKILL)) installSeccomp();

    // Before anything loads AppDome's libloader: own the RegisterNatives slot
    // so its native bridge is rewritten at bind time, not after the verdict.
    installJniBridge();

    pthread_t th;
    if (pthread_create(&th, nullptr, hbThread, nullptr) == 0) pthread_detach(th);

    if (modeOn(M_NOHOOKS)) {
        nlogRaw("hooks", "off (mode 64)");
        HLOG("hardening %s mode=%d NO HOOKS", g_pkg, g_mode);
        return;
    }

    // switches live on shared storage so a behaviour can be flipped between
    // runs without rebuilding the container
    {
        const char* fbs[] = {
            "/storage/emulated/0/Download/hardbox-nofb.txt",
            "/storage/emulated/0/Download/HardBox/hardbox-nofb.txt",
        };
        for (size_t i = 0; i < sizeof(fbs) / sizeof(fbs[0]); i++) {
            if (access(fbs[i], F_OK) == 0) { g_noFirebase = true; break; }
        }
        const char* probes[] = {
            "/storage/emulated/0/Download/hardbox-probe.txt",
            "/storage/emulated/0/Download/HardBox/hardbox-probe.txt",
        };
        for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
            if (access(probes[i], F_OK) == 0) { g_probe = true; break; }
        }
        char sw[64];
        snprintf(sw, sizeof(sw), "nofb=%s probe=%s",
                 g_noFirebase ? "on" : "off", g_probe ? "on" : "off");
        nlogCrit("switch", sw);
    }

    logSymbols();

    // liblog mirror goes in before anything else: the first anti-cheat log
    // line is worth more than every /proc trace combined.
    if (!modeOn(M_NOLOG)) {
        patch("__android_log_print",  (void*)hookLogPrint,  (void**)&origLogPrint,  "logprint");
        patch("__android_log_write",  (void*)hookLogWrite,  (void**)&origLogWrite,  "logwrite");
        patch("__android_log_vprint", (void*)hookLogVprint, (void**)&origLogVprint, "logvprint");
    } else {
        nlogRaw("skip", "liblog mirror");
    }

    // No AAssetManager hooks. See the note above hbThread - an inline patch on
    // libandroid.so killed v46 before its first asset call.
    nlogRaw("skip", "asset hooks (libandroid untouched)");

    if (modeOn(M_UID)) {
        patch("getuid",  (void*)hookGetuid,  (void**)&origGetuid,  "getuid");
        patch("geteuid", (void*)hookGeteuid, (void**)&origGeteuid, "geteuid");
    } else {
        nlogRaw("skip", "uid mask");
    }

    if (modeOn(M_NMS) || modeOn(M_DLTRACE)) {
        patch("dlopen",             (void*)hookDlopen,    (void**)&origDlopen,    "dlopen");
        patch("android_dlopen_ext", (void*)hookDlopenExt, (void**)&origDlopenExt, "dlopenext");
    } else {
        nlogRaw("skip", "dlopen group");
    }

    if (modeOn(M_KILLTRACE) || modeOn(M_NOKILL)) {
        patch("kill",     (void*)hookKill,     (void**)&origKill,     "kill");
        patch("tgkill",   (void*)hookTgkill,   (void**)&origTgkill,   "tgkill");
        patch("sigqueue", (void*)hookSigqueue, (void**)&origSigqueue, "sigqueue");
        patch("pthread_exit", (void*)hookPthreadExit, (void**)&origPthreadExit, "pthread_exit");
    } else {
        nlogRaw("skip", "kill group");
    }

    if (modeOn(M_NOEXIT)) {
        patch("exit",  (void*)hookExit,      (void**)&origExit,      "exit");
        patch("_exit", (void*)hookExitRaw,   (void**)&origExitRaw,   "_exit");
        patch("_Exit", (void*)hookExitUpper, (void**)&origExitUpper, "_Exit");

        // stage: 1 = no handle, 2 = handle but no symbol, 3 = Dobby refused.
        int arStage = 0;
        void* ar = symLib("libandroid_runtime.so", "_ZN7android14AndroidRuntime4exitEi");
        if (!ar) { arStage = 1; ar = sym("_ZN7android14AndroidRuntime4exitEi"); }
        if (ar) {
            if (DobbyHook(ar, (void*)hookAndroidRuntimeExit,
                          (void**)&origAndroidRuntimeExit) == 0) {
                nlogCrit("hook", "AndroidRuntime::exit");
            } else {
                arStage = 3;
            }
        } else if (arStage == 0) {
            arStage = 2;
        }
        if (arStage) {
            char b[200];
            snprintf(b, sizeof(b), "AndroidRuntime::exit stage=%d", arStage);
            nlogCrit("miss", b);
        }

        void* jvm = dlopen("libopenjdkjvm.so", RTLD_NOW);
        if (jvm) {
            void* je = dlsym(jvm, "JVM_Exit");
            if (je && DobbyHook(je, (void*)hookJvmExit, (void**)&origJvmExit) == 0) {
                nlogRaw("hook", "JVM_Exit");
            } else {
                nlogRaw("miss", "JVM_Exit");
            }
            void* jh = dlsym(jvm, "JVM_Halt");
            if (jh && DobbyHook(jh, (void*)hookJvmHalt, (void**)&origJvmHalt) == 0) {
                nlogRaw("hook", "JVM_Halt");
            } else {
                nlogRaw("miss", "JVM_Halt");
            }
        } else {
            nlogCrit("miss", "libopenjdkjvm err=dlopen failed");
        }
    } else {
        nlogRaw("skip", "exit group");
    }

    // The packer's own filesystem access never passes through libc wrappers;
    // it takes libc's syscall() instead. This is the only frame it leaves.
    if (modeOn(M_SYS)) {
        patch("syscall", (void*) hookSyscall, (void**) &g_origSyscall, "syscall");
    } else {
        nlogRaw("skip", "syscall group");
    }

    {
        char hb[128];
        snprintf(hb, sizeof(hb), "mode=%d prop=%d open=%d stat=%d misc=%d dl=%d",
                 g_mode, hookOn(H_PROP) ? 1 : 0, hookOn(H_OPEN) ? 1 : 0,
                 hookOn(H_STAT) ? 1 : 0, hookOn(H_MISC) ? 1 : 0, hookOn(H_DL) ? 1 : 0);
        nlogRaw("hooksel", hb);
    }

    if (hookOn(H_PROP) || modeOn(M_PROPTRACE)) {
        patch("__system_property_get",  (void*)hookPropGet,  (void**)&origPropGet,  "propget");
        patch("__system_property_find", (void*)hookPropFind, (void**)&origPropFind, "propfind");
    } else {
        nlogRaw("skip", "prop group");
    }
    if (hookOn(H_OPEN)) {
        patch("open",                   (void*)hookOpen,     (void**)&origOpen,     "open");
        patch("openat",                 (void*)hookOpenat,   (void**)&origOpenat,   "openat");
        patch("fopen",                  (void*)hookFopen,    (void**)&origFopen,    "fopen");
    } else {
        nlogRaw("skip", "open group");
    }
    if (hookOn(H_STAT)) {
        patch("stat",                   (void*)hookStat,     (void**)&origStat,     "stat");
        patch("lstat",                  (void*)hookLstat,    (void**)&origLstat,    "lstat");
        patch("access",                 (void*)hookAccess,   (void**)&origAccess,   "access");
    } else {
        nlogRaw("skip", "stat group");
    }
    if (hookOn(H_MISC)) {
        patch("uname",                  (void*)hookUname,    (void**)&origUname,    "uname");
        patch("execve",                 (void*)hookExecve,   (void**)&origExecve,   "execve");
        patch("readlink",               (void*)hookReadlink, (void**)&origReadlink, "readlink");
    } else {
        nlogRaw("skip", "misc group");
    }
    if (hookOn(H_DL)) {
        patch("dl_iterate_phdr",        (void*)hookDlIterate, (void**)&origDlIterate, "dl_iterate_phdr");
    } else {
        nlogRaw("skip", "dl group");
    }

    // FORTIFY wrappers: only patch when they are distinct symbols, otherwise the
    // two trampolines call each other and the guest dies of stack overflow.
    if (hookOn(H_OPEN)) {
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
    } else {
        nlogRaw("skip", "open2/openat2 group");
    }

    nlogRaw("done", "hooks installed");
    HLOG("hardening installed for %s mode=%d fd=%d", g_pkg, g_mode, g_logFd);
}
