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
std::atomic<bool> g_pkgTrace{false};
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

void logJavaStack();

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
    // The SDK announces the verdict with the package name it decided we are.
    // Whatever produced that string is the leak - trace it once, at the source.
    if (strstr(msg, "getPackageName") && strstr(tag, "Kumiho") && !g_pkgTrace.exchange(true)) {
        logJavaStack();
    }
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

void* hookDlopen(const char* name, int flags) {
    if (name) trace("dlopen", name);
    if (modeOn(M_NMS) && nmsName(name)) {
        nlogRaw("blocked", name);
        errno = ENOENT;
        return nullptr;
    }
    return origDlopen ? origDlopen(name, flags) : nullptr;
}

void* hookDlopenExt(const char* name, int flags, const void* info) {
    if (name) trace("dlopen", name);
    if (modeOn(M_NMS) && nmsName(name)) {
        nlogRaw("blocked", name);
        errno = ENOENT;
        return nullptr;
    }
    return origDlopenExt ? origDlopenExt(name, flags, info) : nullptr;
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
void killTrace(const char* fn, pid_t pid, int sig) {    const bool self = (pid == getpid() || pid == 0);
    // Only fatal signals matter; ART suspends threads with SIGRT signals all
    // day and would bury the log in its own bookkeeping.
    if (sig != SIGKILL && sig != SIGABRT) return;
    char lib[200];
    libOf(__builtin_return_address(0), lib, sizeof(lib));
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

// One page covers every slot above (highest is 116, byte offset 928).
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
    snprintf(head, sizeof(head), "%s fd=%d mode=%d guestUid=%d realUid=%d realEuid=%d",
             g_pkg, g_logFd, g_mode, g_guestUid, (int)getuid(), (int)geteuid());
    nlogRaw("install", head);

    installCrashHandler();

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
            const char* e = dlerror();
            char b[200];
            snprintf(b, sizeof(b), "AndroidRuntime::exit stage=%d err=%s",
                     arStage, e ? e : "-");
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
            const char* e = dlerror();
            char b[240];
            snprintf(b, sizeof(b), "libopenjdkjvm err=%s", e ? e : "-");
            nlogCrit("miss", b);
        }
    } else {
        nlogRaw("skip", "exit group");
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
