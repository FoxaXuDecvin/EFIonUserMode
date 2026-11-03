// efihost.c - user-mode UEFI application host for Windows.
// Loads an .efi (PE32+ EFI_APPLICATION) manually, fakes the UEFI
// System/Boot/Runtime services, and calls its entry point directly.
// No VM, no firmware, pure user mode. Built with MSVC cl.exe.
//
// Usage: efihost.exe <file.efi> [args are ignored for now]

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <conio.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <wchar.h>
#include <io.h>
#include <setjmp.h>
#include <sys/stat.h>

// not in winnt.h headers, declared manually
NTSYSAPI BOOLEAN NTAPI RtlRemoveFunctionTable(IN PRUNTIME_FUNCTION FunctionTable);

static int g_inRedirected;   // stdin is a pipe/file, not console

typedef unsigned long long UINT64;
typedef unsigned long long UINTN;
typedef unsigned short     CHAR16;
typedef unsigned char      UINT8;
typedef unsigned short     UINT16;
typedef unsigned int       UINT32;
#define VOID void

#define EFI_ERROR_MASK 0x8000000000000000ULL
#define EFI_SUCCESS              0ULL
#define EFI_UNSUPPORTED          (3ULL | EFI_ERROR_MASK)
#define EFI_NOT_FOUND            (14ULL | EFI_ERROR_MASK)
#define EFI_BUFFER_TOO_SMALL     (5ULL  | EFI_ERROR_MASK)
#define EFI_INVALID_PARAMETER    (2ULL  | EFI_ERROR_MASK)
#define EFI_NOT_READY            (6ULL  | EFI_ERROR_MASK)
#define EFI_OUT_OF_RESOURCES     (9ULL  | EFI_ERROR_MASK)
#define EFI_ACCESS_DENIED        (8ULL  | EFI_ERROR_MASK)
#define EFI_DEVICE_ERROR         (7ULL  | EFI_ERROR_MASK)
#define EFI_NO_MAPPING           (18ULL | EFI_ERROR_MASK)
#define EFI_ABORTED              (21ULL | EFI_ERROR_MASK)
#define EFI_ALREADY_STARTED      (20ULL | EFI_ERROR_MASK)
#define EFI_NO_MEDIA             (12ULL | EFI_ERROR_MASK)
#define EFI_MEDIA_CHANGED        (13ULL | EFI_ERROR_MASK)
#define EFI_WRITE_PROTECTED      (15ULL | EFI_ERROR_MASK)
#define EFI_BAD_BUFFER_SIZE      (4ULL  | EFI_ERROR_MASK)

static UINT8 *g_imageBase;   // mapped image, for fault address -> RVA
static UINT64 g_imageSize;
static void  *g_conIn, *g_conOut;   // console protocols (published on handles)

// ---- debug watchdog: if the app makes no progress, dump where it is ----
static volatile long g_appDone;
static HANDLE        g_mainThread;

// host-call counters (which service is the app hammering?)
static volatile long g_cntStall, g_cntAlloc, g_cntFree, g_cntGetTime,
                     g_cntRead, g_cntWrite, g_cntKey, g_cntOpen, g_cntSetPos,
                     g_cntGetInfo, g_cntCopyMem, g_cntCrc32;

// ---- host log level -------------------------------------------------
//   0 = silent   只有崩溃转储 / 致命错误
//   1 = normal   (默认) 启动一行 + 错误
//   2 = verbose  每次协议调用、文件打开、SetVar          (-v)
//   3 = debug    OUT/HII 十六进制、按键线程、看门狗心跳   (-vv / EFHOST_DEBUG)
// 命令行 -q | -v | -vv 优先于环境变量 EFHOST_QUIET=1 | EFHOST_LOG=0..3 | EFHOST_DEBUG=1
static int g_logLevel = 1;
static UINTN g_hiiStrTbl;      // &g_HiiString, for crash diagnostics
#define LOGLV(lvl)     (g_logLevel >= (lvl))
#define LOGV(lvl, ...) do { if (g_logLevel >= (lvl)) fprintf(stderr, __VA_ARGS__); } while (0)

// lock-free-ish logging: no CRT, no heap (the app may hold the heap lock)
static void WdLogL(int lvl, const char *fmt, ...)
{
    if (g_logLevel < lvl) return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = _vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) n = (int)sizeof(buf) - 1;
    if (n > (int)sizeof(buf) - 1) n = (int)sizeof(buf) - 1;
    DWORD written = 0;
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, (DWORD)n, &written, NULL);
}

// catch a CRT exit() from inside the EFI app and show who called it
static void OnAppExit(void)
{
    if (g_appDone) return;             // normal return from main
    void *frames[16];
    WdLogL(1, "\n[efihost] *** app called CRT exit(): backtrace ***\n");
    USHORT n = RtlCaptureStackBackTrace(0, 16, frames, NULL);
    for (USHORT i = 0; i < n; i++) {
        long long rva = (long long)((UINT8 *)frames[i] - g_imageBase);
        if (rva > 0 && (UINT64)rva < g_imageSize)
            WdLogL(1, "  #%u  RVA 0x%llx\n", i, (unsigned long long)rva);
        else
            WdLogL(1, "  #%u  %p (host)\n", i, frames[i]);
    }
}

static DWORD WINAPI HeartbeatThread(void *arg)
{
    (void)arg;
    for (int i = 1; i <= 30; i++) {
        Sleep(2000);
        if (g_appDone) return 0;
        WdLogL(3, "[efihost][hb] alive %2ds | stall=%ld alloc=%ld gettime=%ld read=%ld write=%ld key=%ld open=%ld\n",
              i * 2, g_cntStall, g_cntAlloc, g_cntGetTime, g_cntRead, g_cntWrite,
              g_cntKey, g_cntOpen);
    }
    return 0;
}

static DWORD WINAPI WatchdogThread(void *arg)
{
    (void)arg;
    WdLogL(3, "[efihost][wd] watchdog started (main=%p)\n", (void *)g_mainThread);
    for (int round = 0; round < 12; round++) {
        Sleep(5000);
        if (g_appDone) return 0;
        if (!g_mainThread) { WdLogL(3, "[efihost][wd] no main thread handle\n"); return 0; }
        DWORD prevSuspend = SuspendThread(g_mainThread);
        char rip[64] = "n/a";
        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (prevSuspend != (DWORD)-1 && GetThreadContext(g_mainThread, &ctx))
            _snprintf(rip, sizeof(rip), "RVA 0x%llx",
                      (unsigned long long)((UINT8 *)ctx.Rip - g_imageBase));
        WdLogL(1, "[efihost][wd] t=%ds parked at %s | stall=%ld alloc=%ld free=%ld time=%ld read=%ld write=%ld key=%ld open=%ld setpos=%ld getinfo=%ld\n",
              (round + 1) * 5, rip, g_cntStall, g_cntAlloc, g_cntFree, g_cntGetTime,
              g_cntRead, g_cntWrite, g_cntKey, g_cntOpen, g_cntSetPos, g_cntGetInfo);
        if (prevSuspend != (DWORD)-1) ResumeThread(g_mainThread);
    }
    return 0;
}

static void ReportCaller(const char *what)
{
    void *ret = _ReturnAddress();
    long long rva = (long long)((UINT8 *)ret - g_imageBase);
    if (rva > 0 && (UINT64)rva < g_imageSize)
        LOGV(2, "[efihost] >>> app called %s (from RVA 0x%llx)\n", what, rva);
    else
        LOGV(2, "[efihost] >>> app called %s (from %p)\n", what, ret);
}

static UINTN g_ioTraps;

// Value returned for "mov r32, cr3".  Some boot loaders read CR3 during early
// init; there is no way to expose the real one from user mode.  EFHOST_CR3
// overrides it (hex), e.g. EFHOST_CR3=1b000 for experimenting.
static UINT64 g_fakeCr3 = 0x1B000;

// Nested image control flow: gBS->Exit() / RT->ResetSystem() issued by an
// image that Shell launched must unwind back to StartImage(), not kill the
// host process (that would take the Shell down with the app).
static jmp_buf g_exitJmp;
static int     g_exitValid;
static void    GOP_Snapshot(void);          // defined with the graphics protocol
static UINTN   g_exitStatus;

// EFHOST_BT=1 turns on guest call-site traces (RVAs, resolve with MyShell.map).
// Kept behind a flag because it is noisy and only useful while debugging.
static int g_traceBt;

static void LogBt(int lvl, const char *tag)
{
    if (!g_traceBt || g_logLevel < lvl) return;
    void *frames[8];
    USHORT n = RtlCaptureStackBackTrace(1, 8, frames, NULL);
    fprintf(stderr, "[efihost][bt] %s:", tag);
    for (USHORT i = 0; i < n; i++) {
        long long rva = (long long)((UINT8 *)frames[i] - g_imageBase);
        if (rva > 0 && (UINT64)rva < g_imageSize)
            fprintf(stderr, " 0x%llx", (unsigned long long)rva);
        else
            fprintf(stderr, " host");
    }
    fprintf(stderr, "\n");
}

// Emulate a privileged instruction at ctx->Rip. Returns bytes to skip,
// or -1 if we don't know the opcode.
static int EmulatePrivileged(CONTEXT *ctx)
{
    UINT8 *rip = (UINT8 *)ctx->Rip;
    UINT8  op  = rip[0];
    int len = 0, isOut = 0, is32 = 0;
    switch (op) {
    case 0xEC: len = 1; break;                      // in  al,dx
    case 0xEE: len = 1; isOut = 1; break;           // out dx,al
    case 0xED: len = 1; is32 = 1; break;            // in  eax,dx
    case 0xEF: len = 1; isOut = 1; is32 = 1; break; // out dx,eax
    case 0xE4: len = 2; break;                      // in  al,imm8
    case 0xE6: len = 2; isOut = 1; break;           // out imm8,al
    case 0xE5: len = 2; is32 = 1; break;            // in  eax,imm8
    case 0xE7: len = 2; isOut = 1; is32 = 1; break; // out imm8,eax
    case 0xFA: len = 1; break;                      // cli
    case 0xFB: len = 1; break;                      // sti
    case 0xF4: len = 1; break;                      // hlt (treat as nop!)
    case 0x0F:                                      // two-byte opcodes
        switch (rip[1]) {
        case 0x08: len = 2; break;                  // invd
        case 0x09: len = 2; break;                  // wbinvd
        case 0x30: len = 2; break;                  // wrmsr
        case 0x32: len = 2; ctx->Rax = 0; ctx->Rdx = 0; break; // rdmsr -> 0
        case 0x01: len = 3; break;                  // lgdt/lidt/sgdt/sidt...
        case 0x20:                                  // mov r32, CRn   (0F 20 /r)
        case 0x21:                                  // mov r64, DRn   (0F 21 /r)
        {
            UINT8 modrm = rip[2];
            int   reg = (modrm >> 3) & 7;
            int   rm  = modrm & 7;
            UINT64 v = 0;
            if (rip[1] == 0x20) {
                if (reg == 0)      v = 0x80000033;      // CR0: PG|PE|ET|NE|WP|AM
                else if (reg == 3) v = g_fakeCr3;       // CR3 (EFHOST_CR3)
                else if (reg == 4) v = 0x00000620;      // CR4: basic feature bits
            }
            switch (rm) {
            case 0: ctx->Rax = v; break;
            case 1: ctx->Rcx = v; break;
            case 2: ctx->Rdx = v; break;
            case 3: ctx->Rbx = v; break;
            case 6: ctx->Rsi = v; break;
            case 7: ctx->Rdi = v; break;
            default: break;                             // no way to address rsp/rbp here in practice
            }
            len = 3;
            break;
        }
        case 0x22: len = 3; break;                  // mov CRn, r32  -> ignore
        case 0x23: len = 3; break;                  // mov DRn, r64  -> ignore
        }
        break;
    }
    if (!len) return -1;
    g_ioTraps++;
    if (g_ioTraps <= 40)
        LOGV(3, "[efihost] priv-op %02X %02X at RVA 0x%llx (#%llu)\n",
                op, len > 1 ? rip[1] : 0,
                (unsigned long long)(rip - g_imageBase),
                (unsigned long long)g_ioTraps);
    if (!isOut && len && op != 0xFA && op != 0xFB && op != 0xF4 &&
        !(op == 0x0F && (rip[1] == 0x08 || rip[1] == 0x09 || rip[1] == 0x30 || rip[1] == 0x01))) {
        // IN instruction: pretend the port reads all 1s ("device absent")
        if (is32) ctx->Rax = 0xFFFFFFFFULL;
        else      ctx->Rax = (ctx->Rax & ~0xFFULL) | 0xFFULL;
    }
    ctx->Rip += len;
    return len;
}

static LONG CALLBACK VehHandler(EXCEPTION_POINTERS *ep)
{
    EXCEPTION_RECORD *er = ep->ExceptionRecord;

    // OutputDebugStringW/A raise DBG_PRINTEXCEPTION_* when a debugger is
    // attached.  We are the debugger: print it and resume the app.
    if (er->ExceptionCode == 0x4001000A || er->ExceptionCode == 0x40010006) {
        if (er->NumberParameters >= 2) {
            char line[1024];
            UINTN len = er->ExceptionInformation[0];
            void *str = (void *)er->ExceptionInformation[1];
            int n;
            if (er->ExceptionCode == 0x4001000A) {          // wide
                int cl = (int)len;
                if (cl > 1000) cl = 1000;
                for (int i = 0; i < cl; i++) {
                    unsigned short wc = ((unsigned short *)str)[i];
                    line[i] = (char)(wc < 128 ? wc : '?');
                }
                line[cl] = 0;
                n = _snprintf(line + 0, 0, "");            // no-op, keep cl
                (void)n;
                if (g_logLevel >= 1) {
                    char out[1100];
                    int m = _snprintf(out, sizeof(out), "[efihost][dbg] %s\n", line);
                    DWORD w = 0;
                    if (m > 0) WriteFile(GetStdHandle(STD_ERROR_HANDLE), out, (DWORD)m, &w, NULL);
                }
            } else {
                int cl = (int)len;
                if (cl > 1000) cl = 1000;
                memcpy(line, str, cl);
                line[cl] = 0;
                if (g_logLevel >= 1) {
                    char out[1100];
                    int m = _snprintf(out, sizeof(out), "[efihost][dbg] %s\n", line);
                    DWORD w = 0;
                    if (m > 0) WriteFile(GetStdHandle(STD_ERROR_HANDLE), out, (DWORD)m, &w, NULL);
                }
            }
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    static unsigned long g_excCount;
    if (er->ExceptionCode != 0xC0000096 && ++g_excCount <= 60) {
        // log every non-port-IO exception: if RSP is trashed the SEH frame
        // cannot be found, and the process dies with no other trace.
        CONTEXT *c = ep->ContextRecord;
        UINT8 *rip = (UINT8 *)c->Rip;
        long long rva = (long long)(rip - g_imageBase);
        char buf[256];
        UINT64 retAddr = 0;
        __try { retAddr = *(UINT64 *)c->Rsp; } __except (EXCEPTION_EXECUTE_HANDLER) { retAddr = 0; }
        long long retRva = (long long)((UINT8 *)retAddr - g_imageBase);
        int n = _snprintf(buf, sizeof(buf),
            "[efihost][veh] EXC 0x%08lX at RVA 0x%llx rsp=%p ret=%s rax=%llx rcx=%llx rdx=%llx r8=%llx r9=%llx acc=%llx@%llx\n",
            er->ExceptionCode, (unsigned long long)rva,
            (void *)c->Rsp,
            (retRva > 0 && (UINT64)retRva < g_imageSize) ? "app" : "host",
            (unsigned long long)c->Rax,
            (unsigned long long)c->Rcx, (unsigned long long)c->Rdx,
            (unsigned long long)c->R8,  (unsigned long long)c->R9,
            er->NumberParameters >= 2 ? (unsigned long long)er->ExceptionInformation[0] : 0ULL,
            er->NumberParameters >= 2 ? (unsigned long long)er->ExceptionInformation[1] : 0ULL);
        if (n > 0) {
            DWORD w = 0;
            WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, (DWORD)n, &w, NULL);
        }
        if (g_logLevel >= 2) {
            int m = _snprintf(buf, sizeof(buf), "[efihost][veh]   caller %p (appRVA 0x%llx)\n",
                              (void *)retAddr, (unsigned long long)retRva);
            DWORD w2 = 0;
            if (m > 0) WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, (DWORD)m, &w2, NULL);
        }
        if (g_logLevel >= 2 && er->ExceptionCode == 0xC0000005) {
            // Show the bytes leading up to the faulting read: tells us whether
            // the guest walked off a string, an EFI_FILE_INFO, a device path...
            UINT64 fault = c->Rcx;
            UINT64 from  = (fault > 192) ? (fault - 192) : 0;
            for (UINT64 p = from; p <= fault; p += 16) {
                char line[192];
                int  m = _snprintf(line, sizeof(line), "[efihost][veh]   %016llx:",
                                   (unsigned long long)p);
                __try {
                    UINT8 *q = (UINT8 *)p;
                    for (int k = 0; k < 16 && m > 0 && m < (int)sizeof(line) - 8; k++)
                        m += _snprintf(line + m, sizeof(line) - m, " %02x", q[k]);
                    m += _snprintf(line + m, sizeof(line) - m, "  |");
                    for (int k = 0; k < 16 && m < (int)sizeof(line) - 3; k++) {
                        UINT8 ch = q[k];
                        line[m++] = (ch >= 32 && ch < 127) ? (char)ch : '.';
                    }
                    line[m++] = '|'; line[m++] = '\n'; line[m] = 0;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    m = _snprintf(line, sizeof(line), "[efihost][veh]   %016llx: <unreadable>\n",
                                  (unsigned long long)p);
                }
                DWORD wd = 0;
                if (m > 0) WriteFile(GetStdHandle(STD_ERROR_HANDLE), line, (DWORD)m, &wd, NULL);
            }
        }
        if (g_logLevel >= 3 && er->ExceptionCode == 0xC0000005 &&
            c->Rcx >= (UINT64)g_hiiStrTbl && c->Rcx < (UINT64)g_hiiStrTbl + 0x200) {
            UINTN *t = (UINTN *)c->Rcx;
            int m = _snprintf(buf, sizeof(buf), "[efihost][veh]   DUMP g_HiiString: ");
            DWORD w5 = 0;
            if (m > 0) WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, (DWORD)m, &w5, NULL);
            for (UINTN i = 0; i < 6; i++) {
                m = _snprintf(buf, sizeof(buf), "[%u]=%p ", (unsigned)i, (void *)t[i]);
                if (m > 0) WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, (DWORD)m, &w5, NULL);
            }
            m = _snprintf(buf, sizeof(buf), "\n");
            if (m > 0) WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, (DWORD)m, &w5, NULL);
        }
        if (er->ExceptionCode == 0x80000003 || er->ExceptionCode == 0xC0000005) {
            void   *frames[14];
            USHORT  nf = RtlCaptureStackBackTrace(0, 14, frames, NULL);
            if (g_logLevel >= 1) for (USHORT i = 0; i < nf; i++) {
                long long fr = (long long)((UINT8 *)frames[i] - g_imageBase);
                if (fr > 0 && (UINT64)fr < g_imageSize) {
                    int   m = _snprintf(buf, sizeof(buf), "[efihost][veh]   #%u appRVA 0x%llx\n",
                                        i, (unsigned long long)fr);
                    DWORD w3 = 0;
                    if (m > 0) WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, (DWORD)m, &w3, NULL);
                }
            }
            // LTCG drops frame pointers, so also scan the raw stack for return addresses
            if (g_logLevel >= 2) for (UINTN i = 0; i < 128; i++) {
                UINT64 slot = 0;
                __try { slot = ((UINT64 *)c->Rsp)[i]; }
                __except (EXCEPTION_EXECUTE_HANDLER) { break; }
                long long fr = (long long)((UINT8 *)slot - g_imageBase);
                if (fr > 0 && (UINT64)fr < g_imageSize) {
                    int   m = _snprintf(buf, sizeof(buf), "[efihost][veh]   stack[%03u] appRVA 0x%llx\n",
                                        (unsigned)i, (unsigned long long)fr);
                    DWORD w4 = 0;
                    if (m > 0) WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, (DWORD)m, &w4, NULL);
                }
            }
        }
    }
    if (er->ExceptionCode == 0xC0000096) {   // privileged instruction
        int len = EmulatePrivileged(ep->ContextRecord);
        if (len >= 0) return EXCEPTION_CONTINUE_EXECUTION;
        CONTEXT *ctx = ep->ContextRecord;
        LOGV(1, "[efihost] *** privileged instr not emulated at RVA 0x%llx: %02X %02X %02X %02X ***\n",
                (unsigned long long)((UINT8 *)ctx->Rip - g_imageBase),
                ((UINT8 *)ctx->Rip)[0], ((UINT8 *)ctx->Rip)[1],
                ((UINT8 *)ctx->Rip)[2], ((UINT8 *)ctx->Rip)[3]);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG CrashFilter(EXCEPTION_POINTERS *ep)
{
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    CONTEXT *ctx = ep->ContextRecord;
    long long rva = (long long)((UINT8 *)er->ExceptionAddress - g_imageBase);
    LOGV(0, "\n[efihost] *** EXCEPTION 0x%08lX at %p", er->ExceptionCode, er->ExceptionAddress);
    if (rva > 0 && (UINT64)rva < g_imageSize)
        LOGV(0, " (RVA 0x%llx)", rva);
    LOGV(0, " ***\n");
    if (er->ExceptionCode == 0xC0000005 && er->NumberParameters >= 2)
        LOGV(0, "[efihost]   %s address 0x%llx\n",
                er->ExceptionInformation[0] ? "WRITE" : "READ",
                (unsigned long long)er->ExceptionInformation[1]);
    LOGV(2, "[efihost]   RIP=%p RSP=%p RAX=%llx RBX=%llx RCX=%llx RDX=%llx R8=%llx R9=%llx\n",
            (void *)ctx->Rip, (void *)ctx->Rsp,
            (unsigned long long)ctx->Rax, (unsigned long long)ctx->Rbx,
            (unsigned long long)ctx->Rcx, (unsigned long long)ctx->Rdx,
            (unsigned long long)ctx->R8,  (unsigned long long)ctx->R9);
    return EXCEPTION_EXECUTE_HANDLER;
}

// ---------------------------------------------------------------- tables

static UINTN UnsupportedFn(void) { ReportCaller("UnsupportedFn"); return EFI_UNSUPPORTED; }
static UINTN NotFoundFn(void)    { ReportCaller("NotFoundFn");    return EFI_NOT_FOUND; }

// SIMPLE_TEXT_OUTPUT protocol
typedef struct {
    UINTN Reset;              // (This, ExtendedVerification)
    UINTN OutputString;       // (This, String)
    UINTN TestString;         // (This, String)
    UINTN QueryMode;          // (This, ModeNumber, Columns, Rows)
    UINTN SetMode;            // (This, ModeNumber)
    UINTN SetAttribute;       // (This, Attribute)
    UINTN ClearScreen;        // (This)
    UINTN SetCursorPosition;  // (This, Column, Row)
    UINTN EnableCursor;       // (This, Enable)
    void *Mode;               // EFI_SIMPLE_TEXT_OUTPUT_MODE*  (offset 0x48)
} EFI_SIMPLE_TEXT_OUT;

typedef struct {
    int  MaxMode;
    int  Mode;                // current mode
    int  Attribute;
    int  CursorColumn;
    int  CursorRow;
    int  CursorVisible;
} EFI_SIMPLE_TEXT_OUTPUT_MODE;

static EFI_SIMPLE_TEXT_OUTPUT_MODE g_conOutMode = { 1, 0, 0x0F, 0, 0, 1 };
static EFI_SIMPLE_TEXT_OUTPUT_MODE g_errMode    = { 1, 0, 0x0F, 0, 0, 1 };

typedef struct {
    UINTN Reset;         // (This, ExtendedVerification)
    UINTN ReadKeyStroke; // (This, Key)
    void *WaitForKey;    // event (fake)
} EFI_SIMPLE_TEXT_IN;

#define ST_SIGNATURE  0x5453595320494249ULL // "IBI SYST"
#define BS_SIGNATURE  0x56524553544f4f42ULL // "BOOTSERV"
#define RS_SIGNATURE  0x56524553544e5552ULL // "RUNTSERV"

typedef struct {
    UINT64 Signature;        // 0
    UINT32 Revision;
    UINT32 HeaderSize;
    UINT32 CRC32;
    UINT32 Reserved;
    // 24
    CHAR16              *FirmwareVendor;
    UINT32               FirmwareRevision;
    UINT32               _pad;
    UINT64               ConsoleInHandle;   // 40
    EFI_SIMPLE_TEXT_IN  *ConIn;             // 48
    UINT64               ConsoleOutHandle;  // 56
    EFI_SIMPLE_TEXT_OUT *ConOut;            // 64
    UINT64               StandardErrorHandle;
    EFI_SIMPLE_TEXT_OUT *StdErr;
    VOID                *RuntimeServices;
    VOID                *BootServices;      // 88
    UINTN                NumberOfTableEntries;
    VOID                *ConfigurationTable;
} EFI_SYSTEM_TABLE;

#define EFI_MEMORY_DESCRIPTOR_SIZE 40
typedef struct {
    UINT32 Type;
    UINT32 Pad;
    UINT64 PhysicalStart;
    UINT64 VirtualStart;
    UINT64 NumberOfPages;
    UINT64 Attribute;
} EFI_MEMORY_DESCRIPTOR;

// ------------------------------------------------------------ console out
//
// The Shell's line editor is entirely *cursor positioning* based: after every
// keystroke it calls ConOut->SetCursorPosition(col,row) and repaints from
// there (ShellPkg/Application/Shell/FileHandleWrappers.c,
// FileInterfaceStdInRead).  It also seeds its own column/row from
// ConOut->Mode->CursorColumn/CursorRow, and the startup.nsh countdown paints
// with ShellPrintHiiEx(0, Mode->CursorRow, ...), i.e. it *overwrites* the same
// line once per second.
//
// A write-only console therefore makes backspace look like "the character
// stays and an extra blank appears", and makes the countdown append instead of
// overwrite.  So we keep a virtual cursor and drive the real terminal cursor
// with it.

// 0 = plain stream (stdout redirected to a file): text only, no escapes
// 1 = ANSI/VT escapes (real console with VT enabled, or a tty like mintty)
// 2 = Win32 console relative moves (VT unavailable but handle is a console)
static int g_conKind = -1;
static int g_conCol, g_conRow;          // virtual cursor, shared by ConOut/StdErr
static int g_conW = 80, g_conH = 25;    // screen size reported through QueryMode
static int g_conCursorOn = 1;
static int g_conAttr = 0x0F;
static int g_conLastCR;                 // collapse the CR CR LF UEFI likes to emit

#define ENB_VT_PROCESSING 0x0004

static void ConSyncMode(void)
{
    g_conOutMode.CursorColumn = g_conCol;
    g_conOutMode.CursorRow    = g_conRow;
    g_errMode.CursorColumn    = g_conCol;
    g_errMode.CursorRow       = g_conRow;
}

static void ConProbe(void)
{
    if (g_conKind >= 0) return;
    g_conKind = 0;

    // EFHOST_ANSI=1 forces VT mode even when stdout is not a console (useful
    // when piping into a terminal emulator that does not report a tty).
    if (getenv("EFHOST_ANSI")) {
        const char *cs = getenv("COLUMNS");
        const char *ls = getenv("LINES");
        if (cs && atoi(cs) >= 20) g_conW = atoi(cs);
        if (ls && atoi(ls) >= 5)  g_conH = atoi(ls);
        g_conKind = 1;
        ConSyncMode();
        return;
    }

    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  mode = 0;
    if (h && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode)) {
        CONSOLE_SCREEN_BUFFER_INFO ci;
        if (GetConsoleScreenBufferInfo(h, &ci)) {
            int w = ci.srWindow.Right - ci.srWindow.Left + 1;
            int r = ci.srWindow.Bottom - ci.srWindow.Top + 1;
            if (w >= 20 && w <= 512) g_conW = w;
            if (r >= 5  && r <= 512) g_conH = r;
            g_conCol = ci.dwCursorPosition.X;
            g_conRow = ci.dwCursorPosition.Y - ci.srWindow.Top;
            if (g_conCol < 0 || g_conCol >= g_conW) g_conCol = 0;
            if (g_conRow < 0 || g_conRow >= g_conH) g_conRow = 0;
        }
        if (SetConsoleMode(h, mode | ENB_VT_PROCESSING)) g_conKind = 1;
        else                                            g_conKind = 2;
    } else if (_isatty(_fileno(stdout))) {
        // mintty / ConPTY / cygwin: stdout is a pipe but the far end is a VT
        // terminal, so escapes are understood.  Size comes from the env.
        const char *cs = getenv("COLUMNS");
        const char *ls = getenv("LINES");
        if (cs && atoi(cs) >= 20) g_conW = atoi(cs);
        if (ls && atoi(ls) >= 5)  g_conH = atoi(ls);
        g_conCol = 0;
        g_conRow = 0;
        g_conKind = 1;
    }
    ConSyncMode();
}

static void ConRaw(const char *s, int n)
{
    if (n > 0) fwrite(s, 1, (size_t)n, stdout);
}

// Move the real terminal cursor by (dcol,drow) cells.
static void ConMove(int dcol, int drow)
{
    if (!dcol && !drow) return;
    ConProbe();
    char esc[32];
    if (g_conKind == 1) {
        if (drow < 0)      { _snprintf(esc, sizeof(esc), "\x1b[%dA", -drow); ConRaw(esc, (int)strlen(esc)); }
        else if (drow > 0) { _snprintf(esc, sizeof(esc), "\x1b[%dB",  drow); ConRaw(esc, (int)strlen(esc)); }
        if (dcol < 0)      { _snprintf(esc, sizeof(esc), "\x1b[%dD", -dcol); ConRaw(esc, (int)strlen(esc)); }
        else if (dcol > 0) { _snprintf(esc, sizeof(esc), "\x1b[%dC",  dcol); ConRaw(esc, (int)strlen(esc)); }
    } else if (g_conKind == 2) {
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO ci;
        fflush(stdout);
        if (!GetConsoleScreenBufferInfo(h, &ci)) return;
        COORD p = ci.dwCursorPosition;
        int   x = p.X + dcol, y = p.Y + drow;
        if (x < 0) x = 0;
        if (y < 0) y = 0;
        if (x > ci.dwSize.X - 1) x = ci.dwSize.X - 1;
        if (y > ci.dwSize.Y - 1) y = ci.dwSize.Y - 1;
        p.X = (SHORT)x; p.Y = (SHORT)y;
        SetConsoleCursorPosition(h, p);
    }
}

static void ConSetCursor(int col, int row)
{
    ConProbe();
    if (col < 0) col = 0;
    if (row < 0) row = 0;
    if (col > g_conW - 1) col = g_conW - 1;
    if (row > g_conH - 1) row = g_conH - 1;
    ConMove(col - g_conCol, row - g_conRow);
    g_conCol = col;
    g_conRow = row;
    g_conLastCR = 0;
    ConSyncMode();
}

// Advance the virtual cursor by one printed cell.
static void ConAdvance(void)
{
    if (++g_conCol >= g_conW) {
        g_conCol = 0;
        if (g_conRow < g_conH - 1) g_conRow++;
    }
    ConSyncMode();
}

// Emit UTF-16 as UTF-8 on stdout.
// NOTE: stdout is used with byte-oriented printf() elsewhere, so we must NEVER
// call putwchar()/wprintf() here - once a stream has an orientation, mixing
// wide and narrow output silently corrupts (or drops) characters.
static void PrintW(const CHAR16 *s)
{
    if (!s) return;
    __try {
        ConProbe();
        char buf[1024];
        UINTN n = 0;
        for (; *s; s++) {
            unsigned short c = (unsigned short)*s;
            if (c == 0x0D) {                              // CR: column 0
                if (n) { ConRaw(buf, (int)n); n = 0; }
                if (!g_conLastCR) ConRaw("\r", 1);        // UEFI emits CRCRLF a lot
                g_conLastCR = 1;
                g_conCol = 0;
                ConSyncMode();
                continue;
            }
            if (c == 0x0A) {                              // LF: next line, column 0
                if (n) { ConRaw(buf, (int)n); n = 0; }
                ConRaw(g_conLastCR ? "\n" : "\r\n", g_conLastCR ? 1 : 2);
                g_conLastCR = 0;
                g_conCol = 0;
                if (g_conRow < g_conH - 1) g_conRow++;
                ConSyncMode();
                continue;
            }
            if (c == 0x08) {                              // BS: one cell left
                if (n) { ConRaw(buf, (int)n); n = 0; }
                g_conLastCR = 0;
                if (g_conCol > 0) {
                    ConRaw("\b", 1);
                    g_conCol--;
                }
                ConSyncMode();
                continue;
            }
            if (c < 0x20) continue;                       // other control chars
            g_conLastCR = 0;
            if (c < 0x80) {
                buf[n++] = (char)c;
                if (n >= sizeof(buf)) { ConRaw(buf, (int)n); n = 0; }
            } else {
                if (n) { ConRaw(buf, (int)n); n = 0; }
                char mb[8];
                int k = WideCharToMultiByte(CP_UTF8, 0, (WCHAR *)&c, 1, mb, sizeof(mb), NULL, NULL);
                if (k > 0) ConRaw(mb, k);
                else       ConRaw("?", 1);
            }
            ConAdvance();
        }
        if (n) ConRaw(buf, (int)n);
        fflush(stdout);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        fputc('\n', stdout);
        fflush(stdout);
    }
}
static UINTN SO_OutputString(void *This, CHAR16 *s)
{
    if (LOGLV(3) && s) {
        void *ret = _ReturnAddress();
        LOGV(3, "[efihost] OUT this=%p rva=0x%llx str=%p:",
                This, (unsigned long long)((UINT8 *)ret - g_imageBase), (void *)s);
        for (UINTN i = 0; i < 64 && s[i]; i++) LOGV(3, " %04X", (unsigned short)s[i]);
        LOGV(3, "\n");
    }
    (void)This;
    PrintW(s);
    return 0;
}
static UINTN SO_Reset(void *This, char EV)
{
    (void)This; (void)EV;
    PrintW(L"\r\n");
    g_conCol = 0;
    ConSyncMode();
    return 0;
}
static UINTN SO_TestString(void *This, CHAR16 *s)   { (void)This; (void)s; return 0; }
static UINTN SO_QueryMode(void *This, UINTN m, UINTN *cols, UINTN *rows)
{
    (void)This; (void)m;
    ConProbe();
    if (cols) *cols = (UINTN)g_conW;
    if (rows) *rows = (UINTN)g_conH;
    return 0;
}
static UINTN SO_SetMode(void *This, UINTN m)
{
    (void)This; (void)m;
    return 0;
}
// UEFI attribute -> ANSI SGR.  bit0 blue, bit1 green, bit2 red, bit3 bright.
static void ConApplyAttr(int attr)
{
    if (g_conKind != 1) return;
    int fg = attr & 0x0F;
    int bg = (attr >> 4) & 0x07;
    int f  = (fg & 1) | ((fg & 2) ? 2 : 0) | ((fg & 4) ? 4 : 0);
    int b  = (bg & 1) | ((bg & 2) ? 2 : 0) | ((bg & 4) ? 4 : 0);
    char esc[32];
    _snprintf(esc, sizeof(esc), "\x1b[0;%d;%dm", (fg & 8) ? 90 + f : 30 + f, 40 + b);
    ConRaw(esc, (int)strlen(esc));
}
static UINTN SO_SetAttribute(void *This, UINTN a)
{
    (void)This;
    g_conAttr = (int)a;
    ConProbe();
    ConApplyAttr(g_conAttr);
    return 0;
}
static UINTN SO_ClearScreen(void *This)
{
    (void)This;
    ConProbe();
    fflush(stdout);
    if (g_conKind == 1) {
        const char *clr = "\x1b[0m\x1b[2J\x1b[H";      // reset attrs, erase, home
        ConRaw(clr, (int)strlen(clr));
    } else if (g_conKind == 2) {
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO ci;
        DWORD  written = 0;
        COORD  home = { 0, 0 };
        if (GetConsoleScreenBufferInfo(h, &ci)) {
            DWORD cells = (DWORD)ci.dwSize.X * (DWORD)ci.dwSize.Y;
            FillConsoleOutputCharacterA(h, ' ', cells, home, &written);
            FillConsoleOutputAttribute(h, (WORD)g_conAttr, cells, home, &written);
            SetConsoleCursorPosition(h, home);
        }
    } else {
        ConRaw("\f", 1);
    }
    g_conCol = 0;
    g_conRow = 0;
    ConSyncMode();
    return 0;
}
static UINTN SO_SetCursorPos(void *This, UINTN c, UINTN r)
{
    (void)This;
    ConProbe();
    ConSetCursor((int)c, (int)r);       // this is what makes the line editor work
    return 0;
}
static UINTN SO_EnableCursor(void *This, char e)
{
    (void)This;
    ConProbe();
    g_conCursorOn = e ? 1 : 0;
    g_conOutMode.CursorVisible = g_conCursorOn;
    g_errMode.CursorVisible    = g_conCursorOn;
    if (g_conKind == 1) ConRaw(g_conCursorOn ? "\x1b[?25h" : "\x1b[?25l", 6);
    return 0;
}
static UINTN SI_Reset(void *This, char EV)        { (void)This; (void)EV; return 0; }

// ---------------- keyboard layer ----------------
// Console mode : _kbhit/_getch, non-blocking, extended keys expanded.
// Redirected   : a background reader thread pumps stdin into a ring buffer,
//                so WaitForEvent can be polled without blocking.

#define KEYBUF 1024
static int   g_keyBuf[KEYBUF];
static volatile long g_keyHead, g_keyTail;   // head = write, tail = read
static volatile long g_stdinEof;
static CRITICAL_SECTION g_keyCs;

static DWORD WINAPI KeyReaderThread(void *arg)
{
    (void)arg;
    int prevCR = 0;
    for (;;) {
        int c = getchar();
        if (c == EOF) { g_stdinEof = 1; return 0; }
        // CRLF: the CR already ends the line, drop the LF. A bare LF acts as CR,
        // otherwise the shell would never see an end-of-line on Unix-style input.
        if (c == '\n') { if (prevCR) { prevCR = 0; continue; } c = '\r'; }
        prevCR = (c == '\r');
        LOGV(3, "[efihost] key thread: got 0x%02x '%c'\n", c,
                (c >= 32 && c < 127) ? c : '?');
        while ((g_keyHead + 1) % KEYBUF == g_keyTail) Sleep(5);  // full
        EnterCriticalSection(&g_keyCs);
        g_keyBuf[g_keyHead] = c;
        g_keyHead = (g_keyHead + 1) % KEYBUF;
        LeaveCriticalSection(&g_keyCs);
    }
}

static void KeyLayerInit(int redirected)
{
    InitializeCriticalSection(&g_keyCs);
    if (redirected) {
        HANDLE th = CreateThread(NULL, 0, KeyReaderThread, NULL, 0, NULL);
        if (th) CloseHandle(th);
    }
}

// 1 = a key is waiting (never consumes)
static int KeyAvailable(void)
{
    if (!g_inRedirected) return _kbhit() ? 1 : 0;
    return (g_keyHead != g_keyTail) ? 1 : 0;
}

// returns next raw char, or -1 if none
static int KeyGet(void)
{
    if (!g_inRedirected) return _getch();
    if (g_keyHead == g_keyTail) return -1;
    EnterCriticalSection(&g_keyCs);
    int c = g_keyBuf[g_keyTail];
    g_keyTail = (g_keyTail + 1) % KEYBUF;
    LeaveCriticalSection(&g_keyCs);
    return c;
}

// EFI_INPUT_KEY = { UINT16 ScanCode; CHAR16 UnicodeChar; }
// SCAN: 0x01 Up 0x02 Down 0x03 Right 0x04 Left 0x17 Esc ...
static UINTN SI_ReadKeyStroke(void *This, void *Key)
{
    g_cntKey++;
    (void)This;
    UINT16 *k = (UINT16 *)Key;
    k[0] = 0; k[1] = 0;
    if (!KeyAvailable()) return EFI_NOT_READY;
    int c = KeyGet();
    if (c < 0) return EFI_NOT_READY;
    if (!g_inRedirected && (c == 0 || c == 0xE0)) {   // extended key prefix
        int sc = KeyGet();
        switch (sc) {
        case 72: k[0] = 0x01; break;        // Up
        case 80: k[0] = 0x02; break;        // Down
        case 77: k[0] = 0x03; break;        // Right
        case 75: k[0] = 0x04; break;        // Left
        case 83: k[0] = 0x07; break;        // Delete
        case 71: k[0] = 0x05; break;        // Home
        case 79: k[0] = 0x06; break;        // End
        case 73: k[0] = 0x09; break;        // PgUp
        case 81: k[0] = 0x0A; break;        // PgDn
        case 82: k[0] = 0x0B; break;        // Insert
        case 59: k[0] = 0x0C; break;        // F1
        case 60: k[0] = 0x0D; break;        // F2
        case 61: k[0] = 0x0E; break;        // F3
        case 62: k[0] = 0x0F; break;        // F4
        }
        return 0;
    }
    if (c == '\r') { k[1] = 0x0D; return 0; }
    if (c == '\n') { k[1] = 0x0D; return 0; }
    if (c == 8)    { k[1] = 0x08; return 0; }
    if (c == 27)   { k[0] = 0x17; return 0; }  // Esc
    if (c == '\t') { k[1] = 0x09; return 0; }
    k[1] = (CHAR16)c;
    return 0;
}

// ------------------------------------------------------- boot services

#define BS_IDX_ALLOCATE_PAGES   5   // index of fn ptr in UINTN table (after 24-byte Hdr)
#define BS_IDX_FREE_PAGES       6
#define BS_IDX_GET_MEMORY_MAP   7
#define BS_IDX_ALLOCATE_POOL    8
#define BS_IDX_FREE_POOL        9
#define BS_IDX_STALL           31
#define BS_IDX_SET_WATCHDOG    32
#define BS_IDX_COPY_MEM        44
#define BS_IDX_SET_MEM         45

static UINTN BS_AllocatePages(UINTN Type, UINTN MemType, UINTN Pages, UINT64 **Memory)
{
    void *p = VirtualAlloc(NULL, Pages * 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) return EFI_NOT_FOUND;
    *Memory = (UINT64 *)p;
    return 0;
}
static UINTN BS_FreePages(UINT64 Memory, UINTN Pages) { VirtualFree((void *)Memory, 0, MEM_RELEASE); return 0; }
// Track malloc'ed pointers so FreePool never frees a foreign pointer
// (heap corruption in the host = instant fastfail crash).
// One array of records (single realloc => pointer/capacity can never diverge,
// which a set of parallel arrays can do when one realloc fails).
typedef struct {
    void  *p;         // block handed to the guest
    UINTN  sz;        // requested size
    void  *base;      // non-NULL => VirtualAlloc base (guard mode)
    UINTN  total;     // bytes reserved for that VirtualAlloc block
} POOLENT;

static POOLENT *g_pool;
static UINTN    g_poolCount;
static UINTN    g_poolCap;
static int      g_guardPool;   // EFHOST_GUARD=1: put a PAGE_NOACCESS page after every block

// 16-byte tail canary: catches UEFI-side overruns that would otherwise show up
// much later as STATUS_HEAP_CORRUPTION (0xC0000374) in an unrelated call.
#define POOL_PAD 16
#define POOL_CANARY 0xCD

static void PoolRecordEx(void *p, UINTN size, void *base, UINTN total)
{
    if (g_poolCount == g_poolCap) {
        UINTN    nc = g_poolCap ? g_poolCap * 2 : 8192;
        POOLENT *np = (POOLENT *)realloc(g_pool, nc * sizeof(POOLENT));
        if (!np) return;                 // keep cap unchanged; retry on next alloc
        g_pool    = np;
        g_poolCap = nc;
    }
    g_pool[g_poolCount].p     = p;
    g_pool[g_poolCount].sz    = size;
    g_pool[g_poolCount].base  = base;
    g_pool[g_poolCount].total = total;
    g_poolCount++;
}

// Re-check the most recently handed-out block on every pool operation: an
// overrun there shows up immediately (with a caller trace) instead of surfacing
// minutes later as STATUS_HEAP_CORRUPTION.
static void  *g_lastBlk;
static UINTN  g_lastSz;

static void PoolCheckLast(const char *where)
{
    if (!g_lastBlk) return;
    UINT8 *q = (UINT8 *)g_lastBlk + g_lastSz;
    for (int k = 0; k < POOL_PAD; k++) {
        if (q[k] != POOL_CANARY) {
            LOGV(1, "[efihost] POOL OVERRUN(last block) size=%llu at %s\n",
                 (unsigned long long)g_lastSz, where);
            ReportCaller("block handed out just before this point was overrun");
            g_lastBlk = NULL;
            return;
        }
    }
}

// every host-side UEFI pool block goes through here (also used by DpAlloc)
static void *PoolAlloc(UINTN size)
{
    UINTN n = size ? size : 1;

    if (g_guardPool) {
        // Block ends exactly at a PAGE_NOACCESS page: any write past the
        // requested size faults immediately, and the VEH dump points at the
        // offending EFI instruction.
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        UINTN  page = si.dwPageSize;
        UINTN  body = ((n + page - 1) / page) * page;
        UINT8 *base = (UINT8 *)VirtualAlloc(NULL, body + page, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!base) return NULL;
        DWORD old;
        if (!VirtualProtect(base + body, page, PAGE_NOACCESS, &old)) {
            VirtualFree(base, 0, MEM_RELEASE);
            return NULL;
        }
        // UEFI pool blocks are 8-byte aligned; keep that so 8/16-byte stores
        // by the guest never straddle into the guard page by accident.
        UINTN  asz = (n + 7) & ~(UINTN)7;
        UINT8 *p   = base + body - asz;
        PoolRecordEx(p, n, base, body + page);
        return p;
    }

    PoolCheckLast("PoolAlloc");
    UINTN real = n + POOL_PAD;
    UINT8 *p = (UINT8 *)malloc(real);
    if (!p) return NULL;
    memset(p + n, POOL_CANARY, POOL_PAD);
    PoolRecordEx(p, n, NULL, real);
    g_lastBlk = p;
    g_lastSz  = n;
    return p;
}

static UINTN BS_AllocatePool(UINTN PoolType, UINTN Size, void **Buffer)
{
    g_cntAlloc++;
    if (Size == 0 || Size > (1 << 20))
        LOGV(2, "[efihost] AllocPool(SUSPICIOUS size=0x%llx)\n", (unsigned long long)Size);
    LOGV(3, "[efihost] AllocPool(size=0x%llx)\n", (unsigned long long)Size);
    void *p = PoolAlloc(Size);
    if (!p) {
        LOGV(1, "[efihost] ALLOC FAILED size=0x%llx\n", (unsigned long long)Size);
        return EFI_NOT_FOUND;
    }
    *Buffer = p;
    return 0;
}
static UINTN BS_FreePool(void *Buffer)
{
    g_cntFree++;
    if (!g_guardPool) PoolCheckLast("FreePool");
    for (UINTN i = 0; i < g_poolCount; i++) {
        if (g_pool[i].p == Buffer) {
            UINTN  sz   = g_pool[i].sz;
            void  *base = g_pool[i].base;
            if (base) {
                VirtualFree(base, 0, MEM_RELEASE);
            } else {
                UINT8 *q   = (UINT8 *)Buffer + sz;
                int    bad = 0;
                for (int k = 0; k < POOL_PAD; k++) if (q[k] != POOL_CANARY) { bad = 1; break; }
                if (bad) {
                    LOGV(1, "[efihost] POOL OVERRUN: block %p size=%llu tail:", Buffer,
                         (unsigned long long)sz);
                    if (LOGLV(1)) {
                        for (int k = 0; k < POOL_PAD; k++) fprintf(stderr, " %02x", q[k]);
                        fprintf(stderr, "\n");
                    }
                    ReportCaller("FreePool(overrun block)");
                }
                free(Buffer);
                if (g_lastBlk == Buffer) g_lastBlk = NULL;   // don't inspect freed memory
            }
            // Drop EVERY record of this pointer: a stale duplicate would turn a
            // late second FreePool() into a double free (0xC0000374).
            for (UINTN j = 0; j < g_poolCount; ) {
                if (g_pool[j].p == Buffer) g_pool[j] = g_pool[--g_poolCount];
                else                       j++;
            }
            return 0;
        }
    }
    if (LOGLV(3)) ReportCaller("FreePool(UNTRACKED PTR - ignored)");
    // Never hand back EFI_INVALID_PARAMETER: DEBUG builds ASSERT_EFI_ERROR on this
    // and would abort.  Leaking a host-process allocation is harmless.
    return 0;
}
static UINTN BS_GetMemoryMap(UINTN *Size, EFI_MEMORY_DESCRIPTOR *Map, UINTN *Key,
                             UINTN *DescSize, UINT32 *DescVer)
{
    UINTN need = EFI_MEMORY_DESCRIPTOR_SIZE;
    if (DescSize) *DescSize = EFI_MEMORY_DESCRIPTOR_SIZE;
    if (DescVer)  *DescVer  = 1;
    if (!Size || *Size < need) { if (Size) *Size = need; return EFI_BUFFER_TOO_SMALL; }
    if (!Map) return EFI_INVALID_PARAMETER;
    Map[0].Type = 7; // EfiConventionalMemory
    Map[0].PhysicalStart = 0x100000;
    Map[0].VirtualStart  = 0;
    Map[0].NumberOfPages = 0x1000;
    Map[0].Attribute     = 0xF;
    if (Key) *Key = 1;
    return 0;
}
static UINTN BS_CopyMem(void *Dst, void *Src, UINTN n) { g_cntCopyMem++; memmove(Dst, Src, n); return 0; }
static UINTN BS_SetMem(void *Buf, UINTN n, UINT8 v)    { memset(Buf, v, n); return 0; }
static UINTN BS_Stall(UINTN us) { g_cntStall++; Sleep((DWORD)(us / 1000)); return 0; }
static UINTN BS_SetWatchdog(UINTN t, UINTN code) { return 0; }
static UINTN BS_ExitBootServices(UINTN ImageHandle, UINTN MapKey) { return 0; }

// EFI_BOOT_SERVICES: 24-byte header (3 UINTN slots) + 46 fn pointers.
// fn index = byteOffset/8:
//   3 RaiseTPL 4 RestoreTPL 5 AllocatePages 6 FreePages 7 GetMemoryMap
//   8 AllocatePool 9 FreePool ... 29 ExitBootServices 31 Stall 32 SetWatchdog
//   19 HandleProtocol 22 LocateHandle 39 LocateHandleBuffer 40 LocateProtocol
//   44 CopyMem 45 SetMem

static UINTN g_bs[47]; // 376 bytes

// ==================== EFI filesystem emulation ====================

// GUIDs
static UINT8 GUID_LoadedImage[16] = { 0xA1,0x31,0x1B,0x5B, 0x62,0x95, 0xD2,0x11, 0x8E,0x3F, 0x00,0xA0,0xC9,0x69,0x72,0x3B };
static UINT8 GUID_SimpleFS[16]    = { 0x22,0x5B,0x4E,0x96, 0x59,0x64, 0xD2,0x11, 0x8E,0x39, 0x00,0xA0,0xC9,0x69,0x72,0x3B };
static UINT8 GUID_FileInfo[16]    = { 0x92,0x6E,0x57,0x09, 0x3F,0x6D, 0xD2,0x11, 0x8E,0x39, 0x00,0xA0,0xC9,0x69,0x72,0x3B };
// 964E5B21-6459-11D2-8E39-00A0C969723B
static UINT8 GUID_BlockIo[16]     = { 0x21,0x5B,0x4E,0x96, 0x59,0x64, 0xD2,0x11, 0x8E,0x39, 0x00,0xA0,0xC9,0x69,0x72,0x3B };

static char g_fsDir[MAX_PATH] = ".";

// Mapped volumes.  One SimpleFileSystem protocol instance per directory, so the
// table has to be visible to the path resolver (which is defined before the
// protocol methods that fill it in).
#define MAX_VOL 8
typedef struct {
    UINT64 Revision;          // first member: the interface pointer IS `This`
    UINTN  OpenVolume;
    char   dir[MAX_PATH];
    char   label[16];
    UINT8  dp[24];
    UINTN  handle;
} SFS_VOL;

static SFS_VOL g_vols[MAX_VOL];
static int     g_volCount;

static void U16ToAscii(const CHAR16 *w, char *out, UINTN outCap)
{
    UINTN i = 0;
    for (; w[i] && i + 1 < outCap; i++) out[i] = (char)w[i];
    out[i] = 0;
}
static UINTN AsciiToU16(const char *s, CHAR16 *w, UINTN wCap)
{
    UINTN i = 0;
    for (; s[i] && i + 1 < wCap; i++) w[i] = (CHAR16)(unsigned char)s[i];
    w[i] = 0;
    return i;
}

// EFI_FILE_PROTOCOL object
typedef struct {
    UINT64 Revision;      // 0
    UINTN  Open;          // 8
    UINTN  Close;         // 0x10
    UINTN  Delete;        // 0x18
    UINTN  Read;          // 0x20
    UINTN  Write;         // 0x28
    UINTN  GetPosition;   // 0x30
    UINTN  SetPosition;   // 0x38
    UINTN  GetInfo;       // 0x40
    UINTN  SetInfo;       // 0x48
    UINTN  Flush;         // 0x50
    FILE  *fp;
    char   hostPath[MAX_PATH];
    char   name[260];
    // directory enumeration state (Read() returns a stream of EFI_FILE_INFO)
    int    isDir;
    int    vol;          // which mapped volume this handle belongs to
    int    findStarted, findDone;
    int    pending;      // o->fd holds an entry that has not been emitted yet
    HANDLE hFind;
    WIN32_FIND_DATAA fd;
} EFI_FILE_OBJ;

// Live-object tracking.  Shell sometimes closes the same handle twice (e.g.
// InternalOpenFileDevicePath closes the intermediate handle and a caller keeps
// its own copy); freeing twice corrupts the CRT heap (0xC0000374).  Track what
// we handed out and ignore a second Close() instead of dying.
#define MAX_FOBJ 1024
static EFI_FILE_OBJ *g_fobj[MAX_FOBJ];
static int           g_fobjN;
// Over-allocate: EFI_FILE_PROTOCOL v1 ends after Flush, but EDK2 declares
// OpenEx/ReadEx/WriteEx/FlushEx right after it, and a few code paths peek at
// (or zero) those slots.  64 spare bytes keeps that harmless.
static EFI_FILE_OBJ *AllocFileObj(void)
{
    return (EFI_FILE_OBJ *)calloc(1, sizeof(EFI_FILE_OBJ) + 64);
}

static void FObjTrack(EFI_FILE_OBJ *o) { if (g_fobjN < MAX_FOBJ) g_fobj[g_fobjN++] = o; }
static int  FObjUntrack(EFI_FILE_OBJ *o)
{
    for (int i = 0; i < g_fobjN; i++) {
        if (g_fobj[i] == o) { g_fobj[i] = g_fobj[--g_fobjN]; return 1; }
    }
    return 0;
}

// forward decls
static UINTN FOpen(void *This, void **New, CHAR16 *Name, UINT64 Mode, UINT64 Attr);
static UINTN FClose(void *This);
static UINTN FDelete(void *This);
static UINTN FRead(void *This, UINTN *Size, void *Buf);
static UINTN FWrite(void *This, UINTN *Size, void *Buf);
static UINTN FGetPosition(void *This, UINT64 *Pos);
static UINTN FSetPosition(void *This, UINT64 Pos);
static UINTN FGetInfo(void *This, UINT8 *InfoType, UINTN *Size, void *Info);
static UINTN FSetInfo(void *This, UINT8 *InfoType, UINTN Size, void *Info);
static UINTN FFlush(void *This);


static void InitFileFns(EFI_FILE_OBJ *o)
{
    g_cntGetInfo++;
    g_cntSetPos++;
    g_cntOpen++;
    g_cntWrite++;
    g_cntRead++;
    memset(o, 0, sizeof(*o));
    o->Revision    = 0x00010000;
    o->Open        = (UINTN)FOpen;
    o->Close       = (UINTN)FClose;
    o->Delete      = (UINTN)FDelete;
    o->Read        = (UINTN)FRead;
    o->Write       = (UINTN)FWrite;
    o->GetPosition = (UINTN)FGetPosition;
    o->SetPosition = (UINTN)FSetPosition;
    o->GetInfo     = (UINTN)FGetInfo;
    o->SetInfo     = (UINTN)FSetInfo;
    o->Flush       = (UINTN)FFlush;
}

#define EFI_FILE_MODE_READ   0x1ULL
#define EFI_FILE_MODE_WRITE  0x2ULL
#define EFI_FILE_MODE_CREATE 0x8000000000000000ULL

#ifndef EFI_WARN_DELETE_FAILURE
#define EFI_WARN_DELETE_FAILURE 1
#endif

// Resolve `wname` with UEFI EFI_FILE_PROTOCOL semantics:
//   * a name starting with '\' (or '/') is absolute, rooted at the volume
//   * anything else is relative to *this* directory handle, NOT to the volume
//     root.  Ignoring This broke every path with more than one component
//     ("cd docs; type c.txt" looked for <root>\c.txt).
//   * "." and ".." are honoured; ".." can never walk above the mapped root.
// Returns 1 for a real path, 0 for the volume root itself, -1 on error.
static int ResolvePath(const EFI_FILE_OBJ *dir, const CHAR16 *wname,
                       char *out, UINTN cap)
{
    char name[1024];
    U16ToAscii(wname ? wname : L"", name, sizeof(name));

    int absolute = (name[0] == '\\' || name[0] == '/');

    // every handle belongs to one volume; absolute paths and the ".." floor are
    // relative to that volume's root, not to the host base directory
    int v = (dir && dir->vol >= 0 && dir->vol < g_volCount) ? dir->vol : 0;
    const char *vroot = g_vols[v].dir;

    char base[MAX_PATH];
    if (!absolute && dir != NULL && dir->isDir && dir->hostPath[0]) {
        strncpy(base, dir->hostPath, sizeof(base) - 1);
        base[sizeof(base) - 1] = 0;
    } else {
        strncpy(base, vroot, sizeof(base) - 1);
        base[sizeof(base) - 1] = 0;
    }

    char  norm[MAX_PATH * 2];
    UINTN nlen = 0;
    strncpy(norm, base, sizeof(norm) - 1);
    norm[sizeof(norm) - 1] = 0;
    nlen = (UINTN)strlen(norm);
    while (nlen > 0 && (norm[nlen - 1] == '\\' || norm[nlen - 1] == '/')) norm[--nlen] = 0;

    // ".." may walk up to the mapped root but never above it.  The floor is the
    // root, NOT the directory we started from — otherwise Open("..") on a
    // subdirectory handle would return the subdirectory itself.
    UINTN floorLen = (UINTN)strlen(vroot);
    while (floorLen > 0 && (vroot[floorLen - 1] == '\\' || vroot[floorLen - 1] == '/')) floorLen--;
    if (nlen < floorLen || _strnicmp(norm, vroot, floorLen) != 0) {
        // base is not inside this volume; start from its root instead
        strncpy(norm, vroot, sizeof(norm) - 1);
        norm[sizeof(norm) - 1] = 0;
        nlen = floorLen;
        norm[nlen] = 0;
    }

    const char *p = name;
    while (*p) {
        while (*p == '\\' || *p == '/') p++;
        if (!*p) break;
        const char *e = p;
        while (*e && *e != '\\' && *e != '/') e++;
        UINTN clen = (UINTN)(e - p);

        if (clen == 1 && p[0] == '.') {
            // current directory: no-op
        } else if (clen == 2 && p[0] == '.' && p[1] == '.') {
            while (nlen > floorLen) {
                if (norm[nlen - 1] == '\\') { nlen--; break; }
                nlen--;
            }
            norm[nlen] = 0;
        } else if (nlen + clen + 2 >= sizeof(norm)) {
            return -1;
        } else {
            if (nlen) norm[nlen++] = '\\';
            memcpy(norm + nlen, p, clen);
            nlen += clen;
            norm[nlen] = 0;
        }
        p = e;
    }

    // Root is decided by the resolved path, not by "did we append anything":
    // Open(".") relative to a subdirectory must return that subdirectory, and
    // only a path that really lands on g_fsDir is the volume root.
    if (_stricmp(norm, vroot) == 0) {
        out[0] = 0;
        return 0;                               // volume root
    }
    _snprintf(out, cap, "%s", norm);
    out[cap - 1] = 0;
    return 1;
}

#define EFI_FILE_DIRECTORY_ATTR_LOCAL 0x0000000000000010ULL

static UINTN FOpen(void *This, void **New, CHAR16 *Name, UINT64 Mode, UINT64 Attr)
{
    EFI_FILE_OBJ *o = (EFI_FILE_OBJ *)This;
    LOGV(3, "[efihost] FS: Open Name=[%04x %04x %04x %04x %04x %04x %04x %04x] mode=0x%llx\n",
         Name ? (unsigned)Name[0] : 0, Name ? (unsigned)Name[1] : 0,
         Name ? (unsigned)Name[2] : 0, Name ? (unsigned)Name[3] : 0,
         Name ? (unsigned)Name[4] : 0, Name ? (unsigned)Name[5] : 0,
         Name ? (unsigned)Name[6] : 0, Name ? (unsigned)Name[7] : 0,
         (unsigned long long)Mode);
    char host[MAX_PATH * 2];
    int r = ResolvePath(o, Name, host, sizeof(host));
    if (g_traceBt) {
        char an[128], dbg[512];
        U16ToAscii(Name ? Name : L"", an, sizeof(an));
        _snprintf(dbg, sizeof(dbg), " Open(\"%s\") mode=0x%llx -> %s",
                  an, (unsigned long long)Mode,
                  r < 0 ? "invalid" : (r == 0 ? "<root>" : host));
        LogBt(2, dbg);
    }
    if (r < 0) return EFI_INVALID_PARAMETER;
    if (r == 0) {
        // open root again
        EFI_FILE_OBJ *root = AllocFileObj();
        InitFileFns(root);
        _snprintf(root->hostPath, sizeof(root->hostPath), "%s\\", g_vols[o->vol].dir);
        root->name[0] = 0;
        root->isDir = 1;
        root->vol   = o->vol;
        FObjTrack(root);
        *New = root;
        return 0;
    }
    // a directory? hand back an enumerable handle instead of trying to fopen() it
    {
        DWORD a = GetFileAttributesA(host);
        if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) {
            EFI_FILE_OBJ *d = AllocFileObj();
            InitFileFns(d);
            _snprintf(d->hostPath, sizeof(d->hostPath), "%s\\", host);
            { const char *bn = strrchr(host, '\\'); strncpy(d->name, bn ? bn + 1 : host, sizeof(d->name) - 1); }
            d->isDir = 1;
            d->vol   = o->vol;
            FObjTrack(d);
            *New = d;
            LOGV(2, "[efihost] FS: Open(dir \"%s\") -> OK\n", host);
            return 0;
        }
    }

    int canWrite  = (Mode & EFI_FILE_MODE_WRITE) != 0;
    int canCreate = (Mode & EFI_FILE_MODE_CREATE) != 0;

    // mkdir: EFI_FILE_MODE_CREATE plus EFI_FILE_DIRECTORY in Attributes.
    // Without this branch 'mkdir x' silently created a zero-byte *file*.
    if (canCreate && (Attr & EFI_FILE_DIRECTORY_ATTR_LOCAL)) {
        if (!CreateDirectoryA(host, NULL)) {
            DWORD e = GetLastError();
            if (e != ERROR_ALREADY_EXISTS) {
                LOGV(2, "[efihost] FS: CreateDir(\"%s\") failed err=%lu\n", host, (unsigned long)e);
                return EFI_ACCESS_DENIED;
            }
        }
        EFI_FILE_OBJ *d = AllocFileObj();
        InitFileFns(d);
        _snprintf(d->hostPath, sizeof(d->hostPath), "%s\\", host);
        { const char *bn = strrchr(host, '\\'); strncpy(d->name, bn ? bn + 1 : host, sizeof(d->name) - 1); }
        d->isDir = 1;
        d->vol   = o->vol;
        FObjTrack(d);
        *New = d;
        LOGV(2, "[efihost] FS: CreateDir(\"%s\") -> OK\n", host);
        return 0;
    }

    char m[4];
    if (canCreate && canWrite) {
        FILE *t = fopen(host, "rb");
        if (t) { fclose(t); strcpy(m, "r+b"); }
        else   { strcpy(m, "w+b"); }
    } else if (canWrite) {
        strcpy(m, "r+b");
    } else {
        strcpy(m, "rb");
    }
    FILE *fp = fopen(host, m);
    if (!fp) {
        LOGV(2, "[efihost] FS: Open(\"%s\") mode=0x%llx -> NOT_FOUND\n", host, (unsigned long long)Mode);
        return EFI_NOT_FOUND;
    }
    EFI_FILE_OBJ *f = AllocFileObj();
    InitFileFns(f);
    f->fp  = fp;
    f->vol = o->vol;
    strncpy(f->hostPath, host, sizeof(f->hostPath) - 1);
    { const char *bn = strrchr(host, '\\'); strncpy(f->name, bn ? bn + 1 : host, sizeof(f->name) - 1); }
    FObjTrack(f);
    LOGV(2, "[efihost] FS: Open(\"%s\") mode=0x%llx -> OK (%s)\n", host, (unsigned long long)Mode, m);
    *New = f;
    return 0;
}

static UINTN FClose(void *This)
{
    EFI_FILE_OBJ *o = (EFI_FILE_OBJ *)This;
    if (!o) return EFI_INVALID_PARAMETER;
    if (!FObjUntrack(o)) {
        LOGV(1, "[efihost] FS: WARN double Close(%p) ignored\n", (void *)o);
        return 0;
    }
    if (o->fp) { fclose(o->fp); o->fp = NULL; }
    if (o->findStarted && o->hFind != INVALID_HANDLE_VALUE) { FindClose(o->hFind); o->hFind = INVALID_HANDLE_VALUE; }
    o->isDir = 0;
    // Deliberately NOT freed: Shell keeps stale EFI_FILE_PROTOCOL* copies
    // (InternalOpenFileDevicePath closes intermediate handles and callers still
    // hold them).  Freeing here caused both heap corruption (0xC0000374) and
    // hangs on use-after-free.  The block is a few hundred bytes; keeping it
    // alive makes stale calls harmless no-ops.
    LOGV(3, "[efihost] FS: Close(%p) done (block retained)\n", (void *)o);
    return 0;
}

static UINTN FDelete(void *This)
{
    EFI_FILE_OBJ *o = (EFI_FILE_OBJ *)This;
    if (!o) return EFI_INVALID_PARAMETER;
    if (!FObjUntrack(o)) return 0;                 // already closed
    if (o->fp) fclose(o->fp);
    if (o->findStarted && o->hFind != INVALID_HANDLE_VALUE) FindClose(o->hFind);
    int ok = o->isDir ? (RemoveDirectoryA(o->hostPath) ? 0 : -1)
                      : remove(o->hostPath);
    LOGV(2, "[efihost] FS: Delete(\"%s\"%s) -> %s\n",
         o->hostPath, o->isDir ? ", dir" : "", ok == 0 ? "OK" : "FAILED");
    // same reasoning as FClose(): keep the block alive for stale pointers
    return ok == 0 ? 0 : EFI_WARN_DELETE_FAILURE;
}

// EFI_FILE_INFO: Size(8) FileSize(8) PhysicalSize(8) Create(16) Access(16)
//                Modify(16) Attribute(8) FileName[]  -> header is 80 bytes
#define EFI_FILE_INFO_HDR 80
#define EFI_FILE_DIRECTORY_ATTR 0x0000000000000010ULL
#define EFI_FILE_READ_ONLY_ATTR 0x0000000000000001ULL

// EFI_TIME: Year(2) Month Day Hour Minute Second Pad1(1) Nanosecond(4)
//           TimeZone(2) Daylight(1) Pad2(1)  = 16 bytes
static void FillEfiTime(const FILETIME *ft, UINT8 *out)
{
    SYSTEMTIME st;
    if (!FileTimeToSystemTime(ft, &st)) return;   // leave zeros
    UINT16 year = (UINT16)st.wYear;
    memcpy(out + 0, &year, 2);
    out[2]  = (UINT8)st.wMonth;
    out[3]  = (UINT8)st.wDay;
    out[4]  = (UINT8)st.wHour;
    out[5]  = (UINT8)st.wMinute;
    out[6]  = (UINT8)st.wSecond;
    out[7]  = 0;                                  // Pad1
    UINT32 ns = (UINT32)st.wMilliseconds * 1000000u;
    memcpy(out + 8, &ns, 4);
    INT16 tz = 0x07FF;                            // EFI_UNSPECIFIED_TIMEZONE
    memcpy(out + 12, &tz, 2);
    out[14] = 0;                                  // Daylight
    out[15] = 0;                                  // Pad2
}

static UINTN FRead(void *This, UINTN *Size, void *Buf)
{
    EFI_FILE_OBJ *o = (EFI_FILE_OBJ *)This;
    if (!Size) return EFI_INVALID_PARAMETER;
    LOGV(2, "[efihost] FS: Read(isDir=%d *Size=%llu Buf=%p)\n",
         o->isDir, (unsigned long long)*Size, Buf);

    if (!o->isDir) {
        if (!o->fp) return EFI_UNSUPPORTED;
        if (*Size == 0) return 0;
        UINTN n = fread(Buf, 1, *Size, o->fp);
        *Size = n;
        return 0;
    }

    // ---- directory: emit one EFI_FILE_INFO per call ----
    // Callers commonly probe with *Size == 0 (and sometimes a NULL buffer) to
    // learn the required size; that probe must NOT consume the entry.
    if (o->findDone && !o->pending) { *Size = 0; return 0; }   // end of listing
    if (!o->pending) {
        for (;;) {
            if (!o->findStarted) {
                char pat[MAX_PATH];
                _snprintf(pat, sizeof(pat), "%s*", o->hostPath);
                o->hFind = FindFirstFileA(pat, &o->fd);
                o->findStarted = 1;
                if (o->hFind == INVALID_HANDLE_VALUE) { o->findDone = 1; *Size = 0; return 0; }
            } else if (!FindNextFileA(o->hFind, &o->fd)) {
                o->findDone = 1; *Size = 0; return 0;
            }
            if (!strcmp(o->fd.cFileName, ".") || !strcmp(o->fd.cFileName, "..")) continue;
            o->pending = 1;
            LOGV(3, "[efihost] FS: ReadDir -> '%s' (%llu bytes, dir=%d)\n",
                    o->fd.cFileName,
                    (unsigned long long)(((UINT64)o->fd.nFileSizeHigh << 32) | o->fd.nFileSizeLow),
                    (o->fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0);
            break;
        }
    }
    UINTN nc = strlen(o->fd.cFileName);
    UINTN need = EFI_FILE_INFO_HDR + (nc + 1) * 2;
    if (!Buf || *Size < need) { *Size = need; return EFI_BUFFER_TOO_SMALL; }
    memset(Buf, 0, need);
    UINT8 *p = (UINT8 *)Buf;
    FillEfiTime(&o->fd.ftCreationTime,   p + 24);   // CreateTime
    FillEfiTime(&o->fd.ftLastAccessTime, p + 40);   // LastAccessTime
    FillEfiTime(&o->fd.ftLastWriteTime,  p + 56);   // ModificationTime
    UINT64 fsz = ((UINT64)o->fd.nFileSizeHigh << 32) | (UINT64)o->fd.nFileSizeLow;
    *(UINT64 *)(p + 0)  = need;
    *(UINT64 *)(p + 8)  = fsz;
    *(UINT64 *)(p + 16) = fsz;
    UINT64 attr = 0;
    if (o->fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) attr |= EFI_FILE_DIRECTORY_ATTR;
    if (o->fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY)  attr |= EFI_FILE_READ_ONLY_ATTR;
    *(UINT64 *)(p + 72) = attr;
    CHAR16 *fn = (CHAR16 *)(p + EFI_FILE_INFO_HDR);
    for (UINTN i = 0; i < nc; i++) fn[i] = (CHAR16)(unsigned char)o->fd.cFileName[i];
    fn[nc] = 0;
    *Size = need;
    o->pending = 0;                     // emitted; advance on the next call
    return 0;
}

static UINTN FWrite(void *This, UINTN *Size, void *Buf)
{
    EFI_FILE_OBJ *o = (EFI_FILE_OBJ *)This;
    if (!o->fp) return EFI_UNSUPPORTED;
    if (!Size) return EFI_INVALID_PARAMETER;
    UINTN want = *Size;
    UINTN n = fwrite(Buf, 1, want, o->fp);
    LOGV(2, "[efihost] FS: Write('%s') %llu/%llu bytes\n",
         o->name, (unsigned long long)n, (unsigned long long)want);
    *Size = n;
    return 0;
}

static UINTN FGetPosition(void *This, UINT64 *Pos)
{
    EFI_FILE_OBJ *o = (EFI_FILE_OBJ *)This;
    if (!Pos) return EFI_INVALID_PARAMETER;
    if (o->isDir) { *Pos = 0; return 0; }
    if (!o->fp) return EFI_UNSUPPORTED;
    *Pos = (UINT64)_ftelli64(o->fp);
    return 0;
}

static UINTN FSetPosition(void *This, UINT64 Pos)
{
    EFI_FILE_OBJ *o = (EFI_FILE_OBJ *)This;
    if (o->isDir) {
        // UEFI semantics: seeking a directory to 0 restarts enumeration.
        // Shell 'ls' calls FileHandleSetPosition(DirHandle, 0) before the
        // first Read(); returning UNSUPPORTED here makes it see an empty dir.
        if (o->findStarted && o->hFind != INVALID_HANDLE_VALUE) FindClose(o->hFind);
        o->hFind        = INVALID_HANDLE_VALUE;
        o->findStarted  = 0;
        o->findDone     = 0;
        o->pending      = 0;
        LOGV(2, "[efihost] FS: SetPosition(dir, %llu) -> restart enumeration\n",
             (unsigned long long)Pos);
        return 0;
    }
    if (!o->fp) return EFI_UNSUPPORTED;
    if (Pos == 0xFFFFFFFFFFFFFFFFULL)
        _fseeki64(o->fp, 0, SEEK_END);
    else
        _fseeki64(o->fp, (long long)Pos, SEEK_SET);
    return 0;
}

// EFI_FILE_SYSTEM_INFO GUID: 09576E93-6D3F-11D2-8E39-00A0C969723B
static UINT8 GUID_FileSystemInfo[16] = { 0x93,0x6E,0x57,0x09, 0x3F,0x6D, 0xD2,0x11, 0x8E,0x39, 0x00,0xA0,0xC9,0x69,0x72,0x3B };

static UINTN FGetInfo(void *This, UINT8 *InfoType, UINTN *Size, void *Info)
{
    EFI_FILE_OBJ *o = (EFI_FILE_OBJ *)This;
    if (!Size) return EFI_INVALID_PARAMETER;

    // ---- EFI_FILE_SYSTEM_INFO: volume query (Shell 'map' / 'ls' ask for it) ----
    if (memcmp(InfoType, GUID_FileSystemInfo, 16) == 0) {
        static const char lab[] = "HOSTFS";
        UINTN nlab = strlen(lab);
        UINTN need = 36 + (nlab + 1) * 2;      // Size..BlockSize(36) + label
        if (*Size < need) { *Size = need; return EFI_BUFFER_TOO_SMALL; }
        memset(Info, 0, need);
        *(UINT64  *)((char *)Info + 0)  = need;              // Size
        /* +8 ReadOnly = FALSE (memset) */
        *(UINT64  *)((char *)Info + 16) = (UINT64)1 << 31;   // VolumeSize  2 GiB
        *(UINT64  *)((char *)Info + 24) = (UINT64)1 << 30;   // FreeSpace   1 GiB
        *(UINT32  *)((char *)Info + 32) = 512;               // BlockSize
        for (UINTN i = 0; i <= nlab; i++)
            ((CHAR16 *)((char *)Info + 36))[i] = (CHAR16)lab[i];
        *Size = need;
        LOGV(2, "[efihost] FS: GetInfo(FileSystemInfo) -> %u bytes\n", (unsigned)need);
        return 0;
    }

    if (memcmp(InfoType, GUID_FileInfo, 16) != 0) {
        LOGV(2, "[efihost] FS: GetInfo(unknown guid %02x%02x...) -> UNSUPPORTED\n",
             InfoType[0], InfoType[1]);
        return EFI_UNSUPPORTED;
    }
    UINT64 fsize = 0;
    if (o->fp) {
        long long cur = _ftelli64(o->fp);
        _fseeki64(o->fp, 0, SEEK_END);
        fsize = (UINT64)_ftelli64(o->fp);
        _fseeki64(o->fp, cur, SEEK_SET);
    }
    // EFI_FILE_INFO header is 80 bytes:
    //   Size(8) FileSize(8) PhysicalSize(8) Create(16) Access(16) Mod(16)
    //   Attribute(8 @72) FileName[](@80)
    // (an earlier version used 88 / Attribute@80, which produced an empty
    //  FileName and made Shell refuse to enumerate the directory)
    //
    // The volume root must report an EMPTY FileName, not "." — MdePkg's
    // FileHandleGetFileName() walks up with Open("..") in a loop and only
    // stops when the name it reads back is empty (or Open fails).  Reporting
    // "." made it loop forever once Open("..") started succeeding.
    const char *nm = o->name;
    UINTN namelen = strlen(nm);
    UINTN need = 80 + (namelen + 1) * 2;
    if (*Size < need) { *Size = need; return EFI_BUFFER_TOO_SMALL; }
    memset(Info, 0, need);
    UINT64 *q = (UINT64 *)Info;
    q[0] = need;          // Size
    q[1] = fsize;         // FileSize
    q[2] = fsize;         // PhysicalSize
    UINT64 attr = 0;
    if (o->isDir) attr |= EFI_FILE_DIRECTORY_ATTR;
    *(UINT64 *)((UINT8 *)Info + 72) = attr;      // Attribute
    AsciiToU16(nm, (CHAR16 *)((UINT8 *)Info + 80), namelen + 1);
    *Size = need;
    LOGV(2, "[efihost] FS: GetInfo(FileInfo) '%s' size=%llu attr=0x%llx -> %u bytes\n",
         nm[0] ? nm : "<root>", (unsigned long long)fsize, (unsigned long long)attr, (unsigned)need);
    return 0;
}

static UINTN FSetInfo(void *This, UINT8 *InfoType, UINTN Size, void *Info)
{
    EFI_FILE_OBJ *o = (EFI_FILE_OBJ *)This;
    if (!o || !InfoType || !Info) return EFI_INVALID_PARAMETER;
    if (memcmp(InfoType, GUID_FileInfo, 16) != 0) {
        LOGV(2, "[efihost] FS: SetInfo(unknown guid %02x%02x) -> UNSUPPORTED\n",
             InfoType[0], InfoType[1]);
        return EFI_UNSUPPORTED;
    }
    if (o->isDir || !o->fp) return EFI_UNSUPPORTED;
    if (Size < 80) return EFI_INVALID_PARAMETER;

    // sizeof(EFI_FILE_INFO) at [0], FileSize at [8], Attribute at [72]
    UINT64 newSize = *(UINT64 *)((UINT8 *)Info + 8);
    if (newSize != 0xFFFFFFFFFFFFFFFFULL) {          // ~0 = "leave size alone"
        if (_chsize_s(_fileno(o->fp), (long long)newSize) != 0) {
            LOGV(2, "[efihost] FS: SetInfo(FileInfo) truncate '%s' -> %llu FAILED\n",
                 o->name, (unsigned long long)newSize);
            return EFI_DEVICE_ERROR;
        }
        LOGV(2, "[efihost] FS: SetInfo(FileInfo) truncate '%s' -> %llu bytes\n",
             o->name, (unsigned long long)newSize);
    }
    return 0;
}

static UINTN FFlush(void *This)
{
    EFI_FILE_OBJ *o = (EFI_FILE_OBJ *)This;
    if (o->fp) fflush(o->fp);
    return 0;
}

// ---- volumes: one SimpleFileSystem protocol per mapped directory ----
//
// Hardcoded layout:
//   <fsdir>\fs0, fs1, fs2            -> SimpleFileSystem volumes (FS0:, FS1:, FS2:)
//   <fsdir>\blk0, blk1, blk2 (files) -> BlockIo devices (Shell calls them BLK0:, BLK1:)
//   a blkN *directory* is mounted as a plain volume instead, so the name still
//   works when it just holds loose files.
// If none of those names exist the whole <fsdir> is mounted as a single volume,
// which keeps the old single-volume behaviour.
// (SFS_VOL / g_vols / g_volCount are declared next to g_fsDir, above.)

// Every volume needs its own device path, otherwise Shell cannot tell the
// handles apart and map/`cd` get confused.  A VenHw node with a unique GUID
// byte also gives a stable sort order, so FS0: is always fs0.
static void MakeVolDp(UINT8 *dp, int idx)
{
    static const UINT8 base[24] = {
        0x01,0x04,0x14,0x00,
        0x11,0x22,0x33,0x44, 0x55,0x66, 0x77,0x88,
        0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,
        0x7F,0xFF,0x04,0x00
    };
    memcpy(dp, base, sizeof(base));
    dp[4] = (UINT8)(0x20 + idx);
}

static int VolIndex(void *This)
{
    for (int i = 0; i < g_volCount; i++)
        if ((void *)&g_vols[i] == This) return i;
    return 0;
}

static UINTN SFS_OpenVolume(void *This, void **Root)
{
    int v = VolIndex(This);
    EFI_FILE_OBJ *root = AllocFileObj();
    if (!root) return EFI_OUT_OF_RESOURCES;
    InitFileFns(root);
    _snprintf(root->hostPath, sizeof(root->hostPath), "%s\\", g_vols[v].dir);
    root->vol   = v;
    root->isDir = 1;
    *Root = root;
    LOGV(2, "[efihost] FS: OpenVolume(%s) -> root '%s\\'\n", g_vols[v].label, g_vols[v].dir);
    return 0;
}

static void VolAdd(const char *dir, const char *label)
{
    if (g_volCount >= MAX_VOL) return;
    SFS_VOL *v = &g_vols[g_volCount];
    memset(v, 0, sizeof(*v));
    v->Revision   = 0x00010000;
    v->OpenVolume = (UINTN)SFS_OpenVolume;
    _snprintf(v->dir,   sizeof(v->dir),   "%s", dir);
    _snprintf(v->label, sizeof(v->label), "%s", label);
    v->handle = 0xAAAA1000ULL + (UINTN)g_volCount;
    MakeVolDp(v->dp, g_volCount);
    g_volCount++;
}

// ---- block devices (BLKn: in the Shell) ----------------------------------

typedef struct {
    UINT32 MediaId;
    UINT8  RemovableMedia;
    UINT8  MediaPresent;
    UINT8  LogicalPartition;
    UINT8  ReadOnly;
    UINT8  WriteCaching;
    UINT32 BlockSize;
    UINT32 IoAlign;
    UINT64 LastBlock;
    UINT64 LowestAlignedLba;
    UINT32 LogicalBlocksPerPhysicalBlock;
    UINT32 OptimalTransferLengthGranularity;
} BLK_MEDIA;

typedef struct {
    UINT64     Revision;
    BLK_MEDIA *Media;
    UINTN      Reset;
    UINTN      ReadBlocks;
    UINTN      WriteBlocks;
    UINTN      FlushBlocks;
} BLK_IO;

typedef struct {
    BLK_IO    io;             // first member: callbacks receive &io as This
    char      path[MAX_PATH];
    FILE     *fp;
    UINTN     handle;
    UINT8     dp[24];
    BLK_MEDIA media;
} BLK_DEV;

static BLK_DEV g_blks[3];
static int     g_blkCount;

static UINTN BLK_Reset(void *This, char Extended)
{
    (void)This; (void)Extended;
    return 0;
}

static UINTN BLK_ReadBlocks(void *This, UINT32 MediaId, UINT64 Lba,
                            UINTN BufSize, void *Buf)
{
    BLK_DEV *d = (BLK_DEV *)This;
    if (!d || !Buf) return EFI_INVALID_PARAMETER;
    if (MediaId != d->media.MediaId) return EFI_MEDIA_CHANGED;
    if (!d->media.MediaPresent) return EFI_NO_MEDIA;
    if (d->media.BlockSize == 0 || BufSize % d->media.BlockSize) return EFI_BAD_BUFFER_SIZE;
    if (Lba > d->media.LastBlock) return EFI_INVALID_PARAMETER;
    if (Lba + BufSize / d->media.BlockSize - 1 > d->media.LastBlock) return EFI_INVALID_PARAMETER;
    if (!d->fp) return EFI_DEVICE_ERROR;
    if (_fseeki64(d->fp, (long long)(Lba * d->media.BlockSize), SEEK_SET) != 0) return EFI_DEVICE_ERROR;
    UINTN got = (UINTN)fread(Buf, 1, BufSize, d->fp);
    if (got != BufSize) {
        memset((UINT8 *)Buf + got, 0, BufSize - got);
        return EFI_DEVICE_ERROR;
    }
    return 0;
}

static UINTN BLK_WriteBlocks(void *This, UINT32 MediaId, UINT64 Lba,
                             UINTN BufSize, void *Buf)
{
    BLK_DEV *d = (BLK_DEV *)This;
    if (!d || !Buf) return EFI_INVALID_PARAMETER;
    if (MediaId != d->media.MediaId) return EFI_MEDIA_CHANGED;
    if (!d->media.MediaPresent) return EFI_NO_MEDIA;
    if (d->media.ReadOnly) return EFI_WRITE_PROTECTED;
    if (d->media.BlockSize == 0 || BufSize % d->media.BlockSize) return EFI_BAD_BUFFER_SIZE;
    if (Lba > d->media.LastBlock) return EFI_INVALID_PARAMETER;
    if (Lba + BufSize / d->media.BlockSize - 1 > d->media.LastBlock) return EFI_INVALID_PARAMETER;
    if (!d->fp) return EFI_DEVICE_ERROR;
    if (_fseeki64(d->fp, (long long)(Lba * d->media.BlockSize), SEEK_SET) != 0) return EFI_DEVICE_ERROR;
    UINTN put = (UINTN)fwrite(Buf, 1, BufSize, d->fp);
    fflush(d->fp);
    LOGV(3, "[efihost] BLK: write lba=%llu %llu bytes -> %llu\n",
         (unsigned long long)Lba, (unsigned long long)BufSize, (unsigned long long)put);
    return put == BufSize ? 0 : EFI_DEVICE_ERROR;
}

static UINTN BLK_Flush(void *This)
{
    BLK_DEV *d = (BLK_DEV *)This;
    if (d && d->fp) fflush(d->fp);
    return 0;
}

static void BlkAdd(const char *path)
{
    if (g_blkCount >= 3) return;
    BLK_DEV *d = &g_blks[g_blkCount];
    memset(d, 0, sizeof(*d));
    _snprintf(d->path, sizeof(d->path), "%s", path);

    d->fp = fopen(path, "r+b");
    int writable = d->fp != NULL;
    if (!d->fp) d->fp = fopen(path, "rb");
    if (!d->fp) {
        LOGV(1, "[efihost] BLK: cannot open '%s'\n", path);
        return;
    }

    _fseeki64(d->fp, 0, SEEK_END);
    long long sz = _ftelli64(d->fp);
    _fseeki64(d->fp, 0, SEEK_SET);
    if (sz <= 0) {
        fclose(d->fp);
        d->fp = NULL;
        return;
    }

    d->handle = 0xAAAA2000ULL + (UINTN)g_blkCount;
    MakeVolDp(d->dp, 0x40 + g_blkCount);

    d->media.MediaId        = 0x42 + (UINT32)g_blkCount;
    d->media.MediaPresent   = 1;
    d->media.LogicalPartition = 0;
    d->media.ReadOnly       = writable ? 0 : 1;
    d->media.BlockSize      = 512;
    d->media.IoAlign        = 4;
    d->media.LastBlock      = (UINT64)(sz / 512) - 1;
    d->media.LowestAlignedLba = 0;
    d->media.LogicalBlocksPerPhysicalBlock = 1;
    d->media.OptimalTransferLengthGranularity = 1;

    d->io.Revision    = 0x00010000;
    d->io.Media       = &d->media;
    d->io.Reset       = (UINTN)BLK_Reset;
    d->io.ReadBlocks  = (UINTN)BLK_ReadBlocks;
    d->io.WriteBlocks = (UINTN)BLK_WriteBlocks;
    d->io.FlushBlocks = (UINTN)BLK_Flush;

    g_blkCount++;
    LOGV(1, "[efihost] blk %d: '%s' %llu blocks x 512 (%s)\n",
         g_blkCount - 1, path, (unsigned long long)(d->media.LastBlock + 1),
         writable ? "rw" : "ro");
}

static void VolumesInit(const char *base)
{
    static const char *fsNames[]  = { "fs0", "fs1", "fs2" };
    static const char *blkNames[] = { "blk0", "blk1", "blk2" };

    g_volCount = 0;
    g_blkCount = 0;

    for (int i = 0; i < 3; i++) {
        char p[MAX_PATH];
        _snprintf(p, sizeof(p), "%s\\%s", base, fsNames[i]);
        DWORD a = GetFileAttributesA(p);
        if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY))
            VolAdd(p, fsNames[i]);
    }

    for (int i = 0; i < 3; i++) {
        char p[MAX_PATH];
        _snprintf(p, sizeof(p), "%s\\%s", base, blkNames[i]);
        DWORD a = GetFileAttributesA(p);
        if (a == INVALID_FILE_ATTRIBUTES) continue;
        if (a & FILE_ATTRIBUTE_DIRECTORY) { VolAdd(p, blkNames[i]); continue; }
        BlkAdd(p);
    }

    if (g_volCount == 0) VolAdd(base, "root");   // legacy single-volume layout

    for (int i = 0; i < g_volCount; i++)
        LOGV(1, "[efihost] vol %d: '%s' -> FS%d: dir='%s'\n",
             i, g_vols[i].label, i, g_vols[i].dir);
}

// ---- LoadedImage protocol ----
static EFI_SYSTEM_TABLE *g_stForLI;
typedef struct {
    UINT64 Revision;
    UINT64 ParentHandle;
    UINT64 SystemTable;
    UINT64 DeviceHandle;
    UINT64 FilePath;
    UINT64 Reserved;
    UINT32 LoadOptionsSize;
    UINT32 _pad;
    UINT64 LoadOptions;
    UINT64 ImageBase;
    UINT64 ImageSize;
    UINT32 ImageCodeType;
    UINT32 ImageDataType;
    UINT64 Unload;
} EFI_LOADED_IMAGE;

// The host's own image (the one Shell runs in).  Nested images loaded through
// gBS->LoadImage get their own EFI_LOADED_IMAGE, otherwise Shell's per-image
// fixup (LoadOptions / DeviceHandle) would corrupt the outer shell state.
static EFI_LOADED_IMAGE g_LoadedImage;

// ==================== handle / protocol database ====================

static UINT8 GUID_HIIDatabase[16]    = { 0x72,0xC1,0x9F,0xEF, 0xB2,0xA1, 0x93,0x46, 0xB3,0x27,0x6D,0x32,0xFC,0x41,0x60,0x42 };
static UINT8 GUID_HIIString[16]      = { 0x74,0x69,0xD9,0x0F, 0xAA,0x23, 0xDC,0x4C, 0xB9,0xCB,0x98,0xD1,0x77,0x50,0x32,0x2A };
static UINT8 GUID_HIIFont[16]        = { 0x75,0x47,0xCA,0xE9, 0x57,0x86, 0xFC,0x47, 0x97,0xE7,0x7E,0xD6,0x5A,0x08,0x43,0x24 };
static UINT8 GUID_HIIConfigRouting[16] = { 0xD7,0x72,0x7E,0x58, 0x50,0xCC, 0x79,0x4F, 0x82,0x09,0xCA,0x29,0x1F,0xC1,0xA1,0x0F };
// HII Image: 31A6406A-6BDF-4E46-B2A2-EBAA89C40920 (MdePkg/Include/Protocol/HiiImage.h)
static UINT8 GUID_HIIImage[16]        = { 0x6A,0x40,0xA6,0x31, 0xDF,0x6B, 0x46,0x4E, 0xB2,0xA2,0xEB,0xAA,0x89,0xC4,0x09,0x20 };
static UINT8 GUID_DevicePathUtils[16] = { 0x4E,0xBE,0x79,0x03, 0x06,0xD7, 0x7D,0x43, 0xB0,0x37,0xED,0xB8,0x2F,0xB7,0x72,0xA4 };
// UnicodeCollation2: A4C751FC-23AE-4C3E-92E9-4964CF63F349
static UINT8 GUID_UnicodeCollation2[16] = { 0xFC,0x51,0xC7,0xA4, 0xAE,0x23, 0x3E,0x4C,
                                            0x92,0xE9,0x49,0x64,0xCF,0x63,0xF3,0x49 };
static UINT8 GUID_SimpleTextIn[16]      = { 0xC1,0x77,0x74,0x38, 0xC7,0x69, 0xD2,0x11,
                                            0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B };
static UINT8 GUID_SimpleTextOut[16]     = { 0xC2,0x77,0x74,0x38, 0xC7,0x69, 0xD2,0x11,
                                            0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B };
// EFI_DEVICE_PATH_PROTOCOL: 09576E91-6D3F-11D2-8E39-00A0C969723B
static UINT8 GUID_DevicePath[16]        = { 0x91,0x6E,0x57,0x09, 0x3F,0x6D, 0xD2,0x11,
                                            0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B };
// A real (multi-node) device path for the host volume.  A bare End node is
// valid but some EDK2 consumers (consistency mapping / DevicePathToText) like
// having an actual node to describe, so use a Hardware Vendor node + End.
//   Node 1: HARDWARE_DEVICE_PATH / HW_VENDOR_DP, Length = 20 (4 + 16-byte GUID)
//   Node 2: END_ENTIRE_DEVICE_PATH, Length = 4
static UINT8 g_endDevicePath[24] = {
    0x01, 0x04, 0x14, 0x00,
    0x11,0x22,0x33,0x44, 0x55,0x66, 0x77,0x88,
    0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,
    0x7F, 0xFF, 0x04, 0x00
};

// LoadedImage.FilePath must be a *file* device path, not the volume path:
// Shell feeds it to StrLen()/path helpers, and a VenHw node has no NUL
// terminator, so StrLen used to walk straight off the end and fault.
//   Media/MEDIA_FILEPATH_DP(L"Shell.efi") + End  -> 4 + (9+1)*2 + 4 = 28 bytes
static UINT8 g_imageFilePath[28] = {
    0x04, 0x04, 0x18, 0x00,
    'S',0, 'h',0, 'e',0, 'l',0, 'l',0, '.',0, 'e',0, 'f',0, 'i',0, 0,0,
    0x7F, 0xFF, 0x04, 0x00
};
// DevicePathToText: 8B843E20-8132-4852-90CC-551A4E4A7F1C
static UINT8 GUID_DevicePathToText[16]  = { 0x20,0x3E,0x84,0x8B, 0x32,0x81, 0x52,0x48,
                                            0x90,0xCC,0x55,0x1A,0x4E,0x4A,0x7F,0x1C };
// DevicePathFromText: 05C99A21-C70F-4AD2-8A5F-35DF3343F51E
static UINT8 GUID_DevicePathFromText[16]= { 0x21,0x9A,0xC9,0x05, 0x0F,0xC7, 0xD2,0x4A,
                                            0x8A,0x5F,0x35,0xDF,0x33,0x43,0xF5,0x1E };

typedef struct { UINT8 guid[16]; void *iface; } PROTO_INST;
typedef struct {
    UINTN      handle;
    PROTO_INST protos[24];
    UINTN      count;
    int        used;
} EFI_HANDLE_OBJ;

static EFI_HANDLE_OBJ g_handleTab[64];
static UINTN g_nextHandle = 0xBBBB0000;

static EFI_HANDLE_OBJ *HandleFind(UINTN h)
{
    for (UINTN i = 0; i < 64; i++)
        if (g_handleTab[i].used && g_handleTab[i].handle == h) return &g_handleTab[i];
    return NULL;
}
static EFI_HANDLE_OBJ *HandleGet(UINTN h)   // get or create
{
    EFI_HANDLE_OBJ *o = HandleFind(h);
    if (o) return o;
    for (UINTN i = 0; i < 64; i++)
        if (!g_handleTab[i].used) {
            memset(&g_handleTab[i], 0, sizeof(g_handleTab[i]));
            g_handleTab[i].used = 1;
            g_handleTab[i].handle = h;
            return &g_handleTab[i];
        }
    return NULL;
}
static void *HandleLookup(EFI_HANDLE_OBJ *ho, UINT8 *guid)
{
    if (!ho) return NULL;
    // SimpleFileSystem is per-volume now and lives on its own handle, so it is
    // deliberately NOT faked here (a bogus SFS on the image handle would make
    // LocateDevicePath hand out a volume-less handle)
    for (UINTN i = 0; i < ho->count; i++)
        if (memcmp(ho->protos[i].guid, guid, 16) == 0) return ho->protos[i].iface;
    // LoadedImage is per-image: only fall back to ours when the handle has none
    if (memcmp(guid, GUID_LoadedImage, 16) == 0)  return &g_LoadedImage;
    return NULL;
}

// ---------------- Boot Services: protocol installation ----------------

static UINTN BS_InstallProtocolInterface(UINTN *Reg, UINT8 *Protocol, UINTN IfaceType, void *Interface)
{
    if (!Reg || !Protocol) return EFI_INVALID_PARAMETER;
    UINTN h = *Reg;
    if (!h) { h = ++g_nextHandle; *Reg = h; }
    EFI_HANDLE_OBJ *ho = HandleGet(h);
    if (!ho) return EFI_OUT_OF_RESOURCES;
    if (ho->count < 24) {
        memcpy(ho->protos[ho->count].guid, Protocol, 16);
        ho->protos[ho->count].iface = Interface;
        ho->count++;
    }
    return 0;
}

// varargs: (&Handle, Guid1, Iface1, Guid2, Iface2, ..., NULL)
static UINTN BS_InstallMultiProtocol(UINTN *Handle, ...)
{
    if (!Handle) return EFI_INVALID_PARAMETER;
    UINTN h = *Handle;
    if (!h) { h = ++g_nextHandle; *Handle = h; }
    EFI_HANDLE_OBJ *ho = HandleGet(h);
    if (!ho) return EFI_OUT_OF_RESOURCES;
    va_list ap;
    va_start(ap, Handle);
    while (1) {
        UINT8 *g = va_arg(ap, UINT8 *);
        if (!g) break;
        void *ifc = va_arg(ap, void *);
        if (ho->count < 24) {
            memcpy(ho->protos[ho->count].guid, g, 16);
            ho->protos[ho->count].iface = ifc;
            ho->count++;
        }
    }
    va_end(ap);
    return 0;
}

static UINTN BS_UninstallProtocolInterface(UINTN Handle, UINT8 *Protocol, void *Interface)
{
    EFI_HANDLE_OBJ *ho = HandleFind(Handle);
    if (!ho) return EFI_NOT_FOUND;
    for (UINTN i = 0; i < ho->count; i++)
        if (memcmp(ho->protos[i].guid, Protocol, 16) == 0 && ho->protos[i].iface == Interface) {
            memmove(&ho->protos[i], &ho->protos[i + 1], (ho->count - i - 1) * sizeof(PROTO_INST));
            ho->count--;
            return 0;
        }
    return EFI_NOT_FOUND;
}

static UINTN BS_ReinstallProtocolInterface(UINTN h, UINT8 *g, void *Old, void *New)
{
    EFI_HANDLE_OBJ *ho = HandleFind(h);
    if (!ho) return EFI_NOT_FOUND;
    for (UINTN i = 0; i < ho->count; i++)
        if (memcmp(ho->protos[i].guid, g, 16) == 0 && ho->protos[i].iface == Old) {
            ho->protos[i].iface = New;
            return 0;
        }
    return EFI_NOT_FOUND;
}

static UINTN BS_OpenProtocolInfo(UINTN Handle, UINT8 *Protocol, void **EntryBuffer, UINTN *Count)
{
    (void)Handle; (void)Protocol;
    if (EntryBuffer) *EntryBuffer = NULL;
    if (Count) *Count = 0;
    return 0;
}

static UINTN BS_ProtocolsPerHandle(UINTN Handle, UINT8 ***ProtoBuf, UINTN *Count)
{
    EFI_HANDLE_OBJ *ho = HandleFind(Handle);
    if (!ho || !ProtoBuf || !Count) return EFI_INVALID_PARAMETER;
    UINT8 **arr = malloc((ho->count + 1) * sizeof(UINT8 *));
    for (UINTN i = 0; i < ho->count; i++) arr[i] = ho->protos[i].guid;
    *ProtoBuf = arr;
    *Count = ho->count;
    return 0;
}

static UINTN CollectHandlesFor(UINT8 *guid, UINTN **buf, UINTN *count)
{
    UINTN *tmp = malloc(256 * sizeof(UINTN));
    UINTN n = 0;
    if (memcmp(guid, GUID_SimpleFS, 16) == 0 || memcmp(guid, GUID_LoadedImage, 16) == 0)
        tmp[n++] = 0xAAAA0000;
    for (UINTN i = 0; i < 64; i++) {
        if (!g_handleTab[i].used) continue;
        for (UINTN j = 0; j < g_handleTab[i].count; j++)
            if (memcmp(g_handleTab[i].protos[j].guid, guid, 16) == 0) { tmp[n++] = g_handleTab[i].handle; break; }
    }
    *buf = tmp;
    *count = n;
    return 0;
}

static UINTN OP_LocateHandle2(UINTN SearchType, UINT8 *Protocol, void *Key,
                              UINTN *Size, UINTN *Buffer)
{
    (void)SearchType; (void)Key;
    if (!Size) return EFI_INVALID_PARAMETER;
    UINTN *tmp, n;
    CollectHandlesFor(Protocol, &tmp, &n);
    UINTN need = n * sizeof(UINTN);
    if (*Size < need) { *Size = need; free(tmp); return EFI_BUFFER_TOO_SMALL; }
    if (Buffer) memcpy(Buffer, tmp, need);
    *Size = need;
    free(tmp);
    return n;
}

static UINTN OP_LocateHandleBuffer2(UINTN SearchType, UINT8 *Protocol, void *Key,
                                    UINTN *Count, UINTN **Buffer)
{
    (void)SearchType; (void)Key;
    if (!Count || !Buffer) return EFI_INVALID_PARAMETER;
    CollectHandlesFor(Protocol, Buffer, Count);
    return 0;
}

static UINTN OP_LocateDevicePath2(UINT8 *Protocol, void **DevicePath, UINTN *Device)
{
    (void)Protocol; (void)DevicePath;
    if (Device) *Device = 0xAAAA0000;
    return 0;
}

static UINTN BS_ConnectController(UINTN h, void *Did, void *LastDid, char Rec)
{ (void)h;(void)Did;(void)LastDid;(void)Rec; return EFI_NOT_FOUND; }
static UINTN BS_DisconnectController(UINTN h, void *D, void *C)
{ (void)h;(void)D;(void)C; return EFI_NOT_FOUND; }

static UINTN BS_GetNextMonotonicCount(UINT64 *Count)
{
    static UINT64 mc = 0;
    if (!Count) return EFI_INVALID_PARAMETER;
    *Count = ++mc;
    return 0;
}

static UINT32 crc32_tab_built;
static UINT32 crc32_tab[256];
static void BuildCrc32(void)
{
    for (UINT32 i = 0; i < 256; i++) {
        UINT32 c = i;
        for (int k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        crc32_tab[i] = c;
    }
    crc32_tab_built = 1;
}
static UINTN BS_CalculateCrc32(void *Data, UINTN Size, UINT32 *Crc)
{
    if (!crc32_tab_built) BuildCrc32();
    if (!Crc) return EFI_INVALID_PARAMETER;
    UINT32 c = 0xFFFFFFFFu;
    UINT8 *p = (UINT8 *)Data;
    for (UINTN i = 0; i < Size; i++) c = crc32_tab[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    *Crc = c ^ 0xFFFFFFFFu;
    return 0;
}

// ---------------- events ----------------

static void *conInWaitKey;   // WaitForKey event for our ConIn

#define EVT_TIMER 0x80000000ULL

typedef struct {
    int     used;
    UINTN   type;
    UINTN (*notify)(void *, void *);
    void   *ctx;
    int     signaled;
    UINT64  deadline;      // in 100ns units, 0 = none
    UINT64  period;
} EFI_EVENT_OBJ;

static EFI_EVENT_OBJ g_events[64];

static UINTN BS_CreateEvent(UINTN Type, UINTN NotifyTpl, UINTN (*Fn)(void *, void *),
                            void *Ctx, void **Event)
{
    (void)NotifyTpl;
    if (!Event) return EFI_INVALID_PARAMETER;
    for (UINTN i = 0; i < 64; i++) {
        if (g_events[i].used) continue;
        memset(&g_events[i], 0, sizeof(g_events[i]));
        g_events[i].used = 1;
        g_events[i].type = Type;
        g_events[i].notify = Fn;
        g_events[i].ctx = Ctx;
        *Event = &g_events[i];
        return 0;
    }
    return EFI_OUT_OF_RESOURCES;
}

static UINTN BS_CloseEvent(void *Event)
{
    if (Event) ((EFI_EVENT_OBJ *)Event)->used = 0;
    return 0;
}

static UINTN BS_SignalEvent(void *Event)
{
    EFI_EVENT_OBJ *e = (EFI_EVENT_OBJ *)Event;
    if (!e) return EFI_INVALID_PARAMETER;
    e->signaled = 1;
    if (e->notify) e->notify(e->ctx, 0);
    return 0;
}

static int EventReady(EFI_EVENT_OBJ *e)
{
    if (!e || !e->used) return 0;
    if (e->deadline && GetTickCount64() * 10000ULL >= e->deadline) {
        if (e->notify) e->notify(e->ctx, 0);
        e->deadline = e->period ? GetTickCount64() * 10000ULL + e->period : 0;
        e->signaled = 1;
    }
    return e->signaled;
}

static UINTN BS_CheckEvent(void *Event)
{
    return EventReady((EFI_EVENT_OBJ *)Event) ? 0 : EFI_NOT_READY;
}

static UINTN BS_WaitForEvent(UINTN Count, void **Events, UINTN *Index)
{
    if (!Count || !Events || !Index) return EFI_INVALID_PARAMETER;
    {
        void *ret = _ReturnAddress();
        long long rva = (long long)((UINT8 *)ret - g_imageBase);
        LOGV(3, "[efihost] WaitForEvent(count=%llu) from RVA 0x%llx (15s watchdog)\n",
                (unsigned long long)Count, (unsigned long long)rva);
    }
    UINT64 start = GetTickCount64();
    while (1) {
        for (UINTN i = 0; i < Count; i++) {
            EFI_EVENT_OBJ *e = (EFI_EVENT_OBJ *)Events[i];
            // WaitForKey: fires when a keystroke is pending (does NOT consume it)
            if (e == (EFI_EVENT_OBJ *)conInWaitKey && KeyAvailable()) {
                if (Index) *Index = i;
                return 0;
            }
            if (EventReady(e)) { *Index = i; return 0; }
        }
        if (GetTickCount64() - start > 15000) {   // 15s watchdog: pretend event 0 fired
            LOGV(3, "[efihost] WaitForEvent: watchdog fired, faking index 0\n");
            if (Index) *Index = 0;
            return 0;
        }
        Sleep(10);
    }
}

static UINTN BS_SetTimer(void *Event, UINTN Type, UINT64 TriggerTime)
{
    EFI_EVENT_OBJ *e = (EFI_EVENT_OBJ *)Event;
    if (!e) return EFI_INVALID_PARAMETER;
    if (Type == 0) { e->deadline = 0; e->period = 0; return 0; }  // cancel
    UINT64 now = GetTickCount64() * 10000ULL;
    if (Type == 1) { e->period = TriggerTime; e->deadline = now + TriggerTime; }  // periodic
    else           { e->period = 0; e->deadline = now + TriggerTime; }            // relative
    return 0;
}

// ---------------- runtime services: time & variables ----------------

static UINTN RT_GetTime(void *Time, void *Caps)
{
    g_cntGetTime++;
    (void)Caps;
    if (!Time) return EFI_INVALID_PARAMETER;
    SYSTEMTIME t;
    GetLocalTime(&t);
    UINT8 *p = (UINT8 *)Time;
    UINT16 y = (UINT16)t.wYear;
    memcpy(p, &y, 2);
    p[2] = (UINT8)t.wMonth;
    p[3] = (UINT8)t.wDay;
    p[4] = (UINT8)t.wHour;
    p[5] = (UINT8)t.wMinute;
    p[6] = (UINT8)t.wSecond;
    p[7] = 0;
    UINT32 ns = (UINT32)(GetTickCount64() % 1000) * 1000000u;
    memcpy(p + 8, &ns, 4);
    return 0;
}
static UINTN RT_SetTime(void *Time) { (void)Time; return EFI_UNSUPPORTED; }

typedef struct { char name[128]; UINT8 guid[16]; UINT32 attr; UINT8 *data; UINTN size; } VARSTORE;
static VARSTORE g_vars[256];

static void VarsLoad(void);
static void VarsSave(void);

static UINTN RT_GetVariable(CHAR16 *Name, UINT8 *Guid, UINT32 *Attr, UINTN *Size, void *Data)
{
    if (!Name || !Guid) return EFI_INVALID_PARAMETER;
    char n[128]; U16ToAscii(Name, n, sizeof(n));
    LOGV(2, "[efihost] GetVar('%s' inSize=%llu)\n", n, (unsigned long long)(Size ? *Size : 0));
    if (!n[0]) return EFI_NOT_FOUND;
    for (UINTN i = 0; i < 256; i++) {
        if (!g_vars[i].name[0]) continue;
        if (stricmp(g_vars[i].name, n) != 0) continue;
        if (memcmp(g_vars[i].guid, Guid, 16) != 0) continue;
        if (Attr) *Attr = g_vars[i].attr;
        if (!Size) return EFI_INVALID_PARAMETER;
        if (!Data || *Size < g_vars[i].size) { *Size = g_vars[i].size; return EFI_BUFFER_TOO_SMALL; }
        memcpy(Data, g_vars[i].data, g_vars[i].size);
        *Size = g_vars[i].size;
        return 0;
    }
    return EFI_NOT_FOUND;
}

static UINTN RT_GetNextVariableName(UINTN *Size, CHAR16 *Name, UINT8 *Guid)
{
    if (!Size || !Name || !Guid) return EFI_INVALID_PARAMETER;
    char cur[128]; U16ToAscii(Name, cur, sizeof(cur));
    UINTN start = 0;
    if (cur[0]) {
        int found = 0;
        for (UINTN i = 0; i < 256; i++)
            if (g_vars[i].name[0] && stricmp(g_vars[i].name, cur) == 0 &&
                memcmp(g_vars[i].guid, Guid, 16) == 0) { start = i + 1; found = 1; break; }
        if (!found) return EFI_NOT_FOUND;
    }
    for (UINTN i = start; i < 256; i++) {
        if (!g_vars[i].name[0]) continue;
        if (memcmp(g_vars[i].guid, Guid, 16) != 0) continue;
        UINTN need = (AsciiToU16(g_vars[i].name, Name, 128) + 1) * 2;
        if (*Size < need) { *Size = need; return EFI_BUFFER_TOO_SMALL; }
        *Size = need;
        return 0;
    }
    return EFI_NOT_FOUND;
}

static UINTN RT_SetVariableImpl(CHAR16 *Name, UINT8 *Guid, UINT32 Attr, UINTN Size, void *Data)
{
    if (!Name || !Guid) return EFI_INVALID_PARAMETER;
    char n[128]; U16ToAscii(Name, n, sizeof(n));
    if (!n[0]) return EFI_INVALID_PARAMETER;
    for (UINTN i = 0; i < 256; i++) {
        if (!g_vars[i].name[0]) continue;
        if (stricmp(g_vars[i].name, n) || memcmp(g_vars[i].guid, Guid, 16)) continue;
        free(g_vars[i].data);
        if (Size == 0) { g_vars[i].name[0] = 0; VarsSave(); return 0; }  // delete
        g_vars[i].data = malloc(Size ? Size : 1);
        memcpy(g_vars[i].data, Data, Size);
        g_vars[i].size = Size;
        g_vars[i].attr = Attr;
        VarsSave();
        return 0;
    }
    if (Size == 0) return EFI_NOT_FOUND;   // delete non-existing
    for (UINTN i = 0; i < 256; i++) {
        if (g_vars[i].name[0]) continue;
        strcpy(g_vars[i].name, n);
        memcpy(g_vars[i].guid, Guid, 16);
        g_vars[i].attr = Attr;
        g_vars[i].data = malloc(Size ? Size : 1);
        memcpy(g_vars[i].data, Data, Size);
        g_vars[i].size = Size;
        VarsSave();
        return 0;
    }
    return EFI_OUT_OF_RESOURCES;
}

static UINTN RT_QueryVariableInfo(UINT32 Attr, UINT64 *MaxVar, UINT64 *Remaining, UINT64 *TotalSize)
{
    (void)Attr;
    if (MaxVar) *MaxVar = 0x10000;
    if (Remaining) *Remaining = 0xF000;
    if (TotalSize) *TotalSize = 0x1000;
    return 0;
}

static UINTN RT_ResetSystem(UINTN ResetType, UINTN Status, UINTN Size, void *Data)
{
    (void)Status; (void)Size; (void)Data;
    LOGV(1, "\n[efihost] RT->ResetSystem(type=%llu) called%s.\n",
         (unsigned long long)ResetType, g_exitValid ? " by a nested image - unwinding" : " - terminating");
    if (g_exitValid) {
        // an application ran ResetSystem(): return control to the Shell instead
        // of tearing the host down
        g_exitValid  = 0;
        g_exitStatus = 0;
        longjmp(g_exitJmp, 1);
    }
    GOP_Snapshot();
    ExitProcess(0);
    return 0;
}

static char g_varsPath[MAX_PATH];
static void VarsSave(void)
{
    FILE *f = fopen(g_varsPath, "wb");
    if (!f) return;
    UINT32 cnt = 0;
    for (UINTN i = 0; i < 256; i++) if (g_vars[i].name[0]) cnt++;
    fwrite(&cnt, 4, 1, f);
    for (UINTN i = 0; i < 256; i++) {
        if (!g_vars[i].name[0]) continue;
        fwrite(g_vars[i].name, 1, 128, f);
        fwrite(g_vars[i].guid, 1, 16, f);
        fwrite(&g_vars[i].attr, 4, 1, f);
        fwrite(&g_vars[i].size, 8, 1, f);
        fwrite(g_vars[i].data, 1, g_vars[i].size, f);
    }
    fclose(f);
}

static UINTN RT_SetVariable(CHAR16 *Name, UINT8 *Guid, UINT32 Attr, UINTN Size, void *Data)
{
    UINTN st = RT_SetVariableImpl(Name, Guid, Attr, Size, Data);
    if (Name && Name[0] == 'p' && Name[1] == 'a' && Name[2] == 't' && Name[3] == 'h' && Name[4] == 0)
        ReportCaller("SetVar(path)");
    if (LOGLV(2)) {
        char n[128]; n[0] = 0;
        if (Name) U16ToAscii(Name, n, sizeof(n));
        LOGV(2, "[efihost] SetVar('%s' size=%llu attr=0x%x) -> 0x%llx\n",
                n, (unsigned long long)Size, Attr, (unsigned long long)st);
    }
    return st;
}

// EFI_GLOBAL_VARIABLE: 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
static UINT8 GUID_GlobalVar[16] = { 0x61,0xDF,0xE4,0x8B, 0xCA,0x93, 0xD2,0x11,
                                    0xAA,0x0D,0x00,0xE0,0x98,0x03,0x2B,0x8C };

static void VarSetRaw(const char *name, const UINT8 *guid, const void *data, UINTN size)
{
    for (UINTN i = 0; i < 256; i++) {
        if (!g_vars[i].name[0]) continue;
        if (stricmp(g_vars[i].name, name) || memcmp(g_vars[i].guid, guid, 16)) continue;
        free(g_vars[i].data);
        g_vars[i].data = malloc(size ? size : 1);
        memcpy(g_vars[i].data, data, size);
        g_vars[i].size = size;
        return;
    }
    for (UINTN i = 0; i < 256; i++) {
        if (g_vars[i].name[0]) continue;
        strcpy(g_vars[i].name, name);
        memcpy(g_vars[i].guid, guid, 16);
        g_vars[i].attr = 0x7;                 // NV+BS+RT
        g_vars[i].data = malloc(size ? size : 1);
        memcpy(g_vars[i].data, data, size);
        g_vars[i].size = size;
        return;
    }
}

// firmware defaults a shell expects to find
static void VarsSeedDefaults(void)
{
    int haveLang = 0;
    for (UINTN i = 0; i < 256; i++)
        if (g_vars[i].name[0] && !stricmp(g_vars[i].name, "PlatformLang")) haveLang = 1;
    if (haveLang) return;
    VarSetRaw("PlatformLang",      GUID_GlobalVar, "en-US", 6);
    VarSetRaw("PlatformLangCodes", GUID_GlobalVar, "en-US", 6);
    VarSetRaw("Lang",              GUID_GlobalVar, "eng",   4);
    VarSetRaw("LangCodes",         GUID_GlobalVar, "eng",   4);
    UINT16 timeout = 0;
    VarSetRaw("Timeout",           GUID_GlobalVar, &timeout, 2);
    VarsSave();
}

static void VarsInit(const char *fsDir)
{
    (void)fsDir;
    // NVRAM is global, not part of any mapped volume.  Keep the backing file
    // next to the host executable so it never shows up in the guest's 'ls'
    // (and so a clean fsroot stays clean, which calcium.efi requires).
    char exe[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, exe, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        char *slash = strrchr(exe, '\\');
        if (slash) slash[1] = 0;
        else exe[0] = 0;
        _snprintf(g_varsPath, sizeof(g_varsPath), "%sefivars.bin", exe);
    } else {
        _snprintf(g_varsPath, sizeof(g_varsPath), "efivars.bin");
    }
    VarsLoad();
}

static void VarsLoad(void)
{
    FILE *f = fopen(g_varsPath, "rb");
    if (!f) { VarsSeedDefaults(); return; }
    UINT32 cnt = 0;
    if (fread(&cnt, 4, 1, f) != 1) { fclose(f); return; }
    for (UINT32 k = 0; k < cnt; k++) {
        VARSTORE v; memset(&v, 0, sizeof(v));
        if (fread(v.name, 1, 128, f) != 128) break;
        if (fread(v.guid, 1, 16, f) != 16) break;
        if (fread(&v.attr, 4, 1, f) != 1) break;
        if (fread(&v.size, 8, 1, f) != 1) break;
        v.data = malloc(v.size ? v.size : 1);
        if (fread(v.data, 1, v.size, f) != v.size) { free(v.data); break; }
        for (UINTN i = 0; i < 256; i++)
            if (!g_vars[i].name[0]) { g_vars[i] = v; break; }
    }
    fclose(f);
}

// ------------------------------------------------------------ graphics output
//
// EFI_GRAPHICS_OUTPUT_PROTOCOL over a memory-backed linear framebuffer.
//
// Real firmware returns a *physical* address in Mode->FrameBufferBase.  In user
// mode nothing translates that address: guest code just dereferences the value.
// So handing out the virtual address of our VirtualAlloc block works for every
// program that writes pixels directly (which is what nearly all GOP apps do).
// Only code that feeds FrameBufferBase into page tables (bootmgr) notices the
// difference - and it is already doomed for other reasons.
//
// Pixel layout is PixelBlueGreenRedReserved8BitPerColor, i.e. bytes B,G,R,X,
// which matches EFI_GRAPHICS_OUTPUT_BLT_PIXEL bit-for-bit, so Blt needs no
// channel swizzling.

// 9042A9DE-23DC-4A38-96FB-7ADED080516A
static UINT8 GUID_GraphicsOutput[16] = { 0xDE,0xA9,0x42,0x90, 0xDC,0x23, 0x38,0x4A,
                                        0x96,0xFB,0x7A,0xDE,0xD0,0x80,0x51,0x6A };

typedef struct {
    UINT32 Version;
    UINT32 HorizontalResolution;
    UINT32 VerticalResolution;
    UINT32 PixelFormat;
    UINT32 RedMask;
    UINT32 GreenMask;
    UINT32 BlueMask;
    UINT32 ReservedMask;
    UINT32 PixelsPerScanLine;
} GOP_MODE_INFO;

typedef struct {
    UINT32        MaxMode;
    UINT32        Mode;
    GOP_MODE_INFO *Info;
    UINTN         SizeOfInfo;
    UINT64        FrameBufferBase;
    UINTN         FrameBufferSize;
} GOP_MODE;

typedef struct {
    UINTN     QueryMode;      // (This, ModeNumber, SizeOfInfo, Info)
    UINTN     SetMode;        // (This, ModeNumber)
    UINTN     Blt;            // (This, Buffer, Op, SrcX, SrcY, DstX, DstY, W, H, Delta)
    GOP_MODE *Mode;
} GOP_PROTO;

typedef struct { UINT32 w, h; } GOP_MODE_DESC;

static const GOP_MODE_DESC g_gopModes[] = {
    {  640,  480 }, {  800,  600 }, { 1024,  768 }, { 1280,  720 },
    { 1280, 1024 }, { 1440,  900 }, { 1600,  900 }, { 1920, 1080 }
};
#define GOP_NMODES (sizeof(g_gopModes) / sizeof(g_gopModes[0]))
#define GOP_MAXW   1920
#define GOP_MAXH   1080

static UINT8      *g_gopFb;                    // BGRX, pitch = width * 4
static UINT32      g_gopCur;                   // active mode index
static GOP_MODE_INFO g_gopInfo[GOP_NMODES];
static GOP_MODE      g_gopMode;
static GOP_PROTO     g_gopProto;
static char          g_gopBmpPath[MAX_PATH];

// EfiBltVideoFill / VideoToBltBuffer / BufferToVideo / VideoToVideo
#define GOP_BLT_FILL   0
#define GOP_BLT_V2B    1
#define GOP_BLT_B2V    2
#define GOP_BLT_V2V    3

static UINTN GOP_FillModeInfo(UINT32 idx)
{
    GOP_MODE_INFO *in = &g_gopInfo[idx];
    memset(in, 0, sizeof(*in));
    in->Version              = 0;                       // v1 layout
    in->HorizontalResolution = g_gopModes[idx].w;
    in->VerticalResolution   = g_gopModes[idx].h;
    in->PixelFormat          = 1;                       // BlueGreenRedReserved8BitPerColor
    in->PixelsPerScanLine    = g_gopModes[idx].w;
    return sizeof(GOP_MODE_INFO);
}

static void GOP_ApplyMode(UINT32 idx)
{
    g_gopCur          = idx;
    g_gopMode.Mode    = idx;
    g_gopMode.Info    = &g_gopInfo[idx];
    g_gopMode.SizeOfInfo     = sizeof(GOP_MODE_INFO);
    g_gopMode.FrameBufferBase = (UINT64)(UINTN)g_gopFb;
    g_gopMode.FrameBufferSize = (UINTN)g_gopModes[idx].w * g_gopModes[idx].h * 4;

    // firmware leaves the screen undefined after SetMode; a black frame keeps
    // half-initialised output from looking like a rendering bug
    memset(g_gopFb, 0, (UINTN)GOP_MAXW * GOP_MAXH * 4);
}

static void GOP_Snapshot(void)
{
    if (!g_gopBmpPath[0] || !g_gopFb) return;

    UINT32 W = g_gopModes[g_gopCur].w;
    UINT32 H = g_gopModes[g_gopCur].h;
    UINTN  rowBytes = ((UINTN)W * 3 + 3) & ~(UINTN)3;
    UINTN  dataSize = rowBytes * H;

    UINT8 *d = (UINT8 *)calloc(1, 54 + dataSize);
    if (!d) return;

    d[0] = 'B'; d[1] = 'M';
    *(UINT32 *)(d +  2) = (UINT32)(54 + dataSize);
    *(UINT32 *)(d + 10) = 54;                    // pixel data offset
    *(UINT32 *)(d + 14) = 40;                    // BITMAPINFOHEADER size
    *(INT32  *)(d + 18) = (INT32)W;
    *(INT32  *)(d + 22) = (INT32)H;
    *(UINT16 *)(d + 26) = 1;                     // planes
    *(UINT16 *)(d + 28) = 24;                    // bits per pixel
    *(UINT32 *)(d + 34) = (UINT32)dataSize;

    // BMP stores rows bottom-up
    for (UINT32 y = 0; y < H; y++) {
        const UINT8 *src = g_gopFb + (UINTN)(H - 1 - y) * (UINTN)W * 4;
        UINT8       *dst = d + 54 + (UINTN)y * rowBytes;
        for (UINT32 x = 0; x < W; x++) {
            dst[x * 3 + 0] = src[x * 4 + 0];
            dst[x * 3 + 1] = src[x * 4 + 1];
            dst[x * 3 + 2] = src[x * 4 + 2];
        }
    }

    FILE *f = fopen(g_gopBmpPath, "wb");
    if (f) {
        fwrite(d, 1, 54 + dataSize, f);
        fclose(f);
        LOGV(1, "[efihost] GOP: frame dumped -> %s (%ux%u)\n", g_gopBmpPath, W, H);
    }
    free(d);
}

static UINTN GOP_QueryMode(void *This, UINT32 ModeNumber, UINTN *SizeOfInfo, GOP_MODE_INFO **Info)
{
    (void)This;
    if (!SizeOfInfo || !Info) return EFI_INVALID_PARAMETER;
    if (ModeNumber >= GOP_NMODES) return EFI_UNSUPPORTED;
    *SizeOfInfo = sizeof(GOP_MODE_INFO);
    *Info       = &g_gopInfo[ModeNumber];   // static: FreePool() on it is a no-op here
    LOGV(3, "[efihost] GOP: QueryMode(%u) -> %ux%u\n", ModeNumber,
         g_gopModes[ModeNumber].w, g_gopModes[ModeNumber].h);
    return 0;
}

static UINTN GOP_SetMode(void *This, UINT32 ModeNumber)
{
    (void)This;
    if (!g_gopFb) return EFI_NOT_READY;
    if (ModeNumber >= GOP_NMODES) return EFI_UNSUPPORTED;
    if (ModeNumber != g_gopCur) GOP_ApplyMode(ModeNumber);
    LOGV(1, "[efihost] GOP: SetMode(%u) -> %ux%u, fb=%p (%llu bytes)\n",
         ModeNumber, g_gopModes[ModeNumber].w, g_gopModes[ModeNumber].h,
         (void *)(UINTN)g_gopMode.FrameBufferBase,
         (unsigned long long)g_gopMode.FrameBufferSize);
    return 0;
}

static UINTN GOP_Blt(void *This, UINT32 *Buf, UINTN Op,
                     UINTN SrcX, UINTN SrcY, UINTN DstX, UINTN DstY,
                     UINTN W, UINTN H, UINTN Delta)
{
    (void)This;
    if (!g_gopFb) return EFI_NOT_READY;
    if (Op > GOP_BLT_V2V) return EFI_INVALID_PARAMETER;
    if ((Op == GOP_BLT_B2V || Op == GOP_BLT_V2B) && !Buf) return EFI_INVALID_PARAMETER;

    UINTN SW = g_gopModes[g_gopCur].w;
    UINTN SH = g_gopModes[g_gopCur].h;

    // Delta is the byte pitch of the caller's BltBuffer.  Some callers pass a
    // pixel pitch instead; both shapes show up in the wild.
    UINTN pitch = W;
    if (Delta) pitch = (Delta % 4 == 0 && Delta >= W * 4) ? Delta / 4 : Delta;

    UINTN dw = W, dh = H;
    if (DstX >= SW || DstY >= SH) return 0;
    if (dw > SW - DstX) dw = SW - DstX;
    if (dh > SH - DstY) dh = SH - DstY;
    if (Op == GOP_BLT_V2B || Op == GOP_BLT_V2V) {
        if (SrcX >= SW || SrcY >= SH) return 0;
        if (dw > SW - SrcX) dw = SW - SrcX;
        if (dh > SH - SrcY) dh = SH - SrcY;
    }
    if (!dw || !dh) return 0;

    UINT32 *fb = (UINT32 *)g_gopFb;

    switch (Op) {
    case GOP_BLT_FILL: {
        UINT32 c = Buf[0];
        for (UINTN y = 0; y < dh; y++) {
            UINT32 *row = fb + (DstY + y) * SW + DstX;
            for (UINTN x = 0; x < dw; x++) row[x] = c;
        }
        break;
    }
    case GOP_BLT_B2V: {
        for (UINTN y = 0; y < dh; y++) {
            UINT32       *row = fb + (DstY + y) * SW + DstX;
            const UINT32 *src = Buf + (SrcY + y) * pitch + SrcX;
            memcpy(row, src, dw * 4);
        }
        break;
    }
    case GOP_BLT_V2B: {
        for (UINTN y = 0; y < dh; y++) {
            const UINT32 *row = fb + (SrcY + y) * SW + SrcX;
            UINT32       *dst = Buf + (DstY + y) * pitch + DstX;
            memcpy(dst, row, dw * 4);
        }
        break;
    }
    case GOP_BLT_V2V: {
        // rows may overlap: walk in the direction that keeps the copy honest
        int down = (DstY > SrcY) || (DstY == SrcY && DstX > SrcX);
        for (UINTN i = 0; i < dh; i++) {
            UINTN y = down ? (dh - 1 - i) : i;
            UINT32       *dst = fb + (DstY + y) * SW + DstX;
            const UINT32 *src = fb + (SrcY + y) * SW + SrcX;
            memmove(dst, src, dw * 4);
        }
        break;
    }
    }

    LOGV(3, "[efihost] GOP: Blt(op=%llu src=%llu,%llu dst=%llu,%llu %llux%llu delta=%llu)\n",
         (unsigned long long)Op, (unsigned long long)SrcX, (unsigned long long)SrcY,
         (unsigned long long)DstX, (unsigned long long)DstY,
         (unsigned long long)W, (unsigned long long)H, (unsigned long long)Delta);
    return 0;
}

static void GOP_Init(void)
{
    g_gopFb = (UINT8 *)VirtualAlloc(NULL, (SIZE_T)GOP_MAXW * GOP_MAXH * 4,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_gopFb) {
        LOGV(0, "[efihost] GOP: framebuffer allocation failed\n");
        return;
    }
    for (UINT32 i = 0; i < GOP_NMODES; i++) GOP_FillModeInfo(i);

    g_gopMode.MaxMode    = (UINT32)GOP_NMODES;
    g_gopProto.QueryMode = (UINTN)GOP_QueryMode;
    g_gopProto.SetMode   = (UINTN)GOP_SetMode;
    g_gopProto.Blt       = (UINTN)GOP_Blt;
    g_gopProto.Mode      = &g_gopMode;

    // start in 1024x768 like most firmware does with OVMF
    GOP_ApplyMode(2);

    const char *p = getenv("EFHOST_GOP_BMP");
    if (p && *p) {
        strncpy(g_gopBmpPath, p, sizeof(g_gopBmpPath) - 1);
        LOGV(1, "[efihost] GOP: snapshot path '%s'\n", g_gopBmpPath);
    }
    LOGV(1, "[efihost] GOP: %u modes, active %ux%u, fb=%p\n",
         (unsigned)GOP_NMODES, g_gopModes[g_gopCur].w, g_gopModes[g_gopCur].h, (void *)g_gopFb);
}

// ---------------- HII: database + string ----------------

typedef struct { int used; UINTN handle; UINT8 *data; UINTN size; } HIIPKG;
static HIIPKG g_hiiPkg[32];
static UINTN g_hiiNext = 1;

static UINTN HD_NewPackageList(void *This, void *PackageList, UINTN DriverHandle, UINTN *Handle)
{
    (void)This; (void)DriverHandle;
    if (!PackageList || !Handle) return EFI_INVALID_PARAMETER;
    UINT32 total = *(UINT32 *)((UINT8 *)PackageList + 16);
    for (UINTN i = 0; i < 32; i++) {
        if (g_hiiPkg[i].used) continue;
        g_hiiPkg[i].used = 1;
        g_hiiPkg[i].handle = ++g_hiiNext;
        g_hiiPkg[i].size = total;
        g_hiiPkg[i].data = malloc(total);
        memcpy(g_hiiPkg[i].data, PackageList, total);
        if (getenv("EFHOST_DUMPHII")) {
            char fn[64];
            _snprintf(fn, sizeof(fn), "hii_%u.bin", (unsigned)g_hiiPkg[i].handle);
            FILE *f = fopen(fn, "wb");
            if (f) { fwrite(PackageList, 1, total, f); fclose(f); }
        }
        *Handle = g_hiiPkg[i].handle;
        return 0;
    }
    return EFI_OUT_OF_RESOURCES;
}

static UINTN HD_RemovePackageList(void *This, UINTN Handle)
{
    (void)This;
    for (UINTN i = 0; i < 32; i++)
        if (g_hiiPkg[i].used && g_hiiPkg[i].handle == Handle) {
            free(g_hiiPkg[i].data);
            g_hiiPkg[i].used = 0;
            return 0;
        }
    return EFI_NOT_FOUND;
}

static UINTN HD_UpdatePackageList(void *This, UINTN Handle, void *PackageList)
{
    (void)This;
    UINT32 total = *(UINT32 *)((UINT8 *)PackageList + 16);
    for (UINTN i = 0; i < 32; i++) {
        if (!g_hiiPkg[i].used || g_hiiPkg[i].handle != Handle) continue;
        UINT8 *nd = realloc(g_hiiPkg[i].data, g_hiiPkg[i].size + total);
        if (!nd) return EFI_OUT_OF_RESOURCES;
        g_hiiPkg[i].data = nd;
        memcpy(g_hiiPkg[i].data + g_hiiPkg[i].size, PackageList, total);
        g_hiiPkg[i].size += total;
        return 0;
    }
    return EFI_NOT_FOUND;
}

static UINTN HD_ListPackages(void *This, UINTN *Size, UINTN *Handle)
{
    (void)This;
    if (!Size) return EFI_INVALID_PARAMETER;
    UINTN need = 0;
    for (UINTN i = 0; i < 32; i++) if (g_hiiPkg[i].used) need += sizeof(UINTN);
    if (*Size < need) { *Size = need; return EFI_BUFFER_TOO_SMALL; }
    UINTN n = 0;
    for (UINTN i = 0; i < 32; i++) if (g_hiiPkg[i].used) Handle[n++] = g_hiiPkg[i].handle;
    *Size = need;
    return 0;
}

static UINTN HD_ExportPackages(void *This, UINTN Handle, UINTN *Size, void *Buffer)
{
    (void)This;
    UINTN need = 0;
    for (UINTN i = 0; i < 32; i++)
        if (g_hiiPkg[i].used && (!Handle || g_hiiPkg[i].handle == Handle)) need += g_hiiPkg[i].size;
    if (!Size) return EFI_INVALID_PARAMETER;
    if (*Size < need) { *Size = need; return EFI_BUFFER_TOO_SMALL; }
    UINTN off = 0;
    for (UINTN i = 0; i < 32; i++) {
        if (!g_hiiPkg[i].used || (Handle && g_hiiPkg[i].handle != Handle)) continue;
        memcpy((UINT8 *)Buffer + off, g_hiiPkg[i].data, g_hiiPkg[i].size);
        off += g_hiiPkg[i].size;
    }
    *Size = need;
    return 0;
}

static UINTN HD_GetPackHandle(void *This, UINTN PackageListHandle, UINTN *DriverHandle)
{
    (void)This;
    for (UINTN i = 0; i < 32; i++)
        if (g_hiiPkg[i].used && g_hiiPkg[i].handle == PackageListHandle) {
            if (DriverHandle) *DriverHandle = 0;
            return 0;
        }
    return EFI_NOT_FOUND;
}

static UINTN HD_RegisterNotify(void *This, UINT8 Type, UINTN Fn, void *Ctx) { (void)This;(void)Type;(void)Fn;(void)Ctx; return 0; }
static UINTN HD_UnregisterNotify(void *This, UINTN Notification) { (void)This;(void)Notification; return 0; }
static UINTN HD_SetKeyboardLayout(void *This, void *Layout) { (void)This;(void)Layout; return 0; }

static struct {
    UINTN NewPackageList, RemovePackageList, UpdatePackageList, ListPackages,
          ExportPackages, GetPackHandle, RegisterNotify, UnregisterNotify, SetKeyboardLayout;
    UINTN _pad[23];   // stub padding: out-of-range offsets -> UNSUPPORTED
} g_HiiDatabase = {
    (UINTN)HD_NewPackageList, (UINTN)HD_RemovePackageList, (UINTN)HD_UpdatePackageList,
    (UINTN)HD_ListPackages, (UINTN)HD_ExportPackages, (UINTN)HD_GetPackHandle,
    (UINTN)HD_RegisterNotify, (UINTN)HD_UnregisterNotify, (UINTN)HD_SetKeyboardLayout
};

// string packages: parse SIBT blocks
static UINT8 *HiiFindStringPkg(UINTN hiiHandle, UINTN *pkgLen)
{
    for (UINTN i = 0; i < 32; i++) {
        if (!g_hiiPkg[i].used || g_hiiPkg[i].handle != hiiHandle) continue;
        UINT8 *d = g_hiiPkg[i].data;
        UINT32 total = *(UINT32 *)(d + 16);
        UINTN off = 20;
        while (off + 4 <= 20 + total - 4) {
            UINT32 ptype = *(UINT32 *)(d + off);
            UINT32 plen = ptype & 0xFFFFFF;
            UINT8  ptyp = (UINT8)(ptype >> 24);
            if (plen < 4) break;
            if (ptyp == 4) { *pkgLen = plen; return d + off; }   // EFI_HII_PACKAGE_STRINGS
            off += plen;
        }
    }
    return NULL;
}

// ---- HII string-block decoding (UEFI spec 2.x, UefiInternalFormRepresentation.h) ----
#define SIBT_END               0x00
#define SIBT_STRING_SCSU       0x10
#define SIBT_STRING_SCSU_FONT  0x11
#define SIBT_STRINGS_SCSU      0x12
#define SIBT_STRINGS_SCSU_FONT 0x13
#define SIBT_STRING_UCS2       0x14
#define SIBT_STRING_UCS2_FONT  0x15
#define SIBT_STRINGS_UCS2      0x16
#define SIBT_STRINGS_UCS2_FONT 0x17
#define SIBT_DUPLICATE         0x20
#define SIBT_SKIP2             0x21
#define SIBT_SKIP1             0x22
#define SIBT_EXT1              0x30
#define SIBT_EXT2              0x31
#define SIBT_EXT4              0x32
#define SIBT_FONT              0x40

typedef struct { UINT16 id; UINT8 bt; UINT8 *p; } SIBENT;
static SIBENT g_sib[8192];
static UINTN  g_sibCount;

static void SibAdd(UINT16 id, UINT8 bt, UINT8 *p)
{
    if (g_sibCount < 8192) {
        g_sib[g_sibCount].id = id; g_sib[g_sibCount].bt = bt; g_sib[g_sibCount].p = p;
        g_sibCount++;
    }
}

// Walk the string-info stream and index every string id. Ids start at 1 and are
// assigned in block order: every string (or DUPLICATE) consumes one id, SKIP
// advances the counter without producing a string.
static void SibBuild(UINT8 *pkg, UINTN pkgLen)
{
    g_sibCount = 0;
    if (pkgLen < 12) return;
    UINT32 infoOff = *(UINT32 *)(pkg + 8);
    UINT8 *p   = pkg + infoOff;
    UINT8 *end = pkg + pkgLen;
    UINT16 id  = 1;
    while (p < end) {
        UINT8 bt = p[0];
        if (bt == SIBT_END) break;
        switch (bt) {
        case SIBT_STRING_SCSU: {                  // 1 + nul-terminated SCSU string
            SibAdd(id++, SIBT_STRING_SCSU, p);
            p += 1 + strlen((char *)p + 1) + 1;
            break;
        }
        case SIBT_STRING_UCS2: {                  // 1 + nul-terminated CHAR16 string
            SibAdd(id++, SIBT_STRING_UCS2, p);
            CHAR16 *t = (CHAR16 *)(p + 1);
            UINTN L = 0;
            while (((UINT8 *)t + (L + 1) * 2) <= end && t[L]) L++;
            p += 1 + (L + 1) * 2;
            break;
        }
        case SIBT_DUPLICATE: {                    // 1 + UINT16 reference to another id
            SibAdd(id++, SIBT_DUPLICATE, p);
            p += 3;
            break;
        }
        case SIBT_STRING_SCSU_FONT: {             // 1 + font(1) + SCSU string
            SibAdd(id++, SIBT_STRING_SCSU, p + 1);
            p += 2 + strlen((char *)p + 2) + 1;
            break;
        }
        case SIBT_STRING_UCS2_FONT: {             // 1 + font(1) + CHAR16 string
            SibAdd(id++, SIBT_STRING_UCS2, p + 1);
            CHAR16 *t = (CHAR16 *)(p + 2);
            UINTN L = 0;
            while (((UINT8 *)t + (L + 1) * 2) <= end && t[L]) L++;
            p += 2 + (L + 1) * 2;
            break;
        }
        case SIBT_STRINGS_SCSU: {                 // 1 + count(2) + SCSU strings
            UINT16 cnt = (UINT16)(p[1] | (p[2] << 8));
            UINT8 *q = p + 3;
            for (UINT16 c = 0; c < cnt && q < end; c++) {
                SibAdd(id++, SIBT_STRING_SCSU, q - 1);
                q += strlen((char *)q) + 1;
            }
            p = q;
            break;
        }
        case SIBT_STRINGS_UCS2: {                 // 1 + count(2) + CHAR16 strings
            UINT16 cnt = (UINT16)(p[1] | (p[2] << 8));
            UINT8 *q = p + 3;
            for (UINT16 c = 0; c < cnt && q < end; c++) {
                SibAdd(id++, SIBT_STRING_UCS2, q - 1);
                CHAR16 *t = (CHAR16 *)q;
                UINTN L = 0;
                while (((UINT8 *)t + (L + 1) * 2) <= end && t[L]) L++;
                q += (L + 1) * 2;
            }
            p = q;
            break;
        }
        case SIBT_STRINGS_SCSU_FONT: {            // 1 + font(1) + count(2) + strings
            UINT16 cnt = (UINT16)(p[2] | (p[3] << 8));
            UINT8 *q = p + 4;
            for (UINT16 c = 0; c < cnt && q < end; c++) {
                SibAdd(id++, SIBT_STRING_SCSU, q - 1);
                q += strlen((char *)q) + 1;
            }
            p = q;
            break;
        }
        case SIBT_STRINGS_UCS2_FONT: {            // 1 + font(1) + count(2) + strings
            UINT16 cnt = (UINT16)(p[2] | (p[3] << 8));
            UINT8 *q = p + 4;
            for (UINT16 c = 0; c < cnt && q < end; c++) {
                SibAdd(id++, SIBT_STRING_UCS2, q - 1);
                CHAR16 *t = (CHAR16 *)q;
                UINTN L = 0;
                while (((UINT8 *)t + (L + 1) * 2) <= end && t[L]) L++;
                q += (L + 1) * 2;
            }
            p = q;
            break;
        }
        case SIBT_SKIP2:                          // 1 + UINT16 skip count
            id = (UINT16)(id + (p[1] | (p[2] << 8))); p += 3; break;
        case SIBT_SKIP1:                          // 1 + UINT8 skip count
            id = (UINT16)(id + p[1]); p += 2; break;
        case SIBT_EXT1:
            if (p + 3 > end) return; p += 3 + p[2]; break;
        case SIBT_EXT2:
            if (p + 4 > end) return; p += 4 + (UINT32)(p[2] | (p[3] << 8)); break;
        case SIBT_EXT4:
            if (p + 6 > end) return; p += 6 + *(UINT32 *)(p + 2); break;
        default:
            // Unknown block (e.g. SIBT_FONT): we cannot guarantee a safe
            // advance, so stop indexing instead of running off the end.
            if (LOGLV(3))
                LOGV(3, "[efihost] HII: stop at block 0x%02x after %u ids\n",
                        bt, (unsigned)id);
            return;
        }
    }
}

static UINT8 *SibFind(UINT16 id, UINT8 *bt, int depth)
{
    for (UINTN i = 0; i < g_sibCount; i++) {
        if (g_sib[i].id != id) continue;
        if (g_sib[i].bt == SIBT_DUPLICATE) {
            if (depth > 8) return NULL;
            UINT16 ref = (UINT16)(g_sib[i].p[1] | (g_sib[i].p[2] << 8));
            return SibFind(ref, bt, depth + 1);
        }
        *bt = g_sib[i].bt;
        return g_sib[i].p;
    }
    return NULL;
}

// per-handle dynamic strings (NewString/SetString)
typedef struct { UINTN pkgHandle; UINT16 id; CHAR16 text[512]; } HIISTR;
static HIISTR g_hiiStr[256];

// EFI_HII_GET_STRING: OUT EFI_STRING String is the caller's buffer (NOT a CHAR16**).
static UINTN HS_GetStringImpl(void *This, char *Language, UINTN PackageList, UINTN StringId,
                              CHAR16 *String, UINTN *StringSize, void *StringInfo)
{
    (void)This; (void)Language; (void)StringInfo;
    if (!StringSize) return EFI_INVALID_PARAMETER;
    // dynamic overrides first
    for (UINTN i = 0; i < 256; i++)
        if (g_hiiStr[i].pkgHandle == PackageList && g_hiiStr[i].id == (UINT16)StringId) {
            UINTN need = (wcslen(g_hiiStr[i].text) + 1) * 2;
            if (!String || *StringSize < need) { *StringSize = need; return EFI_BUFFER_TOO_SMALL; }
            memcpy(String, g_hiiStr[i].text, need);
            *StringSize = need;
            return 0;
        }
    // --- decode the string package using the real SIBT_* block layout ---
    UINTN pkgLen = 0;
    UINT8 *pkg = HiiFindStringPkg(PackageList, &pkgLen);
    if (!pkg) return EFI_NOT_FOUND;
    SibBuild(pkg, pkgLen);
    UINT8 bt = 0;
    UINT8 *blk = SibFind((UINT16)StringId, &bt, 0);
    if (!blk) {
        if (LOGLV(3))
            LOGV(3, "[efihost] HII GetString: id %u not found (%u ids indexed)\n",
                    (unsigned)(UINT16)StringId, (unsigned)g_sibCount);
        return EFI_NOT_FOUND;
    }
    static CHAR16 conv[8192];
    CHAR16 *src = NULL;
    UINTN L = 0;
    UINT8 *pend = pkg + pkgLen;                // never read past the package
    if (bt == SIBT_STRING_UCS2) {
        src = (CHAR16 *)(blk + 1);
        while (L < 8191 && (UINT8 *)&src[L] + 2 <= pend && src[L]) L++;
        if (L >= 8191 || (UINT8 *)&src[L] + 2 > pend) L = 0;   // unterminated: drop it
    } else {                                   // SIBT_STRING_SCSU: treat bytes as latin-1
        char *a = (char *)(blk + 1);
        while (L < 8191 && (UINT8 *)&a[L] + 1 <= pend && a[L]) { conv[L] = (CHAR16)(unsigned char)a[L]; L++; }
        conv[L] = 0;
        src = conv;
    }
    UINTN need = (L + 1) * 2;
    if (LOGLV(3)) {
        LOGV(3, "[efihost] HII: pkg=%llu id=%u bt=0x%02x L=%llu '",
                (unsigned long long)PackageList, (unsigned)(UINT16)StringId,
                (unsigned)bt, (unsigned long long)L);
        for (UINTN z = 0; z < L && z < 48; z++)
            fputc((src[z] >= 32 && src[z] < 127) ? (int)src[z] : '?', stderr);
        LOGV(3, "'\n");
    }
    if (!String || *StringSize < need) { *StringSize = need; return EFI_BUFFER_TOO_SMALL; }
    memcpy(String, src, need);
    *StringSize = need;
    return 0;
}
// Fault-tolerant wrapper: a bad HII handle / unterminated string must not take
// the host process down (the app has no .pdata we can trust here).
static UINTN HS_GetString(void *This, char *Language, UINTN PackageList, UINTN StringId,
                          CHAR16 *String, UINTN *StringSize, void *StringInfo)
{
    UINTN rc;
    LOGV(3, "[efihost] HS_GetString(pkg=%llu id=%u inSize=%llu str=%p)\n",
            (unsigned long long)PackageList, (unsigned)(UINT16)StringId,
            (unsigned long long)(StringSize ? *StringSize : 0), (void *)String);
    __try {
        rc = HS_GetStringImpl(This, Language, PackageList, StringId, String, StringSize, StringInfo);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOGV(1, "[efihost] HII GetString: FAULT pkg=%llu id=%u (size=%llu) -> NOT_FOUND\n",
                (unsigned long long)PackageList, (unsigned)(UINT16)StringId,
                (unsigned long long)(StringSize ? *StringSize : 0));
        if (StringSize) *StringSize = 2;
        if (String && *StringSize >= 2) { String[0] = 0; }
        rc = EFI_NOT_FOUND;
    }
    return rc;
}

static UINTN HS_NewString(void *This, UINTN PackageList, UINTN *StringId, CHAR16 *Language,
                          CHAR16 *FontName, CHAR16 *StringText, void *StringInfo)
{
    (void)This; (void)Language; (void)FontName; (void)StringInfo;
    if (!StringId || !StringText) return EFI_INVALID_PARAMETER;
    for (UINTN i = 0; i < 256; i++) {
        if (g_hiiStr[i].pkgHandle) continue;
        g_hiiStr[i].pkgHandle = PackageList;
        UINT16 maxId = 0;
        for (UINTN j = 0; j < 256; j++)
            if (g_hiiStr[j].pkgHandle == PackageList && g_hiiStr[j].id > maxId) maxId = g_hiiStr[j].id;
        g_hiiStr[i].id = (UINT16)(maxId + 1);
        wcsncpy(g_hiiStr[i].text, StringText, 511);
        *StringId = g_hiiStr[i].id;
        return 0;
    }
    return EFI_OUT_OF_RESOURCES;
}

static UINTN HS_SetString(void *This, UINTN PackageList, UINTN StringId, CHAR16 *Language,
                          CHAR16 *StringText, void *StringInfo)
{
    (void)This; (void)Language; (void)StringInfo;
    for (UINTN i = 0; i < 256; i++)
        if (g_hiiStr[i].pkgHandle == PackageList && g_hiiStr[i].id == (UINT16)StringId) {
            wcsncpy(g_hiiStr[i].text, StringText ? StringText : (CHAR16 *)L"", 511);
            return 0;
        }
    for (UINTN i = 0; i < 256; i++)
        if (!g_hiiStr[i].pkgHandle) {
            g_hiiStr[i].pkgHandle = PackageList;
            g_hiiStr[i].id = (UINT16)StringId;
            wcsncpy(g_hiiStr[i].text, StringText ? StringText : (CHAR16 *)L"", 511);
            return 0;
        }
    return EFI_OUT_OF_RESOURCES;
}

// EFI_HII_GET_LANGUAGES: (This, PackageList, CHAR8 *Languages, UINTN *LanguagesSize)
// An earlier build had a bogus 5th 'Result' argument — the caller leaves r9 as
// an unrelated value (often a stack address), so writing through it corrupted
// the app's stack.  Languages is ASCII (CHAR8), not UCS2.
static UINTN HS_GetLanguages(void *This, UINTN PackageList, char *Languages, UINTN *Size)
{
    (void)This; (void)PackageList;
    UINTN need = 4;                       // "eng\0"
    if (!Size) return EFI_INVALID_PARAMETER;
    if (!Languages || *Size < need) { *Size = need; return EFI_BUFFER_TOO_SMALL; }
    Languages[0] = 'e'; Languages[1] = 'n'; Languages[2] = 'g'; Languages[3] = 0;
    *Size = need;
    return 0;
}

// EFI_HII_GET_SECONDARY_LANGUAGES:
// (This, PackageList, CHAR8 *First, CHAR8 *Sec, UINTN *SecSize)
static UINTN HS_GetSecondaryLanguages(void *This, UINTN PackageList, char *First,
                                      char *Sec, UINTN *Size)
{
    (void)This;(void)PackageList;(void)First;
    if (!Size) return EFI_INVALID_PARAMETER;
    if (Sec && *Size >= 1) Sec[0] = 0;    // no secondary languages
    *Size = 1;
    return 0;
}

static struct {
    UINTN NewString, GetString, SetString, GetLanguages, GetSecondaryLanguages;
    UINTN _pad[27];   // stub padding: out-of-range offsets -> UNSUPPORTED
} g_HiiString = {
    (UINTN)HS_NewString, (UINTN)HS_GetString, (UINTN)HS_SetString,
    (UINTN)HS_GetLanguages, (UINTN)HS_GetSecondaryLanguages
};

// HII Config Routing: stub protocol (6 functions)
static UINTN CR_ExtractConfig(void *This, CHAR16 *Req, CHAR16 **Progress, CHAR16 **Results)
{ (void)This;(void)Req; if(Progress)*Progress=(CHAR16*)L""; return EFI_INVALID_PARAMETER; }
static UINTN CR_ExportConfig(void *This, void *Tp, void *Cp, CHAR16 *Cfg, CHAR16 **Progress, CHAR16 **R)
{ (void)This;(void)Tp;(void)Cp;(void)Cfg;if(Progress)*Progress=(CHAR16*)L""; return EFI_UNSUPPORTED; }
static UINTN CR_RouteConfig(void *This, CHAR16 *Cfg, CHAR16 **Progress)
{ (void)This;(void)Cfg; if(Progress)*Progress=(CHAR16*)L""; return EFI_INVALID_PARAMETER; }
static UINTN CR_BlockToConfig(void *This, CHAR16 *Req, void *Block, UINTN BlockSize, CHAR16 **Cfg, CHAR16 **Progress)
{ (void)This;(void)Req;(void)Block;(void)BlockSize;if(Cfg)*Cfg=(CHAR16*)L"";if(Progress)*Progress=(CHAR16*)L""; return EFI_UNSUPPORTED; }
static UINTN CR_ConfigToBlock(void *This, CHAR16 *Cfg, void *Block, UINTN *BlockSize, CHAR16 **Progress)
{ (void)This;(void)Cfg;(void)Block;if(BlockSize)*BlockSize=0;if(Progress)*Progress=(CHAR16*)L""; return EFI_UNSUPPORTED; }
static UINTN CR_GetAltCfg(void *This, CHAR16 *Cfg, void *Guid, CHAR16 *Name, CHAR16 *Path, CHAR16 **Alt)
{ (void)This;(void)Cfg;(void)Guid;(void)Name;(void)Path;if(Alt)*Alt=NULL; return EFI_NOT_FOUND; }

static struct {
    UINTN ExtractConfig, RouteConfig, BlockToConfig, ConfigToBlock, ExportConfig, GetAltCfg;
    UINTN _pad[26];   // stub padding: out-of-range offsets -> UNSUPPORTED
} g_HiiConfigRouting = {
    (UINTN)CR_ExtractConfig, (UINTN)CR_RouteConfig, (UINTN)CR_BlockToConfig,
    (UINTN)CR_ConfigToBlock, (UINTN)CR_ExportConfig, (UINTN)CR_GetAltCfg
};

// HII Image: 31A6406A-6BDF-4E46-B2A2-EBAA89C40920
// Shell only needs this to exist; a text console keeps no image database.
static UINTN HI_NewImage(void *This, UINTN PackageList, UINTN *ImageId, void *Image)
{
    (void)This; (void)PackageList; (void)Image;
    if (!ImageId) return EFI_INVALID_PARAMETER;
    *ImageId = 1;
    return 0;
}
static UINTN HI_GetImage(void *This, UINTN PackageList, UINTN ImageId, void *Image)
{
    (void)This; (void)PackageList; (void)ImageId; (void)Image;
    return EFI_NOT_FOUND;
}
static UINTN HI_SetImage(void *This, UINTN PackageList, UINTN ImageId, void *Image)
{
    (void)This; (void)PackageList; (void)ImageId; (void)Image;
    return EFI_NOT_FOUND;
}
static UINTN HI_DrawImage(void *This, UINTN Flags, void *Image, void **Blt, UINTN BltX, UINTN BltY)
{
    (void)This; (void)Flags; (void)Image; (void)Blt; (void)BltX; (void)BltY;
    return EFI_UNSUPPORTED;
}
static UINTN HI_DrawImageId(void *This, UINTN Flags, UINTN PackageList, UINTN ImageId,
                            void **Blt, UINTN BltX, UINTN BltY)
{
    (void)This; (void)Flags; (void)PackageList; (void)ImageId; (void)Blt; (void)BltX; (void)BltY;
    return EFI_UNSUPPORTED;
}
static struct {
    UINTN NewImage, GetImage, SetImage, DrawImage, DrawImageId;
    UINTN _pad[27];
} g_HiiImage = {
    (UINTN)HI_NewImage, (UINTN)HI_GetImage, (UINTN)HI_SetImage,
    (UINTN)HI_DrawImage, (UINTN)HI_DrawImageId
};

// HII Font: stub protocol (4 functions) — text console doesn't render glyphs
static UINTN HF_StringToImage(void *This, UINTN Flags, CHAR16 *Str, void *Info, void **Blt,
                              UINTN X, UINTN Y, void **Rows, UINTN *RowCnt, UINTN *Cols)
{
    (void)This;(void)Flags;(void)Info;(void)X;(void)Y;(void)Cols;
    if (Rows) *Rows = NULL;
    if (RowCnt) *RowCnt = 0;
    if (Str) PrintW(Str);                        // "render" = print to console
    return 0;
}
static UINTN HF_StringIdToImage(void *This, UINTN Flags, UINT8 *Guid, UINTN Pkg, UINTN Id,
                                void *Info, void **Blt, UINTN X, UINTN Y, void **Rows, UINTN *RowCnt, UINTN *Cols)
{ (void)Guid;(void)Pkg;(void)Id; return HF_StringToImage(This, Flags, (CHAR16 *)L"", Info, Blt, X, Y, Rows, RowCnt, Cols); }
static UINTN HF_GetGlyph(void *This, CHAR16 Ch, void *Info, void **Blt, UINTN *Base)
{ (void)This;(void)Ch;(void)Info;(void)Blt;(void)Base; return EFI_NOT_FOUND; }
static UINTN HF_GetFontInfo(void *This, void **Font, void *In, void **Out, CHAR16 *Str)
{ (void)This;(void)Font;(void)In;(void)Out;(void)Str; return EFI_NOT_FOUND; }

static struct {
    UINTN StringToImage, StringIdToImage, GetGlyph, GetFontInfo;
    UINTN _pad[28];   // stub padding: out-of-range offsets -> UNSUPPORTED
} g_HiiFont = {
    (UINTN)HF_StringToImage, (UINTN)HF_StringIdToImage, (UINTN)HF_GetGlyph, (UINTN)HF_GetFontInfo
};

// ---- EFI_DEVICE_PATH_UTILITIES_PROTOCOL ------------------------------------
// IMPORTANT: these 8 functions have NO 'This' parameter.  ShellPkg links
// DevicePathLibOptionalDevicePathProtocol, whose constructor caches this
// protocol; GetDevicePathSize()/DuplicateDevicePath() go straight through it.
// An earlier version of this table had 12 made-up members, so slot 0 returned
// 0 and DuplicateDevicePath() always failed -> no FSx: mappings at all.
static UINTN DpNodeLen(const void *node)
{
    const UINT8 *p = (const UINT8 *)node;
    return (UINTN)p[2] | ((UINTN)p[3] << 8);
}
static int DpIsEnd(const void *node)
{
    const UINT8 *p = (const UINT8 *)node;
    return p[0] == 0x7F && (p[1] == 0xFF || p[1] == 0x01);
}
static UINTN DpSize(const void *dp)
{
    if (!dp) return 0;
    const UINT8 *p = (const UINT8 *)dp;
    UINTN total = 0;
    for (int i = 0; i < 256; i++) {
        UINTN n = DpNodeLen(p);
        if (n < 4 || n > 4096 || total + n > 65536) return 0;
        total += n;
        if (DpIsEnd(p)) return total;
        p += n;
    }
    return 0;
}
static void *DpAlloc(UINTN size)
{
    UINTN n = size ? size : 4;
    void *p = PoolAlloc(n);               // caller will FreePool() it
    if (p) memset(p, 0, n);
    return p;
}
static UINTN DPU_GetDevicePathSize(void *dp) { return DpSize(dp); }
static void *DPU_DupDevicePath(void *dp)
{
    UINTN n = DpSize(dp);
    if (!n) return NULL;
    void *p = DpAlloc(n);
    if (p) memcpy(p, dp, n);
    return p;
}
static void *DPU_AppendDevicePath(void *a, void *b)
{
    UINTN na = DpSize(a), nb = DpSize(b);
    UINTN bodyA = (na > 4) ? na - 4 : 0;   // strip the End node of the first path
    UINTN bodyB = (nb > 4) ? nb - 4 : 0;
    UINT8 *p = (UINT8 *)DpAlloc(bodyA + bodyB + 4);
    if (!p) return NULL;
    if (bodyA) memcpy(p, a, bodyA);
    if (bodyB) memcpy(p + bodyA, b, bodyB);
    UINTN e = bodyA + bodyB;
    p[e] = 0x7F; p[e + 1] = 0xFF; p[e + 2] = 4; p[e + 3] = 0;
    return p;
}
static void *DPU_AppendDeviceNode(void *dp, void *node)
{
    UINTN nd  = DpSize(dp);
    UINTN body = (nd > 4) ? nd - 4 : 0;
    UINTN nlen = node ? DpNodeLen(node) : 0;
    if (nlen < 4) nlen = 0;
    UINT8 *p = (UINT8 *)DpAlloc(body + nlen + 4);
    if (!p) return NULL;
    if (body) memcpy(p, dp, body);
    if (nlen) memcpy(p + body, node, nlen);
    UINTN e = body + nlen;
    p[e] = 0x7F; p[e + 1] = 0xFF; p[e + 2] = 4; p[e + 3] = 0;
    return p;
}
static void *DPU_AppendInstance(void *a, void *b) { return DPU_AppendDevicePath(a, b); }
static void *DPU_GetNextInstance(void **dpi, UINTN *sz)
{ (void)dpi; if (sz) *sz = 0; return NULL; }
static UINTN DPU_IsMultiInstance(void *dp) { (void)dp; return 0; }
static void *DPU_CreateNode(UINT8 t, UINT8 s, UINT16 len)
{
    if (len < 4) len = 4;
    UINT8 *p = (UINT8 *)DpAlloc(len);
    if (!p) return NULL;
    p[0] = t; p[1] = s; p[2] = (UINT8)(len & 0xFF); p[3] = (UINT8)(len >> 8);
    return p;
}
static struct {
    UINTN GetDevicePathSize, DuplicateDevicePath, AppendDevicePath, AppendDeviceNode,
          AppendDevicePathInstance, GetNextDevicePathInstance,
          IsDevicePathMultiInstance, CreateDeviceNode;
    UINTN _pad[24];
} g_DevPathUtils = {
    (UINTN)DPU_GetDevicePathSize, (UINTN)DPU_DupDevicePath, (UINTN)DPU_AppendDevicePath,
    (UINTN)DPU_AppendDeviceNode, (UINTN)DPU_AppendInstance, (UINTN)DPU_GetNextInstance,
    (UINTN)DPU_IsMultiInstance, (UINTN)DPU_CreateNode
};

// ---------------- UnicodeCollation2 (string services the shell needs) --------
// A4C751FC-23AE-4C3E-92E9-4964CF63F349
// Members: StriColl, MetaiMatch, StrLwr, StrUpr, FatToStr, StrToFat, SupportedLanguages
// The shell sometimes passes junk (even EFI status values) as "strings" when an
// earlier collection step failed.  Guard every walk so we report "not equal"
// instead of faulting the whole process.
static UINTN UC_StriColl(void *This, CHAR16 *a, CHAR16 *b)
{
    (void)This;
    if (!a || !b) return 1;
    if (a == b) return 0;
    __try {
        while (*a && *b) {
            int ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
            int cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
            if (ca != cb) return (UINTN)(ca - cb);
            a++; b++;
        }
        return (UINTN)((int)*a - (int)*b);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 1;
    }
}

static UINTN UC_MetaiMatch(void *This, CHAR16 *str, CHAR16 *pat)
{
    (void)This;
    if (!str || !pat) return 0;
    __try {
        const CHAR16 *s = str, *p = pat, *star = NULL, *ss = s;
        while (*s) {
            if (*p == '?' || ((*p >= 'A' && *p <= 'Z' ? *p + 32 : *p) ==
                              (*s >= 'A' && *s <= 'Z' ? *s + 32 : *s))) {
                s++; p++;
            } else if (*p == '*') {
                star = p++; ss = s;
            } else if (star) {
                p = star + 1; s = ++ss;
            } else return 0;
        }
        while (*p == '*') p++;
        return *p ? 0 : 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

static void UC_StrLwr(void *This, CHAR16 *s)
{
    (void)This;
    if (!s) return;
    __try {
    for (; *s; s++) if (*s >= 'A' && *s <= 'Z') *s = (CHAR16)(*s + 32);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }
}
static void UC_StrUpr(void *This, CHAR16 *s)
{
    (void)This;
    if (!s) return;
    __try {
    for (; *s; s++) if (*s >= 'a' && *s <= 'z') *s = (CHAR16)(*s - 32);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }
}
static void UC_FatToStr(void *This, UINTN FatSize, char *Fat, CHAR16 *Str)
{
    (void)This;
    if (!Fat || !Str) return;
    for (UINTN i = 0; i < FatSize && Fat[i]; i++) Str[i] = (CHAR16)(UINT8)Fat[i];
    Str[FatSize] = 0;
}
static UINTN UC_StrToFat(void *This, CHAR16 *Str, UINTN FatSize, char *Fat)
{
    (void)This;
    if (!Str || !Fat) return 0;
    for (UINTN i = 0; i < FatSize; i++) {
        if (!Str[i]) { Fat[i] = 0; return 1; }
        Fat[i] = (char)(Str[i] < 128 ? Str[i] : '?');
    }
    return 0;
}

static char g_ucLangs[] = "en-US;eng;en";

static struct {
    UINTN StriColl, MetaiMatch, StrLwr, StrUpr, FatToStr, StrToFat, SupportedLanguages;
    UINTN _pad[25];   // stub padding: out-of-range offsets -> UNSUPPORTED
} g_UnicodeCollation2 = {
    (UINTN)UC_StriColl, (UINTN)UC_MetaiMatch, (UINTN)UC_StrLwr, (UINTN)UC_StrUpr,
    (UINTN)UC_FatToStr, (UINTN)UC_StrToFat, (UINTN)g_ucLangs
};

// ---------------- DevicePath <-> Text ----------------
// Both protocols take NO 'This' and return a pool-allocated CHAR16* that the
// caller owns (it will FreePool() it) -- a static string here corrupts the heap.
static CHAR16 *DpText(const char *t)
{
    UINTN n = (UINTN)strlen(t);
    CHAR16 *s = (CHAR16 *)DpAlloc((n + 1) * 2);
    if (s) for (UINTN i = 0; i <= n; i++) s[i] = (CHAR16)t[i];
    return s;
}
// NOTE: Shell's map list decides whether two handles are "the same device" by
// comparing the *text* of their device paths (DevicePathCompare ->
// UnicodeCollation StriColl).  A constant string here makes every volume look
// identical and all of them collapse into one map entry, so the text has to be
// derived from the actual node bytes -- the GUID is what tells our volumes apart.
static void DPT_NodeText(const UINT8 *p, char *out, UINTN cap)
{
    if (!p || cap < 8) { if (out && cap) out[0] = 0; return; }
    UINTN len = DpNodeLen(p);
    if (p[0] == 0x01 && p[1] == 0x04 && len >= 20) {
        const UINT8 *g = p + 4;
        _snprintf(out, cap,
                  "VenHw(%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X)",
                  g[0],g[1],g[2],g[3], g[4],g[5], g[6],g[7], g[8],g[9],
                  g[10],g[11],g[12],g[13],g[14],g[15]);
    } else if (p[0] == 0x04 && p[1] == 0x04) {
        char seg[MAX_PATH];
        U16ToAscii((const CHAR16 *)(p + 4), seg, sizeof(seg));
        _snprintf(out, cap, "%s%s", (seg[0] == '\\') ? "" : "\\", seg);
    } else if (p[0] == 0x7F) {
        _snprintf(out, cap, "End()");
    } else {
        _snprintf(out, cap, "Node(0x%02X,0x%02X)", p[0], p[1]);
    }
    out[cap - 1] = 0;
}

static CHAR16 *DPT_ConvertNodeToText(void *node, int DisplayOnly, int AllowShortcuts)
{
    (void)DisplayOnly; (void)AllowShortcuts;
    char t[512];
    DPT_NodeText((const UINT8 *)node, t, sizeof(t));
    return DpText(t);
}

static CHAR16 *DPT_ConvertPathToText(void *path, int DisplayOnly, int AllowShortcuts)
{
    (void)DisplayOnly; (void)AllowShortcuts;
    char  out[2048];
    UINTN n = 0;
    const UINT8 *p = (const UINT8 *)path;
    out[0] = 0;
    for (UINTN guard = 0; p && guard < 64 && !DpIsEnd(p); guard++) {
        char  node[512];
        UINTN need;
        if (DpNodeLen(p) < 4) break;
        DPT_NodeText(p, node, sizeof(node));
        need = (UINTN)strlen(node);
        if (n + need + 2 >= sizeof(out)) break;
        memcpy(out + n, node, need);
        n += need;
        out[n] = 0;
        p += DpNodeLen(p);
    }
    return DpText(out);
}
static struct {
    UINTN ConvertDeviceNodeToText, ConvertDevicePathToText;
    UINTN _pad[30];
} g_DevPathToText = {
    (UINTN)DPT_ConvertNodeToText, (UINTN)DPT_ConvertPathToText, { 0 }
};
static void *DPF_ConvertTextToNode(CHAR16 *s) { (void)s; return NULL; }
static void *DPF_ConvertTextToPath(CHAR16 *s) { (void)s; return NULL; }
static struct {
    UINTN ConvertTextToDeviceNode, ConvertTextToDevicePath;
    UINTN _pad[30];
} g_DevPathFromText = {
    (UINTN)DPF_ConvertTextToNode, (UINTN)DPF_ConvertTextToPath, { 0 }
};

// ---------------------------------------------------------------- images
// UEFI Shell never hands us an image buffer: it calls
//     gBS->LoadImage (FALSE, Parent, DevicePath, NULL, 0, &NewHandle)
// and expects the *firmware* to open that device path, read the file and map
// it.  Rejecting the NULL SourceBuffer is what produced
//     "Command Error Status: Invalid Parameter"
// for every .efi launched from the Shell.
typedef struct {
    UINTN              handle;
    UINT8             *image;
    UINTN              size;
    UINTN              entryRva;
    int                started;
    EFI_LOADED_IMAGE  *li;         // per-image instance
    UINT8             *filePath;   // malloc'd copy of the Media/FilePath node
} LOADED_IMG;
static LOADED_IMG g_loaded[16];

#ifndef HND_IMAGE
#define HND_IMAGE 0xAAAA0000ULL      // handle that owns the virtual volume
#endif

// g_exitJmp / g_exitValid / g_exitStatus live near the top of the file so
// RT->ResetSystem() can unwind a nested image too.

// Concatenate every Media/FilePath node into one host-relative path.
// The Shell builds "FS0:\docs\app.efi" as a single node, but a hand-made
// device path may split it, so join them with '\'.
static int DpToHostPath(const UINT8 *dp, char *out, UINTN cap)
{
    if (!dp) return -1;
    char rel[MAX_PATH * 2];
    rel[0] = 0;
    int got = 0;
    const char *root = g_fsDir;
    const UINT8 *p = dp;
    for (UINTN guard = 0; guard < 64 && !DpIsEnd(p); guard++) {
        UINTN len = DpNodeLen(p);
        if (len < 4) return -1;
        if (p[0] == 0x01 && p[1] == 0x04 && len >= 20) {   // VenHw: which volume?
            for (int i = 0; i < g_volCount; i++)
                if (memcmp(p, g_vols[i].dp, 20) == 0) { root = g_vols[i].dir; break; }
        }
        if (p[0] == 0x04 && p[1] == 0x04) {          // Media / FilePath
            char seg[MAX_PATH];
            U16ToAscii((const CHAR16 *)(p + 4), seg, sizeof(seg));
            char *s = seg;
            while (*s == '\\' || *s == '/') s++;
            if (*s) {
                if (got) strncat(rel, "\\", sizeof(rel) - strlen(rel) - 1);
                strncat(rel, s, sizeof(rel) - strlen(rel) - 1);
                got = 1;
            }
        }
        p += len;
    }
    if (!got) return -1;
    if (strstr(rel, "..")) return -1;                // never escape the jail
    for (char *q = rel; *q; q++) if (*q == '/') *q = '\\';
    _snprintf(out, cap, "%s\\%s", root, rel);
    out[cap - 1] = 0;
    return 0;
}

static UINT8 *ReadWholeFileA(const char *path, UINTN *outSize)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    _fseeki64(f, 0, SEEK_END);
    long long n = _ftelli64(f);
    _fseeki64(f, 0, SEEK_SET);
    if (n <= 0 || n > (long long)(256LL * 1024 * 1024)) { fclose(f); return NULL; }
    UINT8 *b = (UINT8 *)malloc((size_t)n);
    if (!b) { fclose(f); return NULL; }
    size_t got = fread(b, 1, (size_t)n, f);
    fclose(f);
    if (got != (size_t)n) { free(b); return NULL; }
    *outSize = (UINTN)n;
    return b;
}

// Copy one Media/FilePath node + End into a standalone buffer; LoadedImage
// consumers walk this as a UCS-2 string and expect a terminator.
static UINT8 *DpDupFilePath(const UINT8 *dp)
{
    const UINT8 *p = dp;
    UINT8 *last = NULL;
    for (UINTN guard = 0; p && guard < 64 && !DpIsEnd(p); guard++) {
        UINTN len = DpNodeLen(p);
        if (len < 4) break;
        if (p[0] == 0x04 && p[1] == 0x04) {
            UINT8 *out = (UINT8 *)malloc(len + 4);
            if (!out) return last;
            memcpy(out, p, len);
            out[len + 0] = 0x7F; out[len + 1] = 0xFF;
            out[len + 2] = 0x04; out[len + 3] = 0x00;
            if (last) free(last);
            last = out;
        }
        p += len;
    }
    return last;
}

// Map a PE32+ EFI image and register its unwind data.  Returns the image base
// (or NULL), and reports the entry RVA / mapped size through the out params.
static UINT8 *MapPeImage(const UINT8 *buf, UINTN bufSize, UINTN *outEntry, UINTN *outSize)
{
    if (!buf || bufSize < 0x200) return NULL;
    if (*(const UINT16 *)buf != 0x5A4D) return NULL;
    UINT32 pe = *(const UINT32 *)(buf + 0x3C);
    if ((UINTN)pe + 0x100 > bufSize) return NULL;
    if (memcmp(buf + pe, "PE\0\0", 4) != 0) return NULL;
    UINT16 optOff = *(const UINT16 *)(buf + pe + 20);
    const UINT8 *opt = buf + pe + 24;
    UINT64 entryRva = *(const UINT32 *)(opt + 16);
    UINT64 imgBase  = *(const UINT64 *)(opt + 24);
    UINT32 sizeImg  = *(const UINT32 *)(opt + 56);
    UINT32 hdrSize  = *(const UINT32 *)(opt + 60);
    UINT32 relRva   = *(const UINT32 *)(opt + 112 + 5 * 8);
    UINT32 relSize  = *(const UINT32 *)(opt + 112 + 5 * 8 + 4);
    UINT32 exRva    = *(const UINT32 *)(opt + 112 + 3 * 8);
    UINT32 exSize   = *(const UINT32 *)(opt + 112 + 3 * 8 + 4);
    UINTN  nsec     = *(const UINT16 *)(buf + pe + 6);

    UINT8 *image = VirtualAlloc(NULL, sizeImg, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!image) return NULL;
    memset(image, 0, sizeImg);
    memcpy(image, buf, hdrSize < sizeImg ? hdrSize : sizeImg);

    const UINT8 *sec = opt + optOff;
    for (UINTN i = 0; i < nsec; i++) {
        const UINT8 *s = sec + i * 40;
        UINT32 vs = *(const UINT32 *)(s + 8),  va = *(const UINT32 *)(s + 12);
        UINT32 rs = *(const UINT32 *)(s + 16), rp = *(const UINT32 *)(s + 20);
        UINT32 cp = vs < rs ? vs : rs;
        if (va >= sizeImg) continue;
        if (cp > sizeImg - va) cp = sizeImg - va;
        if (rp > bufSize) continue;
        if (cp > bufSize - rp) cp = (UINT32)(bufSize - rp);
        if (cp) memcpy(image + va, buf + rp, cp);
    }
    if (relRva && relSize && relRva + relSize <= sizeImg) {
        UINT64 newBase = (UINT64)image;
        UINT8 *rel = image + relRva;
        UINTN rem = relSize;
        while (rem >= 8) {
            UINT32 pageRva = *(UINT32 *)rel;
            UINT32 bsize   = *(UINT32 *)(rel + 4);
            if (!bsize || bsize > rem) break;
            for (UINTN i = 8; i + 2 <= bsize; i += 2) {
                UINT16 e = *(UINT16 *)(rel + i);
                if ((e >> 12) == 10 && pageRva + (e & 0xFFF) + 8 <= sizeImg) {
                    UINT8 *fix = image + pageRva + (e & 0xFFF);
                    UINT64 v; memcpy(&v, fix, 8);
                    v = v - imgBase + newBase;
                    memcpy(fix, &v, 8);
                }
            }
            rel += bsize; rem -= bsize;
        }
    }
    if (exRva && exSize && exRva + exSize <= sizeImg)
        RtlAddFunctionTable((PRUNTIME_FUNCTION)(image + exRva), exSize / 12, (UINT64)image);

    *outEntry = (UINTN)entryRva;
    *outSize  = sizeImg;
    return image;
}

static UINTN BS_LoadImage(char Boot, UINTN ParentHandle, void *DevicePath,
                          void *SourceBuffer, UINTN SourceSize, UINTN *ImageHandle)
{
    if (!ImageHandle) return EFI_INVALID_PARAMETER;
    *ImageHandle = 0;

    UINT8 *fileBuf  = NULL;
    UINTN  fileSize = 0;
    UINT8 *fileDp   = NULL;
    int    ownedBuf = 0;

    if (SourceBuffer) {
        // optional fast path: caller already supplied the image bytes
        fileBuf  = (UINT8 *)SourceBuffer;
        fileSize = SourceSize;
    } else {
        // standard path used by the Shell: open the device path ourselves
        if (!DevicePath) {
            LOGV(1, "[efihost] LoadImage: both DevicePath and SourceBuffer are NULL\n");
            return EFI_INVALID_PARAMETER;
        }
        char host[MAX_PATH * 2];
        if (DpToHostPath((const UINT8 *)DevicePath, host, sizeof(host)) < 0) {
            LOGV(1, "[efihost] LoadImage: device path carries no file node\n");
            return EFI_INVALID_PARAMETER;
        }
        fileBuf = ReadWholeFileA(host, &fileSize);
        if (!fileBuf) {
            LOGV(1, "[efihost] LoadImage: cannot open '%s'\n", host);
            return EFI_NOT_FOUND;
        }
        ownedBuf = 1;
        fileDp   = DpDupFilePath((const UINT8 *)DevicePath);
        LOGV(2, "[efihost] LoadImage(\"%s\") %llu bytes\n", host, (unsigned long long)fileSize);
    }

    UINTN entryRva = 0, sizeImg = 0;
    UINT8 *image = MapPeImage(fileBuf, fileSize, &entryRva, &sizeImg);
    if (ownedBuf) free(fileBuf);
    if (!image) {
        if (fileDp) free(fileDp);
        LOGV(1, "[efihost] LoadImage: not a valid PE32+ image\n");
        return EFI_UNSUPPORTED;
    }

    for (UINTN i = 0; i < 16; i++) {
        if (g_loaded[i].handle) continue;
        EFI_LOADED_IMAGE *li = (EFI_LOADED_IMAGE *)calloc(1, sizeof(EFI_LOADED_IMAGE));
        if (!li) { VirtualFree(image, 0, MEM_RELEASE); if (fileDp) free(fileDp); return EFI_OUT_OF_RESOURCES; }
        li->Revision       = 0x00001000;
        li->ParentHandle   = ParentHandle;
        li->SystemTable    = (UINT64)g_stForLI;
        li->DeviceHandle   = HND_IMAGE;            // the volume the file lives on
        li->FilePath       = (UINT64)(fileDp ? fileDp : g_imageFilePath);
        li->ImageBase      = (UINT64)image;
        li->ImageSize      = sizeImg;
        li->ImageCodeType  = 1;                    // EfiLoaderCode: Shell demands an app
        li->ImageDataType  = 2;                    // EfiLoaderData
        li->LoadOptionsSize = 0;
        li->LoadOptions    = 0;

        g_loaded[i].handle   = ++g_nextHandle;
        g_loaded[i].image    = image;
        g_loaded[i].size     = sizeImg;
        g_loaded[i].entryRva = entryRva;
        g_loaded[i].li       = li;
        g_loaded[i].filePath = fileDp;
        g_loaded[i].started  = 0;
        *ImageHandle = g_loaded[i].handle;

        BS_InstallProtocolInterface(&g_loaded[i].handle, GUID_LoadedImage, 0, li);
        LOGV(2, "[efihost] LoadImage -> handle 0x%llx base=%p entry=+0x%llx\n",
             (unsigned long long)g_loaded[i].handle, image, (unsigned long long)entryRva);
        return 0;
    }
    VirtualFree(image, 0, MEM_RELEASE);
    if (fileDp) free(fileDp);
    return EFI_OUT_OF_RESOURCES;
}

static UINTN BS_StartImage(UINTN ImageHandle, UINTN *ExitDataSize, CHAR16 **ExitData)
{
    if (ExitDataSize) *ExitDataSize = 0;
    if (ExitData) *ExitData = NULL;
    for (UINTN i = 0; i < 16; i++) {
        if (g_loaded[i].handle != ImageHandle || !g_loaded[i].image) continue;

        UINTN (*entry)(void *, EFI_SYSTEM_TABLE *) =
            (UINTN (*)(void *, EFI_SYSTEM_TABLE *))(g_loaded[i].image + g_loaded[i].entryRva);
        LOGV(2, "[efihost] StartImage: handle 0x%llx entry=%p\n",
             (unsigned long long)ImageHandle, (void *)entry);

        jmp_buf saved;
        int     savedValid = g_exitValid;
        memcpy(&saved, &g_exitJmp, sizeof(jmp_buf));

        UINTN st;
        if (setjmp(g_exitJmp) == 0) {
            g_exitValid  = 1;
            g_exitStatus = 0;
            st = entry((void *)ImageHandle, g_stForLI);   // real handle, not a fake one
        } else {
            st = g_exitStatus;
        }
        g_exitValid = savedValid;
        memcpy(&g_exitJmp, &saved, sizeof(jmp_buf));

        g_loaded[i].started = 1;
        GOP_Snapshot();                        // nested app may have drawn something
        LOGV(2, "[efihost] StartImage: returned status=0x%llx\n", (unsigned long long)st);
        return st;
    }
    return EFI_NOT_FOUND;
}

// gBS->Exit(): an EFI application's entry point ends with this call.  Returning
// from it would let the app fall into CpuDeadLoop(), so a nested image unwinds
// to StartImage() and a top-level one really terminates the host.
static UINTN BS_Exit(UINTN ImageHandle, UINTN ExitStatus, UINTN ExitDataSize, CHAR16 *ExitData)
{
    (void)ExitDataSize; (void)ExitData;
    LOGV(2, "[efihost] Exit(handle=0x%llx, status=0x%llx)\n",
         (unsigned long long)ImageHandle, (unsigned long long)ExitStatus);
    if (g_exitValid) {
        g_exitValid  = 0;
        g_exitStatus = ExitStatus;
        longjmp(g_exitJmp, 1);
    }
    fflush(NULL);
    GOP_Snapshot();
    exit((int)(ExitStatus & 0xFF));
    return ExitStatus;
}

static UINTN BS_UnloadImage(UINTN ImageHandle)
{
    for (UINTN i = 0; i < 16; i++) {
        if (g_loaded[i].handle != ImageHandle) continue;
        if (g_loaded[i].image) VirtualFree(g_loaded[i].image, 0, MEM_RELEASE);
        if (g_loaded[i].li)       free(g_loaded[i].li);
        if (g_loaded[i].filePath) free(g_loaded[i].filePath);
        memset(&g_loaded[i], 0, sizeof(g_loaded[i]));
        LOGV(2, "[efihost] UnloadImage(0x%llx)\n", (unsigned long long)ImageHandle);
        return 0;
    }
    return EFI_NOT_FOUND;
}

// forward decls for protocol dispatch (defined below)
static void *ProtoFind(const UINT8 *guid);
static void *ProtoFindStrict(const UINT8 *guid);
static UINTN HandleCollect(const UINT8 *guid, UINTN **outBuf, UINTN *outCount);
static UINTN HP_HandleProtocol(UINTN Handle, UINT8 *Protocol, void **Interface);
static UINTN OP_OpenProtocol(UINTN Handle, UINT8 *Protocol, void **Interface,
                             UINTN AgentHandle, UINTN ControllerHandle, UINTN Attr);
static UINTN OP_CloseProtocol(UINTN h, UINT8 *p, UINTN a, UINTN c);
static UINTN OP_LocateHandle(UINTN SearchType, UINT8 *Protocol, void *SearchKey,
                             UINTN *BufferSize, UINTN *Buffer);
static UINTN OP_LocateHandleBuffer(UINTN SearchType, UINT8 *Protocol, void *SearchKey,
                                   UINTN *Count, UINTN **Buffer);
static UINTN OP_LocateProtocol(UINT8 *Protocol, void *Registration, void **Interface);
static UINTN OP_LocateDevicePath(UINT8 *Protocol, void **DevicePath, UINTN *Device);

// ---- SimpleTextInputEx (DD9E7534-7762-4698-8C14-F58517A625AA) ----
// EFI_KEY_DATA = { EFI_INPUT_KEY Key; UINT32 KeyShiftState; UINT8 KeyToggleState; } = 12 bytes
static UINTN SIEx_Reset(void *This, int ExtendedVerification)
{
    (void)This; (void)ExtendedVerification; return 0;
}
static UINTN SIEx_ReadKeyStrokeEx(void *This, void *KeyData)
{
    (void)This;
    if (!KeyData) return EFI_INVALID_PARAMETER;
    unsigned char *p = (unsigned char *)KeyData;
    memset(p, 0, 12);
    UINT16 k[2] = { 0, 0 };
    UINTN st = SI_ReadKeyStroke(This, k);      // reuse the ConIn decoder
    if (st != 0) return st;
    memcpy(p, k, 4);                            // Key.ScanCode + Key.UnicodeChar
    return 0;                                   // KeyShiftState/KeyToggleState stay 0
}
static UINTN SIEx_SetState(void *This, void *KeyToggleState)
{
    (void)This; (void)KeyToggleState; return 0;
}
static UINTN SIEx_RegisterKeyNotify(void *This, void *KeyData, void *NotifyFn, void **NotifyHandle)
{
    (void)This; (void)KeyData; (void)NotifyFn;
    if (!NotifyHandle) return EFI_INVALID_PARAMETER;
    static UINTN tokens = 0;
    *NotifyHandle = (void *)(++tokens);
    return 0;
}
static UINTN SIEx_UnregisterKeyNotify(void *This, void *NotificationHandle)
{
    (void)This; (void)NotificationHandle; return 0;
}
static struct {
    UINTN Reset;
    UINTN ReadKeyStrokeEx;
    UINTN WaitForKeyEx;                 // EFI_EVENT, not a function
    UINTN SetState;
    UINTN RegisterKeyNotify;
    UINTN UnregisterKeyNotify;
    UINTN _pad[32];
} g_ConInEx = {
    (UINTN)SIEx_Reset, (UINTN)SIEx_ReadKeyStrokeEx, 0,
    (UINTN)SIEx_SetState, (UINTN)SIEx_RegisterKeyNotify, (UINTN)SIEx_UnregisterKeyNotify
};
static UINT8 GUID_SimpleTextInputEx[16] = { 0x34,0x75,0x9E,0xDD, 0x62,0x77, 0x98,0x46,
                                            0x8C,0x14, 0xF5,0x85,0x17,0xA6,0x25,0xAA };

// ---- RegisterProtocolNotify: record (GUID -> Event) so callers get SUCCESS ----
typedef struct { UINT8 guid[16]; void *event; } PROTONOTIFY;
static PROTONOTIFY g_notify[64];

static UINTN BS_RegisterProtocolNotify(UINT8 *Protocol, void *Event, void **Registration)
{
    if (!Protocol || !Registration) return EFI_INVALID_PARAMETER;
    for (UINTN i = 0; i < 64; i++) {
        if (!g_notify[i].event) {
            memcpy(g_notify[i].guid, Protocol, 16);
            g_notify[i].event = Event;
            *Registration = (void *)&g_notify[i];
            return 0;
        }
    }
    return EFI_OUT_OF_RESOURCES;
}

static void BuildBootServices(void)
{
    memset(g_bs, 0, sizeof(g_bs));
    g_bs[0] = BS_SIGNATURE;
    ((UINT32 *)g_bs)[2] = 0x00020070;         // Revision 2.70
    ((UINT32 *)g_bs)[3] = sizeof(g_bs);       // HeaderSize
    ((UINT32 *)g_bs)[4] = 0;                  // CRC32
    g_bs[3]  = (UINTN)UnsupportedFn;          // RaiseTPL
    g_bs[4]  = (UINTN)UnsupportedFn;          // RestoreTPL
    g_bs[5]  = (UINTN)BS_AllocatePages;
    g_bs[6]  = (UINTN)BS_FreePages;
    g_bs[7]  = (UINTN)BS_GetMemoryMap;
    g_bs[8]  = (UINTN)BS_AllocatePool;
    g_bs[9]  = (UINTN)BS_FreePool;
    g_bs[10] = (UINTN)BS_CreateEvent;
    g_bs[11] = (UINTN)BS_SetTimer;
    g_bs[12] = (UINTN)BS_WaitForEvent;
    g_bs[13] = (UINTN)BS_SignalEvent;
    g_bs[14] = (UINTN)BS_CloseEvent;
    g_bs[15] = (UINTN)BS_CheckEvent;
    g_bs[16] = (UINTN)BS_InstallProtocolInterface;
    g_bs[17] = (UINTN)BS_ReinstallProtocolInterface;
    g_bs[18] = (UINTN)BS_UninstallProtocolInterface;
    g_bs[19] = (UINTN)HP_HandleProtocol;      // HandleProtocol
    g_bs[21] = (UINTN)BS_RegisterProtocolNotify;
    g_bs[22] = (UINTN)OP_LocateHandle;        // LocateHandle
    g_bs[23] = (UINTN)OP_LocateDevicePath;    // LocateDevicePath
    g_bs[25] = (UINTN)BS_LoadImage;
    g_bs[26] = (UINTN)BS_StartImage;
    g_bs[27] = (UINTN)BS_Exit;                // apps end with gBS->Exit()
    g_bs[28] = (UINTN)BS_UnloadImage;
    g_bs[29] = (UINTN)BS_ExitBootServices;
    g_bs[30] = (UINTN)BS_GetNextMonotonicCount;
    g_bs[31] = (UINTN)BS_Stall;
    g_bs[32] = (UINTN)BS_SetWatchdog;
    g_bs[33] = (UINTN)BS_ConnectController;
    g_bs[34] = (UINTN)BS_DisconnectController;
    g_bs[35] = (UINTN)OP_OpenProtocol;        // OpenProtocol
    g_bs[36] = (UINTN)OP_CloseProtocol;       // CloseProtocol
    g_bs[37] = (UINTN)BS_OpenProtocolInfo;    // OpenProtocolInformation
    g_bs[38] = (UINTN)BS_ProtocolsPerHandle;  // ProtocolsPerHandle
    g_bs[39] = (UINTN)OP_LocateHandleBuffer;  // LocateHandleBuffer
    g_bs[40] = (UINTN)OP_LocateProtocol;      // LocateProtocol
    g_bs[43] = (UINTN)BS_CalculateCrc32;      // CalculateCrc32
    g_bs[44] = (UINTN)BS_CopyMem;
    g_bs[45] = (UINTN)BS_SetMem;
    for (int i = 3; i < 46; i++)
        if (!g_bs[i]) g_bs[i] = (UINTN)UnsupportedFn;
}

static UINTN g_rs[20];
// ---- protocol dispatch: HandleProtocol family ----
static UINTN HP_HandleProtocol(UINTN Handle, UINT8 *Protocol, void **Interface)
{
    if (!Interface) return EFI_INVALID_PARAMETER;
    *Interface = NULL;
    // Per-handle first: SimpleFileSystem, DevicePath and LoadedImage all have a
    // distinct instance per handle.  The old order returned the global registry
    // entry, so every volume got volume 0's interface and the same device path.
    void *res = HandleLookup(HandleFind(Handle), Protocol);
    if (!res) {
        if (memcmp(Protocol, GUID_LoadedImage, 16) == 0) {
            res = &g_LoadedImage;       // our own image's instance
        } else if (memcmp(Protocol, GUID_SimpleFS, 16) == 0 ||
                   memcmp(Protocol, GUID_DevicePath, 16) == 0) {
            res = NULL;                 // never fake a per-handle protocol
        } else {
            res = ProtoFindStrict(Protocol);
        }
    }
    UINT32 a; UINT16 b, c;
    memcpy(&a, Protocol, 4); memcpy(&b, Protocol + 4, 2); memcpy(&c, Protocol + 6, 2);
    if (res) {
        *Interface = res;
        LOGV(2, "[efihost] HandleProtocol(h=0x%llx, %08X-%04X-%04X) -> OK %p\n",
                (unsigned long long)Handle, a, b, c, res);
        return 0;
    }
    *Interface = NULL;          // never leave the out-param as stack garbage
    LOGV(2, "[efihost] HandleProtocol(MISSING) h=0x%llx %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
            (unsigned long long)Handle, a, b, c, Protocol[8], Protocol[9], Protocol[10], Protocol[11],
            Protocol[12], Protocol[13], Protocol[14], Protocol[15]);
    ReportCaller("HandleProtocol(unknown GUID)");
    return EFI_NOT_FOUND;
}

static UINTN OP_OpenProtocol(UINTN Handle, UINT8 *Protocol, void **Interface,
                             UINTN AgentHandle, UINTN ControllerHandle, UINTN Attr)
{
    (void)AgentHandle; (void)ControllerHandle; (void)Attr;
    return HP_HandleProtocol(Handle, Protocol, Interface);
}

static UINTN OP_CloseProtocol(UINTN h, UINT8 *p, UINTN a, UINTN c)
{ (void)h; (void)p; (void)a; (void)c; return 0; }

#define EFI_LOCATE_BY_PROTOCOL 2

static UINTN OP_LocateHandle(UINTN SearchType, UINT8 *Protocol, void *SearchKey,
                             UINTN *BufferSize, UINTN *Buffer)
{
    (void)SearchKey;
    {
        UINT32 a = 0; UINT16 b = 0, c = 0;
        if (Protocol) { memcpy(&a, Protocol, 4); memcpy(&b, Protocol + 4, 2); memcpy(&c, Protocol + 6, 2); }
        LOGV(2, "[efihost] LH(type=%llu, %08X-%04X-%04X)\n",
                (unsigned long long)SearchType, a, b, c);
    }
    const UINT8 *guid = (SearchType == 2 /*ByProtocol*/) ? Protocol : NULL;
    UINTN *buf = NULL, n = 0;
    if (SearchType == 2 && !Protocol) return EFI_INVALID_PARAMETER;
    n = HandleCollect(guid, &buf, &n);
    if (guid) {
        UINT32 a; UINT16 b, c;
        memcpy(&a, guid, 4); memcpy(&b, guid + 4, 2); memcpy(&c, guid + 6, 2);
        LOGV(2, "[efihost] LocateHandle(ByProtocol %08X-%04X-%04X) -> n=%llu\n",
                a, b, c, (unsigned long long)n);
    }
    if (!n) return EFI_NOT_FOUND;
    UINTN need = n * sizeof(UINTN);
    if (!BufferSize || *BufferSize < need || !Buffer) {
        if (BufferSize) *BufferSize = need;
        free(buf);
        return EFI_BUFFER_TOO_SMALL;
    }
    memcpy(Buffer, buf, need);
    *BufferSize = need;
    free(buf);
    return 0;
}

static UINTN OP_LocateHandleBuffer(UINTN SearchType, UINT8 *Protocol, void *SearchKey,
                                   UINTN *Count, UINTN **Buffer)
{
    (void)SearchKey;
    {
        UINT32 a = 0; UINT16 b = 0, c = 0;
        if (Protocol) { memcpy(&a, Protocol, 4); memcpy(&b, Protocol + 4, 2); memcpy(&c, Protocol + 6, 2); }
        LOGV(2, "[efihost] LHB(type=%llu, %08X-%04X-%04X)\n",
                (unsigned long long)SearchType, a, b, c);
    }
    if (!Count || !Buffer) return EFI_INVALID_PARAMETER;
    const UINT8 *guid = (SearchType == 2 /*ByProtocol*/) ? Protocol : NULL;
    if (SearchType == 2 && !Protocol) return EFI_INVALID_PARAMETER;
    UINTN *buf = NULL, n = 0;
    n = HandleCollect(guid, &buf, &n);
    if (guid) {
        UINT32 a; UINT16 b, c;
        memcpy(&a, guid, 4); memcpy(&b, guid + 4, 2); memcpy(&c, guid + 6, 2);
        LOGV(2, "[efihost] LocateHandleBuffer(ByProtocol %08X-%04X-%04X) -> n=%llu\n",
                a, b, c, (unsigned long long)n);
    }
    if (!n) return EFI_NOT_FOUND;
    *Count = n;
    *Buffer = buf;
    return 0;
}

// ---- protocol registry: GUID -> interface, shared by all dispatch paths ----
#define MAX_PROTO 24
static struct { UINT8 guid[16]; void *iface; } g_protos[MAX_PROTO];
static UINTN g_protoCount;

static void ProtoAdd(const UINT8 *guid, void *iface)
{
    if (g_protoCount >= MAX_PROTO) return;
    memcpy(g_protos[g_protoCount].guid, guid, 16);
    g_protos[g_protoCount].iface = iface;
    g_protoCount++;
}

// Unknown protocols: hand back a table of stubs instead of NULL, so apps that
// skip the return-code check get EFI_UNSUPPORTED rather than a null deref.
#define NULLPROTO_SLOTS 512
static UINTN g_nullProto[NULLPROTO_SLOTS];

static void BuildNullProto(void)
{
    for (int i = 0; i < NULLPROTO_SLOTS; i++) g_nullProto[i] = (UINTN)UnsupportedFn;
}

static void *ProtoFind(const UINT8 *guid)
{
    for (UINTN i = 0; i < g_protoCount; i++)
        if (memcmp(g_protos[i].guid, guid, 16) == 0) return g_protos[i].iface;
    return g_nullProto;   // last resort: stub table, never NULL
}

// strict lookup used where a real protocol is required (no stub fallback)
static void *ProtoFindStrict(const UINT8 *guid)
{
    for (UINTN i = 0; i < g_protoCount; i++)
        if (memcmp(g_protos[i].guid, guid, 16) == 0) return g_protos[i].iface;
    return NULL;
}

// fill the stub padding of a protocol table with UnsupportedFn
static void ProtoPad(void *tbl, UINTN slots)
{
    UINTN *t = (UINTN *)tbl;
    for (UINTN i = 0; i < slots; i++)
        if (!t[i]) t[i] = (UINTN)UnsupportedFn;
}

static void BuildProtocols(void)
{
    g_protoCount = 0;
    BuildNullProto();
    GOP_Init();
    ProtoAdd(GUID_GraphicsOutput,   &g_gopProto);
    ProtoAdd(GUID_SimpleFS,         &g_vols[0]);
    if (g_blkCount > 0) ProtoAdd(GUID_BlockIo, &g_blks[0].io);
    ProtoAdd(GUID_LoadedImage,      &g_LoadedImage);
    ProtoAdd(GUID_HIIDatabase,      &g_HiiDatabase);
    ProtoAdd(GUID_HIIString,        &g_HiiString);
    ProtoAdd(GUID_HIIFont,          &g_HiiFont);
    ProtoAdd(GUID_HIIConfigRouting, &g_HiiConfigRouting);
    ProtoAdd(GUID_HIIImage,         &g_HiiImage);
    ProtoAdd(GUID_DevicePathUtils,  &g_DevPathUtils);
    ProtoAdd(GUID_UnicodeCollation2,&g_UnicodeCollation2);
    ProtoAdd(GUID_SimpleTextInputEx,&g_ConInEx);
    ProtoAdd(GUID_FileInfo,         &g_vols[0]);    // informational only
    // DevicePath is per-handle (one per volume): registering it globally made
    // every handle report the same path.
    ProtoAdd(GUID_DevicePathToText, &g_DevPathToText);
    ProtoAdd(GUID_DevicePathFromText, &g_DevPathFromText);
    ProtoPad(&g_HiiDatabase, sizeof(g_HiiDatabase)/sizeof(UINTN));
    ProtoPad(&g_HiiString, sizeof(g_HiiString)/sizeof(UINTN));
    ProtoPad(&g_HiiConfigRouting, sizeof(g_HiiConfigRouting)/sizeof(UINTN));
    ProtoPad(&g_HiiImage, sizeof(g_HiiImage)/sizeof(UINTN));
    ProtoPad(&g_HiiFont, sizeof(g_HiiFont)/sizeof(UINTN));
    ProtoPad(&g_DevPathUtils, sizeof(g_DevPathUtils)/sizeof(UINTN));
    g_hiiStrTbl = (UINTN)&g_HiiString;
    ProtoPad(&g_UnicodeCollation2, sizeof(g_UnicodeCollation2)/sizeof(UINTN));
    ProtoPad(&g_ConInEx, sizeof(g_ConInEx)/sizeof(UINTN));
    ProtoPad(&g_DevPathToText, sizeof(g_DevPathToText)/sizeof(UINTN));
    ProtoPad(&g_DevPathFromText, sizeof(g_DevPathFromText)/sizeof(UINTN));
}

// ---- populate the handle database so LocateHandle(ByProtocol) works ----
#define HND_IMAGE   0xAAAA0000ULL
#define HND_CONIN   0xAAAA0001ULL
#define HND_CONOUT  0xAAAA0002ULL
#define HND_HII     0xAAAA0010ULL
#define HND_DPU     0xAAAA0011ULL
#define HND_COLL    0xAAAA0012ULL
#define HND_GOP     0xAAAA0004ULL

static void HndInstall(UINTN h, const UINT8 *guid, void *iface)
{
    EFI_HANDLE_OBJ *ho = HandleGet(h);
    if (!ho || ho->count >= 24) return;
    memcpy(ho->protos[ho->count].guid, guid, 16);
    ho->protos[ho->count].iface = iface;
    ho->count++;
}

static void BuildHandles(void)
{
    HndInstall(HND_IMAGE, GUID_LoadedImage,       &g_LoadedImage);
    HndInstall(HND_IMAGE, GUID_DevicePath,        g_endDevicePath);
    for (int i = 0; i < g_volCount; i++) {
        HndInstall(g_vols[i].handle, GUID_SimpleFS,   &g_vols[i]);
        HndInstall(g_vols[i].handle, GUID_DevicePath, g_vols[i].dp);
    }
    for (int i = 0; i < g_blkCount; i++) {
        HndInstall(g_blks[i].handle, GUID_BlockIo,    &g_blks[i].io);
        HndInstall(g_blks[i].handle, GUID_DevicePath, g_blks[i].dp);
    }
    HndInstall(HND_CONIN, GUID_SimpleTextIn,      g_conIn);
    HndInstall(HND_CONIN, GUID_SimpleTextInputEx, &g_ConInEx);
    HndInstall(HND_CONOUT,GUID_SimpleTextOut,     g_conOut);
    // Real firmware keeps GOP on the graphics device handle, and BootLogoLib &
    // friends reach it through gST->ConsoleOutHandle.  Install on both so either
    // route works.
    HndInstall(HND_CONOUT,GUID_GraphicsOutput,    &g_gopProto);
    HndInstall(HND_GOP,   GUID_GraphicsOutput,    &g_gopProto);
    HndInstall(HND_HII,   GUID_HIIDatabase,       &g_HiiDatabase);
    HndInstall(HND_HII,   GUID_HIIString,         &g_HiiString);
    HndInstall(HND_HII,   GUID_HIIFont,           &g_HiiFont);
    HndInstall(HND_HII,   GUID_HIIConfigRouting,  &g_HiiConfigRouting);
    HndInstall(HND_HII,   GUID_HIIImage,          &g_HiiImage);
    HndInstall(HND_DPU,   GUID_DevicePathUtils,   &g_DevPathUtils);
    HndInstall(HND_COLL,  GUID_UnicodeCollation2, &g_UnicodeCollation2);
    HndInstall(HND_DPU,   GUID_DevicePathToText,  &g_DevPathToText);
    HndInstall(HND_DPU,   GUID_DevicePathFromText,&g_DevPathFromText);
}

// collect all handles exposing a protocol (or all handles when guid==NULL)
static UINTN HandleCollect(const UINT8 *guid, UINTN **outBuf, UINTN *outCount)
{
    UINTN n = 0;
    for (UINTN i = 0; i < 64; i++) {
        if (!g_handleTab[i].used) continue;
        if (guid) {
            int found = 0;
            for (UINTN j = 0; j < g_handleTab[i].count; j++)
                if (memcmp(g_handleTab[i].protos[j].guid, guid, 16) == 0) { found = 1; break; }
            if (!found) {
                // virtual protocols served without a real install (HII etc.)
                if (!ProtoFindStrict((UINT8 *)guid)) continue;
                if (n == 0) { /* fallthrough: expose one handle for it */ }
                else continue;
            }
        }
        n++;
    }
    if (!n && guid && ProtoFindStrict((UINT8 *)guid)) n = 1;   // at least one
    if (!n) return 0;
    UINTN *buf = (UINTN *)calloc(n, sizeof(UINTN));
    if (!buf) return 0;
    UINTN k = 0;
    for (UINTN i = 0; i < 64 && k < n; i++) {
        if (!g_handleTab[i].used) continue;
        if (guid) {
            int found = 0;
            for (UINTN j = 0; j < g_handleTab[i].count; j++)
                if (memcmp(g_handleTab[i].protos[j].guid, guid, 16) == 0) { found = 1; break; }
            if (!found) continue;
        }
        buf[k++] = g_handleTab[i].handle;
    }
    if (k == 0) buf[k++] = HND_IMAGE;      // virtual fallback
    if (outBuf)   *outBuf = buf; else free(buf);
    if (outCount) *outCount = k;
    return k;
}

static UINTN OP_LocateProtocol(UINT8 *Protocol, void *Registration, void **Interface)
{
    (void)Registration;
    if (!Protocol || !Interface) return EFI_INVALID_PARAMETER;
    void *p = ProtoFindStrict(Protocol);
    if (p) { *Interface = p; return 0; }
    {
        UINT32 a; UINT16 b, c;
        memcpy(&a, Protocol, 4); memcpy(&b, Protocol + 4, 2); memcpy(&c, Protocol + 6, 2);
        LOGV(2, "[efihost] LocateProtocol(unknown) %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
                a, b, c, Protocol[8], Protocol[9], Protocol[10], Protocol[11],
                Protocol[12], Protocol[13], Protocol[14], Protocol[15]);
    }
    *Interface = NULL;             // spec behaviour: absent protocol -> NOT_FOUND
    return EFI_NOT_FOUND;
}

// LocateDevicePath(Protocol, &DevicePath, &Device)
//   - picks the handle exposing Protocol whose own device path is a *prefix*
//     of *DevicePath (longest match wins)
//   - on success advances *DevicePath to the REMAINDER, as the UEFI spec says.
//     InternalOpenFileDevicePath() relies on that remainder to find the
//     MEDIA_FILEPATH_DP node and extract the file name; leaving it untouched
//     made every ShellOpenFileByName() fail (cd / type / mkdir / cp ...).
static UINTN OP_LocateDevicePath(UINT8 *Protocol, void **DevicePath, UINTN *Device)
{
    if (!Protocol || !DevicePath || !*DevicePath) return EFI_INVALID_PARAMETER;

    UINT8 *dp  = (UINT8 *)*DevicePath;
    UINTN  dsz = DpSize(dp);
    if (dsz < 4) return EFI_INVALID_PARAMETER;

    if (g_traceBt) {
        LOGV(2, "[efihost]   dp size=%u:", (unsigned)dsz);
        for (UINT8 *n = dp; dsz && !DpIsEnd(n); n += DpNodeLen(n)) {
            char tmp[260];
            tmp[0] = 0;
            if (n[0] == 0x04 && n[1] == 0x04) U16ToAscii((CHAR16 *)(n + 4), tmp, sizeof(tmp));
            LOGV(2, " [%02x/%02x len=%u '%s']", n[0], n[1], (unsigned)DpNodeLen(n), tmp);
            if ((UINTN)(n - dp) > dsz) break;
        }
        LOGV(2, "\n");
    }

    UINTN *buf = NULL, cnt = 0;
    HandleCollect(Protocol, &buf, &cnt);
    if (!buf || cnt == 0) { if (buf) free(buf); return EFI_NOT_FOUND; }

    UINT8 *bestRest = NULL;
    UINTN  bestHnd  = 0;

    for (UINTN i = 0; i < cnt; i++) {
        EFI_HANDLE_OBJ *ho = HandleGet(buf[i]);
        if (!ho) continue;
        UINT8 *hd = NULL;
        int    hasProto = 0;
        for (UINTN k = 0; k < ho->count; k++) {
            if (!memcmp(ho->protos[k].guid, Protocol, 16)) hasProto = 1;
            if (!memcmp(ho->protos[k].guid, GUID_DevicePath, 16))
                hd = (UINT8 *)ho->protos[k].iface;
        }
        if (!hasProto || !hd) continue;

        UINT8 *a = hd, *b = dp;
        int    match = 1;
        while (!DpIsEnd(a)) {
            UINTN la = DpNodeLen(a);
            if (la < 4 || (UINTN)(dp + dsz - b) < la) { match = 0; break; }
            UINTN lb = DpNodeLen(b);
            if (lb != la || memcmp(a, b, la) != 0) { match = 0; break; }
            a += la;
            b += lb;
            if ((UINTN)(b - dp) > dsz) { match = 0; break; }
        }
        if (match && (!bestRest || b > bestRest)) { bestRest = b; bestHnd = buf[i]; }
    }
    free(buf);

    if (!bestRest) return EFI_NOT_FOUND;
    *DevicePath = bestRest;                 // remainder after the matched nodes
    if (Device) *Device = bestHnd;
    LOGV(2, "[efihost] LocateDevicePath -> handle 0x%llx, remainder 0x%02x%02x (%u bytes left)\n",
         (unsigned long long)bestHnd, bestRest[0], bestRest[1],
         (unsigned)(dp + dsz - bestRest));
    return 0;
}

static void BuildRuntimeServices(void)
{
    memset(g_rs, 0, sizeof(g_rs));
    g_rs[0] = RS_SIGNATURE;
    ((UINT32 *)g_rs)[2] = 0x00020070;
    ((UINT32 *)g_rs)[3] = sizeof(g_rs);
    g_rs[3]  = (UINTN)RT_GetTime;                 // GetTime
    g_rs[4]  = (UINTN)RT_SetTime;                 // SetTime
    g_rs[5]  = (UINTN)UnsupportedFn;              // GetWakeupTime
    g_rs[6]  = (UINTN)UnsupportedFn;              // SetWakeupTime
    g_rs[9]  = (UINTN)RT_GetVariable;             // GetVariable
    g_rs[10] = (UINTN)RT_GetNextVariableName;     // GetNextVariableName
    g_rs[11] = (UINTN)RT_SetVariable;             // SetVariable
    g_rs[12] = (UINTN)BS_GetNextMonotonicCount;   // GetNextHighMonotonicCount (same shape)
    g_rs[13] = (UINTN)RT_ResetSystem;             // ResetSystem
    g_rs[16] = (UINTN)RT_QueryVariableInfo;       // QueryVariableInfo
    for (int i = 0; i < 20; i++)
        if (!g_rs[i]) g_rs[i] = (UINTN)UnsupportedFn;
}

// ------------------------------------------------------------- PE loader

static UINT8 *g_file;
static long   g_fsize;

static UINT16 rd16(const UINT8 *p) { UINT16 v; memcpy(&v, p, 2); return v; }
static UINT32 rd32(const UINT8 *p) { UINT32 v; memcpy(&v, p, 4); return v; }
static UINT64 rd64(const UINT8 *p) { UINT64 v; memcpy(&v, p, 8); return v; }
static void   wr64(UINT8 *p, UINT64 v) { memcpy(p, &v, 8); }

static UINT8 *pe_pe;        // "PE\0\0"
static UINT8 *pe_opt;       // optional header
static UINTN  pe_numSections;
static UINT8 *pe_sections;
static UINT64 pe_entryRVA, pe_imageBase, pe_sizeOfImage;
static UINT64 pe_relocDirRVA, pe_relocDirSize;
static UINT64 pe_exceptDirRVA, pe_exceptDirSize;

static int ParsePE(void)
{
    if (g_fsize < 0x100 || rd16(g_file) != 0x5A4D) return 0;
    UINT32 e_lfanew = rd32(g_file + 0x3C);
    if (e_lfanew + 264 > (UINT32)g_fsize) return 0;
    pe_pe = g_file + e_lfanew;
    if (memcmp(pe_pe, "PE\0\0", 4) != 0) return 0;
    if (rd16(pe_pe + 4) != 0x8664) { LOGV(0, "[efihost] not x64 image\n"); return 0; }
    pe_numSections = rd16(pe_pe + 6);
    UINT16 sizeOpt = rd16(pe_pe + 20);
    pe_opt = pe_pe + 24;
    if (rd16(pe_opt) != 0x20B) { LOGV(0, "[efihost] not PE32+\n"); return 0; }
    pe_entryRVA      = rd32(pe_opt + 16);
    pe_imageBase     = rd64(pe_opt + 24);
    pe_sizeOfImage   = rd32(pe_opt + 56);
    pe_relocDirRVA   = rd32(pe_opt + 112 + 5 * 8);
    pe_relocDirSize  = rd32(pe_opt + 112 + 5 * 8 + 4);
    pe_exceptDirRVA  = rd32(pe_opt + 112 + 3 * 8);   // Exception dir (.pdata)
    pe_exceptDirSize = rd32(pe_opt + 112 + 3 * 8 + 4);
    pe_sections      = pe_opt + sizeOpt;
    return 1;
}

static void ApplyRelocs(UINT8 *image, UINT64 newBase)
{
    if (!pe_relocDirRVA || !pe_relocDirSize) {
        LOGV(1, "[efihost] WARNING: no .reloc section; image base must match 0x%llx\n",
                (unsigned long long)pe_imageBase);
        return;
    }
    UINT8 *rel = image + pe_relocDirRVA;
    UINTN  remaining = pe_relocDirSize;
    while (remaining >= 8) {
        UINT32 pageRVA    = rd32(rel);
        UINT32 blockSize  = rd32(rel + 4);
        if (!blockSize || blockSize > remaining) break;
        UINTN numEntries = (blockSize - 8) / 2;
        for (UINTN i = 0; i < numEntries; i++) {
            UINT16 e = rd16(rel + 8 + i * 2);
            UINT16 type   = e >> 12;
            UINT16 offset = e & 0xFFF;
            if (type == 0) continue;          // padding
            if (type == 10) {                 // IMAGE_REL_BASED_DIR64
                UINT8 *fix = image + pageRVA + offset;
                wr64(fix, rd64(fix) - pe_imageBase + newBase);
            } else {
                LOGV(1, "[efihost] unsupported reloc type %u\n", type);
            }
        }
        rel += blockSize;
        remaining -= blockSize;
    }
}

// ------------------------------------------------------------------ main

typedef UINTN (*EfiEntryFn)(void *ImageHandle, EFI_SYSTEM_TABLE *SystemTable);

int main(int argc, char **argv)
{
    const char *efiPath  = NULL;
    const char *fsDirArg = NULL;

    // log level: env first, then command-line flags override it
    if (getenv("EFHOST_QUIET")) g_logLevel = 0;
    if (getenv("EFHOST_DEBUG")) g_logLevel = 3;
    if (getenv("EFHOST_GUARD")) g_guardPool = 1;   // diagnostic: guard page after every pool block
    if (getenv("EFHOST_CR3"))   g_fakeCr3 = _strtoui64(getenv("EFHOST_CR3"), NULL, 0);
    if (getenv("EFHOST_BT"))    g_traceBt   = 1;   // diagnostic: guest call-site RVAs on FS opens
    if (getenv("EFHOST_LOG")) {
        int v = atoi(getenv("EFHOST_LOG"));
        if (v >= 0 && v <= 3) g_logLevel = v;
    }
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-q") || !strcmp(argv[i], "--quiet")) { g_logLevel = 0; continue; }
        if (!strcmp(argv[i], "-v"))       { if (g_logLevel < 2) g_logLevel = 2; continue; }
        if (!strcmp(argv[i], "-vv") || !strcmp(argv[i], "--debug")) { g_logLevel = 3; continue; }
        if (!efiPath) efiPath = argv[i];
        else if (!fsDirArg) fsDirArg = argv[i];
    }
    if (fsDirArg) strncpy(g_fsDir, fsDirArg, sizeof(g_fsDir) - 1);

    if (!efiPath) {
        fprintf(stderr,
                "usage: %s [-q|-v|-vv] <file.efi> [fsdir]\n"
                "  -q    host output off (only crash dumps)\n"
                "  -v    verbose: protocol calls, file open, SetVar\n"
                "  -vv   full debug: OUT/HII hex, key thread, watchdog\n"
                "  env   EFHOST_QUIET=1 | EFHOST_LOG=0..3 | EFHOST_DEBUG=1\n",
                argv[0]);
        return 1;
    }
    setvbuf(stdout, NULL, _IONBF, 0);   // survive abnormal termination
    setvbuf(stderr, NULL, _IONBF, 0);
    AddVectoredExceptionHandler(1, VehHandler);
    g_inRedirected = !_isatty(0);
    KeyLayerInit(g_inRedirected);
    if (LOGLV(3)) {
        DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                        &g_mainThread, THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
                        FALSE, 0);
        HANDLE wd = CreateThread(NULL, 0, WatchdogThread, NULL, 0, NULL);
        if (wd) CloseHandle(wd);
        HANDLE hb = CreateThread(NULL, 0, HeartbeatThread, NULL, 0, NULL);
        if (hb) CloseHandle(hb);
        atexit(OnAppExit);
    }
    LOGV(2, "[efihost] stdin %s (isatty=%d)\n",
         g_inRedirected ? "REDIRECTED (reader thread)" : "CONSOLE (_kbhit)", _isatty(0));

    FILE *f = fopen(efiPath, "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    g_fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    g_file = malloc(g_fsize);
    if (!g_file || fread(g_file, 1, g_fsize, f) != (size_t)g_fsize) {
        LOGV(0, "[efihost] read failed\n");
        return 1;
    }
    fclose(f);

    if (!ParsePE()) {
        LOGV(0, "[efihost] '%s' is not a PE32+ image\n", efiPath);
        return 1;
    }
    LOGV(1, "[efihost] subsystem=%u  entry RVA=0x%llx  ImageBase=0x%llx  SizeOfImage=0x%llx  relocs=%s\n",
         rd16(pe_opt + 68), (unsigned long long)pe_entryRVA,
         (unsigned long long)pe_imageBase, (unsigned long long)pe_sizeOfImage,
         pe_relocDirSize ? "yes" : "NO");

    // Allocate image at a 64K-aligned base (loader decides), then fix relocs
    UINT8 *image = VirtualAlloc(NULL, pe_sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!image) { LOGV(0, "[efihost] VirtualAlloc failed: %lu\n", GetLastError()); return 1; }
    UINT64 newBase = (UINT64)image;
    g_imageBase = image;
    g_imageSize = pe_sizeOfImage;

    memset(image, 0, pe_sizeOfImage);
    UINT32 sizeOfHeaders = rd32(pe_opt + 60);
    memcpy(image, g_file, sizeOfHeaders);
    for (UINTN i = 0; i < pe_numSections; i++) {
        UINT8 *s = pe_sections + i * 40;
        UINT32 vsize = rd32(s + 8), vaddr = rd32(s + 12);
        UINT32 rsize = rd32(s + 16), rptr  = rd32(s + 20);
        UINT32 copy = vsize < rsize ? vsize : rsize;
        if (copy) memcpy(image + vaddr, g_file + rptr, copy);
        LOGV(2, "[efihost]   sec '%-8.8s' RVA 0x%x raw 0x%x (%u bytes)\n",
             s, vaddr, rptr, rsize);
    }
    ApplyRelocs(image, newBase);

    // Register .pdata so SEH unwinding works for this hand-mapped image.
    // Without this, an exception inside EFI code cannot be dispatched and
    // the process dies with a silent fail-fast (0xC0000409).
    if (pe_exceptDirRVA && pe_exceptDirSize) {
        UINTN cnt = pe_exceptDirSize / 12;
        if (RtlAddFunctionTable((PRUNTIME_FUNCTION)(image + pe_exceptDirRVA), (DWORD)cnt, newBase))
            LOGV(2, "[efihost] registered %llu unwind entries from .pdata\n", (unsigned long long)cnt);
        else
            LOGV(1, "[efihost] WARNING: RtlAddFunctionTable failed\n");
    }

    // ---- build fake UEFI environment ----
    static EFI_SIMPLE_TEXT_OUT conOut, stdErr;
    static EFI_SIMPLE_TEXT_IN  conIn;
    static EFI_SYSTEM_TABLE    st;
    static CHAR16              fwVendor[] = L"UserModeHostUEFI";

    conOut.Reset             = (UINTN)SO_Reset;
    conOut.OutputString      = (UINTN)SO_OutputString;
    conOut.TestString        = (UINTN)SO_TestString;
    conOut.QueryMode         = (UINTN)SO_QueryMode;
    conOut.SetMode           = (UINTN)SO_SetMode;
    conOut.SetAttribute      = (UINTN)SO_SetAttribute;
    conOut.ClearScreen       = (UINTN)SO_ClearScreen;
    conOut.SetCursorPosition = (UINTN)SO_SetCursorPos;
    conOut.EnableCursor      = (UINTN)SO_EnableCursor;
    conOut.Mode              = &g_conOutMode;
    stdErr = conOut;                 // stderr mirrors the console
    stdErr.Mode              = &g_errMode;
    conIn.Reset              = (UINTN)SI_Reset;
    conIn.ReadKeyStroke      = (UINTN)SI_ReadKeyStroke;
    conIn.WaitForKey         = NULL;
    g_conIn  = &conIn;
    g_conOut = &conOut;

    BuildBootServices();
    BuildRuntimeServices();
    VolumesInit(g_fsDir);            // fs0/fs1/fs2 -> FS0.., blk0.. -> BLK0..
    BuildProtocols();
    BuildHandles();
    LOGV(2, "[efihost] tables: null=%p sfs=%p hiiDb=%p hiiStr=%p hiiFont=%p hiiCfg=%p dpu=%p uc=%p dp=%p\n",
            (void *)g_nullProto, (void *)&g_vols[0], (void *)&g_HiiDatabase,
            (void *)&g_HiiString, (void *)&g_HiiFont, (void *)&g_HiiConfigRouting,
            (void *)&g_DevPathUtils, (void *)&g_UnicodeCollation2, (void *)g_endDevicePath);

    // real WaitForKey event so WaitForEvent() can be woken by keystrokes
    {
        void *ev = NULL;
        if (BS_CreateEvent(0, 0, NULL, NULL, &ev) == 0)
            conInWaitKey = conIn.WaitForKey = ev;
        g_ConInEx.WaitForKeyEx = (UINTN)conInWaitKey;
    }

    // ---- minimal HOB list (PHIT + END_OF_HOB_LIST) so DxeHobLib can find it ----
    static unsigned char hobBuf[512];
    {
        struct { unsigned short t, l; unsigned int r; } *h;
        unsigned char *p = hobBuf;
        unsigned long long base = (unsigned long long)(UINTN)p;
        h = (void *)p;
        h->t = 0x0001;                 // EFI_HOB_TYPE_HANDOFF
        h->l = 56;                     // sizeof (EFI_HOB_HANDOFF_INFO_TABLE)
        h->r = 0;
        *(unsigned int *)(p + 8)          = 0x00090000;   // Version
        *(unsigned int *)(p + 12)         = 0;            // BootMode (full config)
        *(unsigned long long *)(p + 16)   = base + sizeof(hobBuf);  // EfiMemoryTop
        *(unsigned long long *)(p + 24)   = base;                   // EfiMemoryBottom
        *(unsigned long long *)(p + 32)   = base + 56;              // EfiFreeMemoryTop
        *(unsigned long long *)(p + 40)   = base + 56;              // EfiFreeMemoryBottom
        *(unsigned long long *)(p + 48)   = base + 56;              // EfiEndOfHobList
        h = (void *)(p + 56);
        h->t = 0xFFFF;                 // EFI_HOB_TYPE_END_OF_HOB_LIST
        h->l = 8;
        h->r = 0;
    }
    static struct { unsigned char guid[16]; void *table; } cfgTab[4];
    {
        static unsigned char hobGuid[16] = { 0x4C,0xF2,0x39,0x77, 0xD7,0x93, 0xD4,0x11,
                                             0x9A,0x3A, 0x00,0x90,0x27,0x3F,0xC1,0x4D };
        memcpy(cfgTab[0].guid, hobGuid, 16);
        cfgTab[0].table = hobBuf;
    }
    // ---- stub DXE Services table (gDS) ----
    static UINTN g_dxesvc[64];
    {
        for (UINTN i = 0; i < 64; i++) g_dxesvc[i] = (UINTN)UnsupportedFn;
        unsigned char *h = (unsigned char *)g_dxesvc;
        *(unsigned long long *)(h + 0)  = 0x565245535F455844ULL;   // 'DXE_SERV'
        *(unsigned int *)(h + 8)        = 0x00010028;              // Revision
        *(unsigned int *)(h + 12)       = 24;                      // HeaderSize
        *(unsigned int *)(h + 16)       = 0;                       // CRC32
        *(unsigned int *)(h + 20)       = 0;                       // Reserved
        static unsigned char dsGuid[16] = { 0xBA,0x34,0xAD,0x05, 0x02,0x6F, 0x14,0x42,
                                            0x95,0x2E,0x4D,0xA0,0x39,0x8E,0x2B,0xB9 };
        memcpy(cfgTab[1].guid, dsGuid, 16);
        cfgTab[1].table = g_dxesvc;
    }

    memset(&st, 0, sizeof(st));
    st.Signature          = ST_SIGNATURE;
    st.Revision           = 0x00020070;    // 2.7
    st.HeaderSize         = sizeof(st);
    st.FirmwareVendor     = fwVendor;
    st.FirmwareRevision   = (1 << 16) | 0; // 1.0
    st.ConsoleInHandle    = 0xAAAA0001;
    st.ConIn              = &conIn;
    st.ConsoleOutHandle   = 0xAAAA0002;
    st.ConOut             = &conOut;
    st.StandardErrorHandle= 0xAAAA0003;
    st.StdErr             = &stdErr;
    st.RuntimeServices    = g_rs;
    st.BootServices       = g_bs;
    st.NumberOfTableEntries = 2;
    st.ConfigurationTable = cfgTab;

    // ---- LoadedImage + FS dir ----
    g_stForLI = &st;
    memset(&g_LoadedImage, 0, sizeof(g_LoadedImage));
    g_LoadedImage.Revision      = 0x00001000;
    g_LoadedImage.SystemTable   = (UINT64)&st;
    g_LoadedImage.DeviceHandle  = g_vols[0].handle;   // first mapped volume
    g_LoadedImage.FilePath      = (UINT64)g_imageFilePath;  // DoStartupScript()/StrLen() read it
    g_LoadedImage.ImageBase     = newBase;
    g_LoadedImage.ImageSize     = pe_sizeOfImage;
    g_LoadedImage.ImageCodeType = 2;            // EfiLoaderCode
    g_LoadedImage.ImageDataType = 3;            // EfiLoaderData
    LOGV(1, "[efihost] FS mapped: '%s' (pass as argv[2] to change)\n", g_fsDir);

    // ---- NVRAM variable store (backed by <fsdir>\efivars.bin) ----
    VarsInit(g_fsDir);

    // ---- jump in ----
    if (!pe_entryRVA) { LOGV(0, "[efihost] zero entry point\n"); return 1; }
    EfiEntryFn entry = (EfiEntryFn)(image + pe_entryRVA);
    LOGV(2, "[efihost] calling entry at %p (base %p)...\n", (void *)entry, (void *)image);

    UINTN status;
    __try {
        status = entry((void *)0xAAAA0000, &st);
    } __except (CrashFilter(GetExceptionInformation())) {
        return 2;
    }
    g_appDone = 1;
    LOGV(1, "[efihost] EFI app returned status=0x%llx (%s)\n",
         (unsigned long long)status,
         (status & EFI_ERROR_MASK) ? "EFI_ERROR" : "EFI_SUCCESS");

    GOP_Snapshot();

    VirtualFree(image, 0, MEM_RELEASE);
    free(g_file);
    return 0;
}
