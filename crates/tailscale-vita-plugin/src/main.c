/*
 * tailscale-vita-plugin — Phase 2 SUPRX shim.
 *
 * Stages the full tailscale-vita Runtime under *TVIT00010 (the demo
 * eboot). When the demo launches:
 *   1. taipool_init reserves a private heap for Rust's
 *      #[global_allocator].
 *   2. ts_vita_rt_start() (in libtailscale_vita_rt.a) spawns the
 *      bootstrap thread which loads Config, brings up Runtime, binds
 *      the listener, and runs the accept loop.
 *   3. module_start returns immediately so SCE proceeds to launch the
 *      demo's main(), which (when config has suprx_host_only=true)
 *      just sleeps to keep the process alive.
 *
 * On module_stop: ts_vita_rt_stop signals shutdown and joins; then
 * taipool_term frees the heap.
 *
 * Phase 3 promotes this from *TVIT00010 to *main (loaded into
 * SceShell), at which point a panic here takes the shell down — which
 * is why we still let the runtime crash silently and rely on Rust's
 * std::panic::catch_unwind in ts_vita_rt_start.
 */

#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/clib.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/types.h>
#include <pthread.h>
#include <string.h>
#include <sys/reent.h>

/* TAIPOOL_AS_STDLIB makes taipool.h define malloc/free/calloc/realloc
 * as taipool-backed wrappers. Without this, pthread's internal malloc
 * (used to allocate thread state) calls newlib's malloc which needs
 * `_sbrk`-backed heap init — and that init is in vitasdk's startup
 * files, which `-nostartfiles` skips. Without TAIPOOL_AS_STDLIB,
 * pthread_create returns EAGAIN (rc=11) and std::thread::spawn
 * crashes (Phase 2 hardware finding 2026-05-05). */
#define TAIPOOL_AS_STDLIB
#include <taipool.h>

/* Phase 2 diagnostic: append a checkpoint marker to a trace file
 * before each potentially-crashing step in module_start. Lets us
 * tell from FTP exactly where the demo died (since vita-log's
 * machinery might itself be the crash culprit). Using raw sceIo*
 * avoids any libc/heap dependency. */
#define TRACE_PATH "ux0:data/tailscale-vita/phase2-trace.txt"

static void trace(const char *msg)
{
    SceUID fd = sceIoOpen(TRACE_PATH,
                          SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND,
                          0666);
    if (fd >= 0) {
        sceIoWrite(fd, msg, strlen(msg));
        sceIoWrite(fd, "\n", 1);
        sceIoClose(fd);
    }
    sceClibPrintf("[ts-vita] trace: %s\n", msg);
}

/* 8-16 MB per plan §heap. Phase 1C used 4 MB for hello-world; the
 * full runtime allocates several MB at startup (smoltcp socket bufs,
 * h2 frame bufs, DERP queue buffers, RustCrypto state, PEM-decoded
 * cert chain). Start at 16 MB; profile + tune later. */
#define TAIPOOL_BYTES (16 * 1024 * 1024)

/* Defined in crates/tailscale-vita-rt/src/lib.rs. */
extern int  ts_vita_rt_start(void);
extern void ts_vita_rt_stop(void);

/* The vitasdk libc/pthread init-on-startup chain that `-nostartfiles`
 * would otherwise skip. crt0.o normally calls these via:
 *
 *   _start -> _init_vita_newlib (which calls _init_vita_heap,
 *                                _init_vita_reent, _init_vita_malloc,
 *                                _init_vita_io)
 *          -> __libc_init_array (which runs `pthread_setup` from
 *                                vita_osal.o's `.init_array.00101`
 *                                ctor — pthread_setup itself does
 *                                `pthread_init(); __sinit(_impure_ptr);`)
 *          -> main
 *
 * We replicate the parts we need directly. taipool covers malloc,
 * so we skip `_init_vita_heap` / `_init_vita_malloc`. We still need
 * `_init_vita_reent` for the TLS slot (slot 0x89) + reent mutex that
 * pte_osInit reads via vitasdk_get_pthread_data. After that,
 * `pthread_setup()` does pthread_init + __sinit. */
extern void _init_vita_reent(void);
extern void _init_vita_io(void);
/* Splitting pthread_setup into its components for tracing — it
 * crashes from module_start and we want to know exactly where. */
extern int  pthread_init(void);
extern void __sinit(struct _reent *);

/* Phase 2: stubs for the two libc-cleanup symbols normally provided
 * by vitasdk's crti.o / crtn.o / vita startup files. We use
 * `-nostartfiles` (no crt0/crti/crtn) because crt0 references `main`
 * which we don't have (SUPRX entry is `module_start`). The libc
 * cleanup paths (`__libc_fini_array`, `_exit`) reference these but
 * are never actually called in a SUPRX (taiHEN tears the process
 * down without going through libc shutdown). Empty fns satisfy the
 * linker and are dead code at runtime.
 */
void _fini(void) {}
void _free_vita_newlib(void) {}

int module_start(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;

    /* Best-effort mkdir; ignore failure (might already exist). */
    sceIoMkdir("ux0:data/tailscale-vita", 0777);

    /* Truncate the trace file so we only see this run's output. */
    SceUID truncfd = sceIoOpen(TRACE_PATH,
                               SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC,
                               0666);
    if (truncfd >= 0) {
        sceIoClose(truncfd);
    }

    trace("c1: module_start entry");

    char buf[64];
    sceClibSnprintf(buf, sizeof buf, "c2: pre-taipool_init(%d)",
                    TAIPOOL_BYTES);
    trace(buf);

    int pool_rc = taipool_init(TAIPOOL_BYTES);
    sceClibSnprintf(buf, sizeof buf, "c3: taipool_init -> %d", pool_rc);
    trace(buf);
    if (pool_rc < 0) {
        return SCE_KERNEL_START_FAILED;
    }

    /* CRITICAL: replicate the libc/pthread init chain that crt0's
     * `_start` would normally have run before main(). With
     * `-nostartfiles`, none of this fires automatically. The
     * 2026-05-05 hardware finding: simply calling `pthread_init()`
     * on its own is not enough — the function reads from a TLS slot
     * (sceKernelGetTLSAddr(0x89)) via vitasdk_get_pthread_data, and
     * that slot must be initialised by `_init_vita_reent` first.
     * Without _init_vita_reent, pthread_init crashes the calling
     * thread silently. */
    /* Initialise newlib reent + stdio global state from
     * module_start. pthread_init/__sinit are NOT called here —
     * they crash from module_start's SCE module-loader thread
     * context. Instead the SCE-spawned bootstrap thread (kicked off
     * by ts_vita_rt_start) calls them later, where __getreent_for_thread
     * can auto-allocate a per-thread reent slot. */
    trace("c3a: pre-_init_vita_reent");
    _init_vita_reent();
    trace("c3b: _init_vita_reent returned");
    _init_vita_io();
    trace("c3c: _init_vita_io returned");

    trace("c4: pre-ts_vita_rt_start");
    int rust_rc = ts_vita_rt_start();
    sceClibSnprintf(buf, sizeof buf, "c5: ts_vita_rt_start -> %d",
                    rust_rc);
    trace(buf);
    if (rust_rc != 0) {
        taipool_term();
        return SCE_KERNEL_START_FAILED;
    }

    trace("c6: returning SCE_KERNEL_START_SUCCESS");
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;

    sceClibPrintf("[ts-vita] module_stop\n");
    ts_vita_rt_stop();
    taipool_term();
    return SCE_KERNEL_STOP_SUCCESS;
}
