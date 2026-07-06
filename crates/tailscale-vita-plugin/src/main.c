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
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/types.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/reent.h>

/* S6 ROOT-CAUSE FIX (2026-06-24): we deliberately DO NOT define
 * TAIPOOL_AS_STDLIB anymore. That macro made taipool.h override C
 * malloc/free/calloc/realloc — but NOT memalign. std's System allocator
 * (used directly by os.rs thread_local, NOT the #[global_allocator])
 * allocates over-aligned blocks via libc memalign and frees via libc
 * free; with the macro, memalign hit NEWLIB while free hit taipool_free
 * — two different heaps, so taipool_free read a bogus block header
 * (0xdeadbeef) and crashed. That was the thread_local! first-access
 * crash. The original 2026-05-05 reason for the macro (pthread's
 * internal malloc had no heap) is moot now that module_start runs
 * _init_vita_heap()/_init_vita_malloc() — newlib's C heap is live. So
 * leave ALL of malloc/free/calloc/realloc/memalign on newlib (a
 * self-consistent set), which makes std::System matched. Rust's Global
 * allocator stays taipool via the extern taipool_alloc/free in lib.rs. */
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
/* S7: taipool is no longer Rust's global allocator (that's now newlib's
 * System) — keep a small reservation only in case something still touches
 * taipool_alloc; the runtime's heap is the newlib heap below. */
/* M20-D take 6: 4 MB -> 1 MB. Vestigial reservation; every MB counts
 * inside SceShell's partition. */
#define TAIPOOL_BYTES (1 * 1024 * 1024)

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
extern void _init_vita_heap(void);
extern void _init_vita_reent(void);
extern void _init_vita_malloc(void);
extern void _init_vita_io(void);
/* Splitting pthread_setup into its components for tracing — it
 * crashes from module_start and we want to know exactly where. */
extern int  pthread_init(void);
extern void __sinit(struct _reent *);

/* Bound newlib's C-side heap. _init_vita_heap defaults to 128 MB when
 * this weak symbol is undefined — far too much for a SUPRX sharing the
 * demo's address space. pthread-embedded's internal C malloc only needs
 * kilobytes (thread/mutex structs), so 8 MB is ample. */
/* S7: the newlib heap now backs ALL Rust allocation (Global = System) plus
 * C-side libc + pthread internals — bumped to 32 MB to cover the runtime
 * (smoltcp bufs, h2 frames, rustls cert chains, crypto, the netmap). */
/* M20-D take 6: 32 MB -> 16 MB. Estimated real use is 3-5 MB (PLUGIN-
 * DEPLOY.md budget); 16 MB keeps >3x margin while halving the biggest
 * single grab from SceShell's partition. */
unsigned int _newlib_heap_size_user = 16 * 1024 * 1024;

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

/* ============================================================
 * M15-A3 S6 VALIDATION SHIM — SCE-backed pthread TLS keys.
 *
 * pthread-embedded's pthread_key_create crashes in this SUPRX even
 * after pte_osInit succeeds (its sub-ops — calloc + sceKernelGetRandom
 * Number — both work in isolation, so the fault is in its own compiled
 * copy: the static-state duplication vs the eboot's libpthread). These
 * strong symbols live in main.o (always linked, never pulled-from-
 * archive), so the linker resolves Rust std's pthread_key_create /
 * setspecific / getspecific to THESE instead of libpthread.a's. Backed
 * by a thread-id-keyed table + one SCE mutex. Validation scope: NO key
 * destructors (fine for Copy thread_local!s). If thread_local! works
 * with this, the full pthread-ABI shim (mutex/cond/rwlock) is viable.
 * ============================================================ */
#define SHIM_MAX_KEYS    128
#define SHIM_MAX_THREADS 64

typedef struct {
    SceUID tid; /* 0 = free slot */
    void  *values[SHIM_MAX_KEYS];
} shim_row;

static shim_row g_shim_rows[SHIM_MAX_THREADS];
static char     g_shim_key_used[SHIM_MAX_KEYS];
static SceUID   g_shim_mutex = -1;

static void shim_lock(void)
{
    if (g_shim_mutex >= 0) sceKernelLockMutex(g_shim_mutex, 1, NULL);
}
static void shim_unlock(void)
{
    if (g_shim_mutex >= 0) sceKernelUnlockMutex(g_shim_mutex, 1);
}

/* pthread-embedded's per-thread "self" descriptor key. Normally created
 * by pthread_init() (pthread_init.c:72) — which we SKIP because it crashes
 * in this SUPRX (S6). Left NULL, pthread_self()'s descriptor cache
 * (`pthread_setspecific(pte_selfThreadKey, self)`) targets key 0, which our
 * shim rejects (idx = -1) as a no-op. So every pthread_self() on a foreign
 * (sceKernelCreateThread) thread re-runs the `sp == NULL` path and mints a
 * fresh pte_thread_t via pte_new() — a ~256 B leak PER CALL (~890 KB/s on
 * hardware → 32 MB OOM in ~40 s; S7 root cause). Giving the key a real shim
 * slot makes the cache work: one descriptor per thread, reused thereafter. */
extern pthread_key_t pte_selfThreadKey;
extern pthread_key_t pte_cleanupKey;

/* Called once from module_start, before any thread spawns. */
void pte_shim_init(void)
{
    g_shim_mutex = sceKernelCreateMutex("pte-shim", 0, 0, NULL);
    /* Must come AFTER g_shim_mutex (pthread_key_create takes shim_lock).
     * These are the two keys pthread_init() would create; without them the
     * self-descriptor cache and cleanup-handler TLS are no-ops (key 0). */
    pthread_key_create(&pte_selfThreadKey, NULL);
    pthread_key_create(&pte_cleanupKey, NULL);
}

int pthread_key_create(pthread_key_t *key, void (*destructor)(void *))
{
    (void)destructor; /* validation: destructors not honored */
    int idx = -1;
    shim_lock();
    for (int i = 0; i < SHIM_MAX_KEYS; i++) {
        if (!g_shim_key_used[i]) {
            g_shim_key_used[i] = 1;
            idx = i;
            break;
        }
    }
    shim_unlock();
    if (idx < 0) return 11; /* EAGAIN */
    *key = (pthread_key_t)(uintptr_t)(idx + 1);
    return 0;
}

int pthread_key_delete(pthread_key_t key)
{
    int idx = (int)(uintptr_t)key - 1;
    if (idx < 0 || idx >= SHIM_MAX_KEYS) return 22; /* EINVAL */
    shim_lock();
    g_shim_key_used[idx] = 0;
    shim_unlock();
    return 0;
}

static shim_row *shim_row_current(int create)
{
    SceUID tid = sceKernelGetThreadId();
    int freei = -1;
    for (int i = 0; i < SHIM_MAX_THREADS; i++) {
        if (g_shim_rows[i].tid == tid) return &g_shim_rows[i];
        if (freei < 0 && g_shim_rows[i].tid == 0) freei = i;
    }
    if (!create || freei < 0) return NULL;
    g_shim_rows[freei].tid = tid;
    return &g_shim_rows[freei];
}

int pthread_setspecific(pthread_key_t key, const void *value)
{
    int idx = (int)(uintptr_t)key - 1;
    if (idx < 0 || idx >= SHIM_MAX_KEYS) return 22;
    shim_lock();
    shim_row *row = shim_row_current(1);
    if (row) row->values[idx] = (void *)value;
    shim_unlock();
    return row ? 0 : 12; /* ENOMEM */
}

void *pthread_getspecific(pthread_key_t key)
{
    int idx = (int)(uintptr_t)key - 1;
    if (idx < 0 || idx >= SHIM_MAX_KEYS) return NULL;
    shim_lock();
    shim_row *row = shim_row_current(0);
    void *v = row ? row->values[idx] : NULL;
    shim_unlock();
    return v;
}

/* M20-D (2026-07-05): ALL memory acquisition is deferred off module_start.
 * Three *main boot attempts froze at/after the PS logo because module_start
 * ran at SceShell-boot+0.5s and grabbed ~36 MB out of the shell's partition
 * (32 MB newlib heap memblock + 4 MB taipool) while the shell itself was
 * still allocating its boot working set — even when module_start RETURNED
 * SUCCESS the shell starved (take-3 trace: watcher armed, c6 returned, boot
 * still froze). module_start now only spawns a tiny (64 KB) init thread and
 * returns; that thread waits until system uptime >= BOOT_GRACE before doing
 * the heavy init. Under *TVIT00010 staging (app launch, uptime >> grace)
 * the wait is zero and behavior is unchanged. */
/* Take 6: 60 s -> 30 s. Under the two-stage loader the LOAD time is what
 * gates us (loader ladder starts at 40 s), so uptime is already past this
 * grace when module_start runs and heavy init proceeds immediately —
 * grabbing the heap while the window that admitted the image is still
 * open. The grace only still matters if someone lists the fat SUPRX
 * directly under *main again (don't). */
#define BOOT_GRACE_US (30ULL * 1000 * 1000)
/* taipool retry: transient boot-time pressure gets three more chances. */
#define POOL_RETRIES     3
#define POOL_RETRY_US    (10 * 1000 * 1000)

static volatile int g_pool_inited = 0;
static volatile int g_stopping    = 0;

/* The old module_start body: taipool + newlib chain + pte shim + Rust
 * start. Runs on the deferred-init thread (or synchronously from
 * module_start only as a last-resort fallback if even the tiny thread
 * can't be created). Returns 0 on success. */
/* Take 6 preflight: before grabbing taipool + the 16 MB newlib heap out
 * of the host process's partition, check there's actually room. Inside
 * SceShell post-boot the partition can be cache-filled (take-5's
 * 0x80024302); plowing ahead would fail _init_vita_heap and abort Rust
 * alloc mid-init — inside the shell that's a crash, not a log line. A
 * failed probe (rc<0) is treated as "unknown, proceed". Under app
 * staging the app partition is roomy and this passes on try 1. */
#define BUDGET_RETRIES 6

static int budget_preflight(void)
{
    char buf[96];
    /* taipool + the newlib heap grab + 1 MB slack for thread stacks. */
    int need = (int)(TAIPOOL_BYTES + _newlib_heap_size_user
                     + 1 * 1024 * 1024);
    for (int i = 0; i <= BUDGET_RETRIES; i++) {
        SceKernelFreeMemorySizeInfo mi;
        mi.size = sizeof mi;
        int rc = sceKernelGetFreeMemorySize(&mi);
        if (rc < 0) {
            sceClibSnprintf(buf, sizeof buf,
                            "c2m: free probe failed (0x%08X); proceeding",
                            (unsigned)rc);
            trace(buf);
            return 0;
        }
        sceClibSnprintf(buf, sizeof buf,
                        "c2m: free user=%dK need=%dK (try %d)",
                        mi.size_user / 1024, need / 1024, i + 1);
        trace(buf);
        if (mi.size_user >= need) {
            return 0;
        }
        if (g_stopping) {
            return -1;
        }
        sceKernelDelayThread(POOL_RETRY_US);
    }
    return -1;
}

static int heavy_init_and_start(void)
{
    char buf[64];

    if (budget_preflight() != 0) {
        trace("c2n: budget preflight failed; heavy init aborted");
        return -1;
    }

    sceClibSnprintf(buf, sizeof buf, "c2: pre-taipool_init(%d)",
                    TAIPOOL_BYTES);
    trace(buf);

    int pool_rc = -1;
    for (int i = 0; i <= POOL_RETRIES; i++) {
        pool_rc = taipool_init(TAIPOOL_BYTES);
        sceClibSnprintf(buf, sizeof buf, "c3: taipool_init -> %d (try %d)",
                        pool_rc, i + 1);
        trace(buf);
        if (pool_rc >= 0) {
            break;
        }
        if (g_stopping) {
            return -1;
        }
        sceKernelDelayThread(POOL_RETRY_US);
    }
    if (pool_rc < 0) {
        return -1;
    }
    g_pool_inited = 1;

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
    /* M15-A3 S6 spike — full newlib C-side init so pthread-embedded's
     * internal calloc/malloc (pthread_mutex_init, pthread_mutexattr_init)
     * works. The missing _init_vita_malloc() was the std::sync::Mutex
     * crash: newlib __malloc_lock on an uninitialised LwMutex. Order
     * matches crt0 (heap, reent, malloc, io). Then create pte_selfThreadKey
     * so thread_local! can self-heal. None of this calls the crashing
     * pte_osInit / full pthread_init. */
    trace("c3a: pre-_init_vita_heap");
    _init_vita_heap();
    trace("c3b: pre-_init_vita_reent");
    _init_vita_reent();
    trace("c3c: pre-_init_vita_malloc");
    _init_vita_malloc();
    trace("c3d: pre-_init_vita_io");
    _init_vita_io();
    trace("c3e: newlib C-side init done (heap+reent+malloc+io)");
    /* Create the pthread-key shim's lock before any thread spawns. */
    pte_shim_init();
    trace("c3f: pte_shim_init done");

    trace("c4: pre-ts_vita_rt_start");
    int rust_rc = ts_vita_rt_start();
    sceClibSnprintf(buf, sizeof buf, "c5: ts_vita_rt_start -> %d",
                    rust_rc);
    trace(buf);
    if (rust_rc != 0) {
        taipool_term();
        g_pool_inited = 0;
        return -1;
    }
    trace("c6: heavy init complete");
    return 0;
}

/* Deferred-init thread entry: wait out SceShell's boot rush, then run
 * the heavy init. System uptime (µs since boot) distinguishes *main-at-
 * boot (wait the remainder of the grace window) from app-launch staging
 * or a late load (uptime past grace: init immediately). */
static int deferred_init_main(SceSize args, void *argp)
{
    (void)args;
    (void)argp;
    SceUInt64 up = sceKernelGetSystemTimeWide();
    if (up < BOOT_GRACE_US) {
        trace("d1: early boot — delaying heavy init until boot grace");
        sceKernelDelayThread((SceUInt32)(BOOT_GRACE_US - up));
    }
    if (g_stopping) {
        trace("d2: stop requested before init; aborting");
        sceKernelExitDeleteThread(0);
        return 0;
    }
    trace("d3: boot grace passed; running heavy init");
    int rc = heavy_init_and_start();
    trace(rc == 0 ? "d4: heavy init OK" : "d5: heavy init FAILED");
    sceKernelExitDeleteThread(0);
    return 0;
}

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

    trace("c1: module_start entry (deferred-init)");

    /* Nothing heavy here — see BOOT_GRACE_US comment. 64 KB stack: the
     * init chain itself is shallow; the Rust runtime gets its own 4 MB
     * bootstrap stack later. */
    SceUID thid = sceKernelCreateThread("ts-vita-init", deferred_init_main,
                                        0x60, 64 * 1024, 0, 0, NULL);
    if (thid < 0) {
        /* Can't even make a 64 KB thread: fall back to synchronous init
         * (the staging path of old). If THAT fails, fail the module. */
        trace("c1a: init-thread create failed; falling back to sync init");
        if (heavy_init_and_start() != 0) {
            return SCE_KERNEL_START_FAILED;
        }
        return SCE_KERNEL_START_SUCCESS;
    }
    if (sceKernelStartThread(thid, 0, NULL) < 0) {
        trace("c1b: init-thread start failed; falling back to sync init");
        if (heavy_init_and_start() != 0) {
            return SCE_KERNEL_START_FAILED;
        }
        return SCE_KERNEL_START_SUCCESS;
    }

    trace("c7: init thread armed; module_start returning SUCCESS");
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;

    sceClibPrintf("[ts-vita] module_stop\n");
    g_stopping = 1;
    ts_vita_rt_stop();
    if (g_pool_inited) {
        taipool_term();
    }
    return SCE_KERNEL_STOP_SUCCESS;
}
