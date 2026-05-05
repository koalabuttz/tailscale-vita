/*
 * tailscale-vita-plugin — Phase 1B
 *
 * SUPRX shim. C-side does the absolute minimum (mkdir, hello-world,
 * call into Rust); the real work lives in `tailscale-vita-rt` (Rust
 * staticlib, linked at build time).
 *
 * Staging: this is currently loaded under *TVIT00010 (the demo eboot's
 * TITLEID), NOT *main. Crashes affect only the demo app, not SceShell.
 * Promotion to *main happens after Rust panic isolation is proven on
 * hardware (Phase 3).
 *
 * On module_start (= demo eboot launch, while *TVIT00010-staged):
 *   1. Best-effort mkdir of ux0:data/tailscale-vita.
 *   2. Write "hello from suprx module_start\n" to suprx-hello.txt
 *      (Phase 1A marker — confirms the C side ran).
 *   3. Call ts_vita_rt_hello() from libtailscale_vita_rt.a, which
 *      writes rust-hello.txt (Phase 1B marker — confirms Rust ran).
 */

#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/clib.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/types.h>
#include <string.h>
#include <taipool.h>

#define STATE_DIR  "ux0:data/tailscale-vita"
#define HELLO_PATH STATE_DIR "/suprx-hello.txt"

/* Phase 1C heap budget. Vitacompanion gets by with 1 MB; we'll
 * eventually need 8-16 MB for the full Rust runtime (smoltcp/h2/derp
 * buffers + RustCrypto state). 4 MB is enough headroom for Phase 1C's
 * allocator-validation workload (a String + a small Vec); we'll grow
 * this in Phase 2 when the runtime actually starts.
 */
#define TAIPOOL_BYTES (4 * 1024 * 1024)

/* Defined in crates/tailscale-vita-rt/src/lib.rs. Returns 0 on
 * success, negative SCE error code on failure. */
extern int ts_vita_rt_hello(void);
/* Phase 1D: spawns a long-running Rust thread; returns the SCE thid. */
extern int ts_vita_rt_start_thread(void);

int module_start(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;

    sceClibPrintf("[ts-vita] module_start: hello from suprx\n");

    /* Best-effort mkdir; ignore EEXIST. */
    sceIoMkdir(STATE_DIR, 0777);

    SceUID fd = sceIoOpen(HELLO_PATH,
                          SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC,
                          0666);
    if (fd >= 0) {
        const char *msg = "hello from suprx module_start\n";
        sceIoWrite(fd, msg, strlen(msg));
        sceIoClose(fd);
    } else {
        sceClibPrintf("[ts-vita] sceIoOpen(%s) -> 0x%08x\n",
                      HELLO_PATH, (unsigned)fd);
    }

    /* Init taipool BEFORE calling Rust. ts_vita_rt_hello allocates
     * via Rust's #[global_allocator] which dispatches to taipool.
     * If taipool_init fails, skip the Rust call entirely so we don't
     * try to alloc against an uninitialized pool.
     */
    int pool_rc = taipool_init(TAIPOOL_BYTES);
    if (pool_rc < 0) {
        sceClibPrintf("[ts-vita] taipool_init(%d) -> %d, skipping rust\n",
                      TAIPOOL_BYTES, pool_rc);
    } else {
        sceClibPrintf("[ts-vita] taipool_init(%d) OK\n", TAIPOOL_BYTES);
        int rust_rc = ts_vita_rt_hello();
        sceClibPrintf("[ts-vita] ts_vita_rt_hello -> %d\n", rust_rc);
        int thid = ts_vita_rt_start_thread();
        sceClibPrintf("[ts-vita] ts_vita_rt_start_thread -> %d\n", thid);
    }

    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;
    sceClibPrintf("[ts-vita] module_stop\n");
    taipool_term();
    return SCE_KERNEL_STOP_SUCCESS;
}
