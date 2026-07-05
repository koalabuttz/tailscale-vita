/* tailscale-vita-loader — two-stage boot loader (M20-D take 5).
 *
 * WHY THIS EXISTS: the runtime SUPRX is ~2.3 MB in-memory (1.97 MB text —
 * rustls + h2 + boringtun + smoltcp + std). taiHEN maps *main plugins into
 * SceShell at PROCESS CREATION, i.e. while the PS logo is still up; on
 * 2026-07-05 four out of five promoted boots froze at/after the logo with
 * the fat module doing literally nothing (take-4 trace: module_start
 * returned SUCCESS, init deferred, boot froze anyway). Loading 2.3 MB into
 * the shell's partition during its own boot rush is the killer — the same
 * load performed POST-boot is proven fine (the one lucky boot ran the full
 * runtime with 31 peers for 10+ minutes).
 *
 * So config.txt lists ONLY this stub (~4 KB) under *main. It spawns a tiny
 * thread, sleeps until system uptime >= BOOT_GRACE, then loads the fat
 * SUPRX via sceKernelLoadStartModule — whose own module_start defers
 * nothing at that point (its boot-grace check sees uptime past the window
 * and inits immediately).
 *
 * Trace markers (L*) append to the shared phase2-trace file WITHOUT
 * truncating it: if the staged load fails they survive for diagnosis; if
 * it succeeds the fat module's own truncate-on-start wipes them, which is
 * fine — success is self-evident from the c-, d-, r- markers that follow.
 */
#include <psp2/io/fcntl.h>
#include <psp2/kernel/clib.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/types.h>

#define TARGET_MODULE "ur0:tai/tailscale-vita-plugin.suprx"
#define TRACE_PATH    "ux0:data/tailscale-vita/phase2-trace.txt"

/* Wait until this much system uptime (µs) before loading the fat module.
 * LiveArea is typically interactive by ~35-45 s; 60 s adds margin. */
#define BOOT_GRACE_US (60ULL * 1000 * 1000)
/* One retry if the first load fails (transient boot-tail pressure). */
#define RETRY_DELAY_US (30 * 1000 * 1000)

static void ltrace(const char *msg)
{
    SceUID fd = sceIoOpen(TRACE_PATH,
                          SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0666);
    if (fd >= 0) {
        sceIoWrite(fd, msg, sceClibStrnlen(msg, 128));
        sceIoWrite(fd, "\n", 1);
        sceIoClose(fd);
    }
    sceClibPrintf("[ts-vita-loader] %s\n", msg);
}

static int loader_main(SceSize args, void *argp)
{
    (void)args;
    (void)argp;

    SceUInt64 up = sceKernelGetSystemTimeWide();
    if (up < BOOT_GRACE_US) {
        sceKernelDelayThread((SceUInt32)(BOOT_GRACE_US - up));
    }
    ltrace("L2: boot grace passed; loading runtime module");

    for (int attempt = 0; attempt < 2; attempt++) {
        SceUID mid = sceKernelLoadStartModule(TARGET_MODULE, 0, NULL, 0,
                                              NULL, NULL);
        if (mid >= 0) {
            /* Success: the fat module's own trace takes over from here. */
            sceClibPrintf("[ts-vita-loader] loaded 0x%08X\n", (unsigned)mid);
            sceKernelExitDeleteThread(0);
            return 0;
        }
        char buf[80];
        sceClibSnprintf(buf, sizeof buf,
                        "L3: load attempt %d failed (0x%08X)", attempt + 1,
                        (unsigned)mid);
        ltrace(buf);
        sceKernelDelayThread(RETRY_DELAY_US);
    }
    ltrace("L4: giving up; runtime not loaded this boot");
    sceKernelExitDeleteThread(0);
    return 0;
}

int module_start(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;

    /* Nothing heavy, nothing blocking: one 16 KB thread, then out. */
    SceUID thid = sceKernelCreateThread("ts-vita-loader", loader_main, 0x60,
                                        16 * 1024, 0, 0, NULL);
    if (thid < 0) {
        return SCE_KERNEL_START_FAILED;
    }
    if (sceKernelStartThread(thid, 0, NULL) < 0) {
        return SCE_KERNEL_START_FAILED;
    }
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
    (void)argc;
    (void)args;
    /* The loaded runtime module has its own module_stop; taiHEN/SceShell
     * teardown handles it. Nothing to do here. */
    return SCE_KERNEL_STOP_SUCCESS;
}
