/* tailscale-vita-loader — two-stage boot loader (M20-D take 5/6).
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
 * So config.txt lists ONLY this stub (~5 KB) under *main.
 *
 * TAKE 6: take 5's single attempt at boot+60s failed 0x80024302 twice —
 * by 60 s SceShell's caches have eaten the partition. But the one lucky
 * boot proves the memory EXISTS early. So instead of one shot, hunt for
 * the window: a ladder of load attempts starting right as LiveArea comes
 * interactive (~40 s) and stretching to 6 min (in case pressure relaxes),
 * with sceKernelGetFreeMemorySize logged before every attempt AND at three
 * probe-only points (12/20/30 s). Even a boot where every attempt fails
 * hands us SceShell's free-memory-over-time curve — the data that decides
 * between grace tuning, image diet, and kubridge for take 7.
 *
 * Markers go to loader-trace.txt (own file — the fat module truncates
 * phase2-trace.txt on start, which used to wipe the loader's story).
 */
#include <psp2/io/fcntl.h>
#include <psp2/kernel/clib.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/types.h>

#define TARGET_MODULE "ur0:tai/tailscale-vita-plugin.suprx"
#define LTRACE_PATH   "ux0:data/tailscale-vita/loader-trace.txt"

/* Probe-only points: log free memory, don't load. ux0 is writable well
 * before this (take-1 wrote vita.log at boot+0.55 s). */
static const unsigned PROBE_AT_SEC[] = { 12, 20, 30 };

/* Load-attempt ladder. First rung ~when LiveArea turns interactive;
 * later rungs catch late cache eviction / pressure relaxing. */
static const unsigned ATTEMPT_AT_SEC[] = {
    40, 50, 62, 75, 90, 120, 180, 240, 300, 360,
};

#define N_PROBES   (sizeof PROBE_AT_SEC / sizeof PROBE_AT_SEC[0])
#define N_ATTEMPTS (sizeof ATTEMPT_AT_SEC / sizeof ATTEMPT_AT_SEC[0])

static void ltrace(const char *msg, int truncate)
{
    int flags = SCE_O_WRONLY | SCE_O_CREAT |
                (truncate ? SCE_O_TRUNC : SCE_O_APPEND);
    SceUID fd = sceIoOpen(LTRACE_PATH, flags, 0666);
    if (fd >= 0) {
        sceIoWrite(fd, msg, sceClibStrnlen(msg, 160));
        sceIoWrite(fd, "\n", 1);
        sceIoClose(fd);
    }
    sceClibPrintf("[ts-vita-loader] %s\n", msg);
}

/* Format one telemetry line: tag, uptime, free mem (KB) per pool. */
static void trace_free(const char *tag, int truncate)
{
    SceKernelFreeMemorySizeInfo mi;
    mi.size = sizeof mi;
    int rc = sceKernelGetFreeMemorySize(&mi);
    unsigned up_s =
        (unsigned)(sceKernelGetSystemTimeWide() / 1000000ULL);
    char buf[160];
    if (rc >= 0) {
        sceClibSnprintf(buf, sizeof buf,
                        "%s up=%us free_kb user=%d cdram=%d phycont=%d",
                        tag, up_s, mi.size_user / 1024, mi.size_cdram / 1024,
                        mi.size_phycont / 1024);
    } else {
        sceClibSnprintf(buf, sizeof buf,
                        "%s up=%us free probe failed (0x%08X)", tag, up_s,
                        (unsigned)rc);
    }
    ltrace(buf, truncate);
}

static void sleep_until_uptime_sec(unsigned target_sec)
{
    SceUInt64 target_us = (SceUInt64)target_sec * 1000000ULL;
    SceUInt64 up = sceKernelGetSystemTimeWide();
    if (up < target_us) {
        sceKernelDelayThread((SceUInt32)(target_us - up));
    }
}

static int loader_main(SceSize args, void *argp)
{
    (void)args;
    (void)argp;
    char buf[160];

    /* Telemetry-only probes; first one truncates = fresh file per boot. */
    for (unsigned i = 0; i < N_PROBES; i++) {
        sleep_until_uptime_sec(PROBE_AT_SEC[i]);
        trace_free("P:", i == 0);
    }

    for (unsigned i = 0; i < N_ATTEMPTS; i++) {
        sleep_until_uptime_sec(ATTEMPT_AT_SEC[i]);
        sceClibSnprintf(buf, sizeof buf, "L2: try %u", i + 1);
        trace_free(buf, 0);

        SceUID mid = sceKernelLoadStartModule(TARGET_MODULE, 0, NULL, 0,
                                              NULL, NULL);
        if (mid >= 0) {
            sceClibSnprintf(buf, sizeof buf, "L5: loaded mid=0x%08X",
                            (unsigned)mid);
            ltrace(buf, 0);
            trace_free("L5-after:", 0);
            sceKernelExitDeleteThread(0);
            return 0;
        }
        sceClibSnprintf(buf, sizeof buf, "L3: try %u failed (0x%08X)",
                        i + 1, (unsigned)mid);
        ltrace(buf, 0);
    }
    ltrace("L4: giving up; runtime not loaded this boot", 0);
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
