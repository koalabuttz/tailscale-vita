/* M21 spike — bgapp launcher (eboot.bin, CATEGORY gdc).
 *
 * The visible app: its only job is to start the background application
 * (eboot2.bin in this same package) via SceBgAppUtil, log the result,
 * and exit. The LiveArea card stays open after exit — the bgapp lives
 * until that card is peeled off (or an enlarged-memory game launches).
 *
 * Convention learned from BGFTP v3.24 (MIT, GrapheneCt): one VPK holds
 * eboot.bin + sce_sys/param.sfo (gdc) AND eboot2.bin +
 * sce_sys/param2.sfo (gdd, own TITLE_ID, INSTALL_DIR_* pointing back at
 * the launcher's TITLE_ID). sceBgAppUtilStartBgApp launches eboot2.bin.
 * BGFTP passes mode=0; vitasdk's header says "must be 1" — we try 0
 * first and fall back to 1, logging both, so the spike also settles
 * that discrepancy.
 */
#include <psp2/bgapputil.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/clib.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/sysmodule.h>

#define LOG_PATH "ux0:data/tailscale-vita/bgapp-spike.log"

static void slog(const char *msg)
{
    SceUID fd = sceIoOpen(LOG_PATH, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND,
                          0666);
    if (fd >= 0) {
        sceIoWrite(fd, msg, sceClibStrnlen(msg, 160));
        sceIoWrite(fd, "\n", 1);
        sceIoClose(fd);
    }
    sceClibPrintf("[bgapp-launcher] %s\n", msg);
}

int main(void)
{
    char buf[160];

    sceIoMkdir("ux0:data", 0777);
    sceIoMkdir("ux0:data/tailscale-vita", 0777);
    slog("launcher: start");

    int mrc = sceSysmoduleLoadModule(SCE_SYSMODULE_BG_APP_UTIL);
    sceClibSnprintf(buf, sizeof buf, "launcher: load BG_APP_UTIL -> 0x%08X",
                    (unsigned)mrc);
    slog(buf);

    int rc = sceBgAppUtilStartBgApp(0);
    sceClibSnprintf(buf, sizeof buf, "launcher: StartBgApp(0) -> 0x%08X",
                    (unsigned)rc);
    slog(buf);
    if (rc < 0) {
        rc = sceBgAppUtilStartBgApp(1);
        sceClibSnprintf(buf, sizeof buf, "launcher: StartBgApp(1) -> 0x%08X",
                        (unsigned)rc);
        slog(buf);
    }

    /* Give the shell a beat to spawn the bg process before we exit. */
    sceKernelDelayThread(2 * 1000 * 1000);
    slog("launcher: exiting (bgapp should be alive now)");
    sceKernelExitProcess(0);
    return 0;
}
