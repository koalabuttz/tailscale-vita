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
 *
 * Phase A (PLAN-M21): before exiting, this process — with its OWN
 * sceNetInit context — poll-connects to the bgapp's TCP listener on
 * 127.0.0.1:41112 and logs an XPROC VERDICT line. That is the
 * dashboard(gdc) ↔ daemon(gdd) LocalAPI IPC question: loopback has only
 * ever been proven between two ends sharing ONE sceNet instance.
 */
#include <psp2/bgapputil.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/clib.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/net/net.h>
#include <psp2/sysmodule.h>

#include <string.h>

#define LOG_PATH   "ux0:data/tailscale-vita/bgapp-spike.log"
#define XPROC_PORT 41112

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

static char g_net_mem[64 * 1024];

/* Poll-connect to the bgapp's 127.0.0.1:41112 listener for up to 20 s
 * (the gdd needs a moment to boot and bind). Logs the decisive line:
 *   launcher: XPROC VERDICT = YES ...   cross-process loopback works
 *   launcher: XPROC VERDICT = NO  ...   fallback ladder engages
 */
static void xproc_probe(void)
{
    char buf[200];

    int rc = sceSysmoduleLoadModule(SCE_SYSMODULE_NET);
    sceClibSnprintf(buf, sizeof buf, "launcher: load NET -> 0x%08X",
                    (unsigned)rc);
    slog(buf);

    SceNetInitParam nip;
    nip.memory = g_net_mem;
    nip.size = sizeof g_net_mem;
    nip.flags = 0;
    rc = sceNetInit(&nip);
    sceClibSnprintf(buf, sizeof buf, "launcher: sceNetInit -> 0x%08X",
                    (unsigned)rc);
    slog(buf);

    int last_rc = 0;
    for (int try = 1; try <= 40; try++) {
        int s = sceNetSocket("launcher-xproc", SCE_NET_AF_INET,
                             SCE_NET_SOCK_STREAM, SCE_NET_IPPROTO_TCP);
        if (s < 0) {
            last_rc = s;
            sceKernelDelayThread(500 * 1000);
            continue;
        }
        int to = 2 * 1000 * 1000;
        sceNetSetsockopt(s, SCE_NET_SOL_SOCKET, SCE_NET_SO_RCVTIMEO, &to,
                         sizeof to);

        SceNetSockaddrIn sin;
        memset(&sin, 0, sizeof sin);
        sin.sin_len = sizeof sin;
        sin.sin_family = SCE_NET_AF_INET;
        sin.sin_port = sceNetHtons(XPROC_PORT);
        sin.sin_addr.s_addr = sceNetHtonl(0x7F000001); /* 127.0.0.1 */

        rc = sceNetConnect(s, (SceNetSockaddr *)&sin, sizeof sin);
        if (rc < 0) {
            last_rc = rc;
            sceNetSocketClose(s);
            sceKernelDelayThread(500 * 1000);
            continue;
        }

        static const char req[] =
            "GET /spike HTTP/1.1\r\nHost: localhost\r\n\r\n";
        sceNetSend(s, req, sizeof req - 1, 0);
        char resp[128];
        int n = sceNetRecv(s, resp, sizeof resp - 1, 0);
        sceNetSocketClose(s);
        if (n > 0) {
            resp[n] = '\0';
            /* keep the verdict line one-line: clip at first CR */
            char *cr = strchr(resp, '\r');
            if (cr) {
                *cr = '\0';
            }
            sceClibSnprintf(buf, sizeof buf,
                            "launcher: XPROC VERDICT = YES (try %d, "
                            "status=\"%s\")",
                            try, resp);
            slog(buf);
            return;
        }
        /* connected but no bytes back — suspicious, keep trying */
        last_rc = n;
        sceClibSnprintf(buf, sizeof buf,
                        "launcher: xproc connect ok but recv=%d (try %d)", n,
                        try);
        slog(buf);
        sceKernelDelayThread(500 * 1000);
    }
    sceClibSnprintf(buf, sizeof buf,
                    "launcher: XPROC VERDICT = NO (40 tries over 20s, "
                    "last rc=0x%08X)",
                    (unsigned)last_rc);
    slog(buf);
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

    /* Phase A: probe the bgapp's loopback listener from THIS process.
     * Run it regardless of the StartBgApp rc — if a bgapp from an
     * earlier launch is still alive, the probe still answers the
     * cross-process question. */
    xproc_probe();

    slog("launcher: exiting (bgapp should be alive now)");
    sceKernelExitProcess(0);
    return 0;
}
