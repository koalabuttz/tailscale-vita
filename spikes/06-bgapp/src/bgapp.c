/* M21 spike — background service (eboot2.bin, CATEGORY gdd).
 *
 * Runs headless after the launcher exits. Proves the four properties the
 * Tailscale-daemon-as-bgapp plan needs:
 *
 *   1. SURVIVAL   — heartbeat log line every 30 s (+ a boot notification).
 *                   Survives launcher exit, LiveArea browsing, app/game
 *                   launches (test manually), screen-off.
 *   2. MEMORY     — declares a 14 MB newlib heap (BGFTP's proven value),
 *                   malloc-touches 10 MB, then ladders 1 MB memblocks to
 *                   find the partition ceiling. All logged.
 *   3. NETWORK    — inits SceNet, logs the device IP, runs a UDP echo
 *                   server on :31338 (test from a LAN host while a game
 *                   runs — that's the money shot).
 *   4. SLEEP      — ticks DISABLE_AUTO_SUSPEND each loop like BGFTP, so
 *                   the console stays awake (screen may turn off). NOTE:
 *                   the console will NOT auto-sleep while this runs; peel
 *                   the LiveArea card to stop it.
 *   5. XPROC      — Phase A of PLAN-M21: TCP listener on 127.0.0.1:41112
 *                   (exactly where LocalAPI binds). The launcher (gdc, a
 *                   SEPARATE process with its OWN sceNet context) connects
 *                   and GETs. Today LocalAPI loopback is only proven
 *                   in-process — one sceNetInit instance may short-circuit
 *                   loopback in the library without touching the kernel
 *                   stack. This proves (or kills) dashboard↔daemon IPC.
 *
 * Log: ux0:data/tailscale-vita/bgapp-spike.log (shared with launcher).
 */
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/clib.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/notificationutil.h>
#include <psp2/sysmodule.h>

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* BGFTP's proven bgapp heap size. If the gdd partition can't grant this,
 * crt0's heap init fails BEFORE main() — silent death, no log, no core
 * (round-2 signature). SPIKE_HEAP_MB=1 builds the bisect variant. */
#ifndef SPIKE_HEAP_MB
#define SPIKE_HEAP_MB 14
#endif
unsigned int _newlib_heap_size_user = SPIKE_HEAP_MB * 1024 * 1024;

#define LOG_PATH   "ux0:data/tailscale-vita/bgapp-spike.log"
#define ECHO_PORT  31338
#define XPROC_PORT 41112 /* LocalAPI's real port — bind exactly like it */

static unsigned up_s(void)
{
    return (unsigned)(sceKernelGetSystemTimeWide() / 1000000ULL);
}

static void slog(const char *fmt, ...)
{
    char line[224];
    int off = sceClibSnprintf(line, sizeof line, "[bg up=%us] ", up_s());
    va_list ap;
    va_start(ap, fmt);
    sceClibVsnprintf(line + off, sizeof line - off, fmt, ap);
    va_end(ap);

    SceUID fd = sceIoOpen(LOG_PATH, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND,
                          0666);
    if (fd >= 0) {
        sceIoWrite(fd, line, sceClibStrnlen(line, sizeof line));
        sceIoWrite(fd, "\n", 1);
        sceIoClose(fd);
    }
    sceClibPrintf("[bgapp] %s\n", line);
}

/* vitasdk binding: sceNotificationUtilSendNotification takes a UTF-16
 * text buffer that "must be 0x410 bytes". ASCII-widen into a zeroed
 * buffer of exactly that size. BGFTP (MIT, GrapheneCt) passes a zeroed
 * SceNotificationUtilSendParam struct with UTF-16 text at offset 0 —
 * byte-identical wire shape to this. Its first send happens seconds
 * after boot (from ftpvita callbacks), ours ~1 s in and fails with
 * 0x80106301 — so the retry schedule in main() tests the shell-not-
 * ready-yet theory. */
static int g_notify_ok = 0;

static int notify(const char *ascii)
{
    SceWChar16 buf[0x410 / 2];
    memset(buf, 0, sizeof buf);
    for (int i = 0; ascii[i] && i < (int)(sizeof buf / 2) - 1; i++) {
        buf[i] = (SceWChar16)(unsigned char)ascii[i];
    }
    int rc = sceNotificationUtilSendNotification(buf);
    if (rc < 0) {
        slog("notify failed: 0x%08X", (unsigned)rc);
    } else {
        g_notify_ok = 1;
    }
    return rc;
}

static void probe_memory(void)
{
    SceKernelFreeMemorySizeInfo mi;
    mi.size = sizeof mi;
    int rc = sceKernelGetFreeMemorySize(&mi);
    if (rc >= 0) {
        slog("mem: free_kb user=%d cdram=%d phycont=%d", mi.size_user / 1024,
             mi.size_cdram / 1024, mi.size_phycont / 1024);
    } else {
        slog("mem: free probe failed 0x%08X", (unsigned)rc);
    }

    void *p = malloc(10 * 1024 * 1024);
    if (p) {
        memset(p, 0xA5, 10 * 1024 * 1024);
        slog("mem: malloc+touch 10 MB on %u MB heap OK",
             _newlib_heap_size_user / (1024 * 1024));
        free(p);
    } else {
        slog("mem: malloc 10 MB FAILED (heap grant short?)");
    }

    /* How much MORE than the heap will the partition give us? */
    SceUID blocks[64];
    int n = 0;
    while (n < 64) {
        SceUID b = sceKernelAllocMemBlock("spike-probe",
                                          SCE_KERNEL_MEMBLOCK_TYPE_USER_RW,
                                          1024 * 1024, NULL);
        if (b < 0) {
            break;
        }
        blocks[n++] = b;
    }
    for (int i = 0; i < n; i++) {
        sceKernelFreeMemBlock(blocks[i]);
    }
    slog("mem: memblock ladder grabbed +%d MB beyond heap%s", n,
         n >= 64 ? " (cap hit)" : "");
}

static char g_net_mem[256 * 1024];

/* Returns the bound UDP socket, or <0. Logs the device IP. */
static int net_up(void)
{
    int rc = sceSysmoduleLoadModule(SCE_SYSMODULE_NET);
    slog("net: load module -> 0x%08X", (unsigned)rc);

    SceNetInitParam nip;
    nip.memory = g_net_mem;
    nip.size = sizeof g_net_mem;
    nip.flags = 0;
    rc = sceNetInit(&nip);
    slog("net: sceNetInit -> 0x%08X", (unsigned)rc);

    rc = sceNetCtlInit();
    slog("net: sceNetCtlInit -> 0x%08X", (unsigned)rc);

    SceNetCtlInfo info;
    memset(&info, 0, sizeof info);
    rc = sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_IP_ADDRESS, &info);
    if (rc >= 0) {
        slog("net: ip=%s", info.ip_address);
        char msg[96];
        sceClibSnprintf(msg, sizeof msg, "TS bgapp spike alive: %s:%d",
                        info.ip_address, ECHO_PORT);
        notify(msg);
    } else {
        slog("net: get ip failed 0x%08X", (unsigned)rc);
        notify("TS bgapp spike alive (no IP yet)");
    }

    int s = sceNetSocket("spike-echo", SCE_NET_AF_INET, SCE_NET_SOCK_DGRAM,
                         SCE_NET_IPPROTO_UDP);
    if (s < 0) {
        slog("net: socket failed 0x%08X", (unsigned)s);
        return s;
    }
    int timeout_us = 1 * 1000 * 1000;
    sceNetSetsockopt(s, SCE_NET_SOL_SOCKET, SCE_NET_SO_RCVTIMEO, &timeout_us,
                     sizeof timeout_us);

    SceNetSockaddrIn sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_len = sizeof sin;
    sin.sin_family = SCE_NET_AF_INET;
    sin.sin_port = sceNetHtons(ECHO_PORT);
    sin.sin_addr.s_addr = SCE_NET_INADDR_ANY;
    rc = sceNetBind(s, (SceNetSockaddr *)&sin, sizeof sin);
    slog("net: bind :%d -> 0x%08X", ECHO_PORT, (unsigned)rc);
    if (rc < 0) {
        sceNetSocketClose(s);
        return rc;
    }
    return s;
}

/* Phase A probe: non-blocking TCP listener on 127.0.0.1:41112, polled
 * from the main loop. Serves one canned HTTP response per connection.
 * Requires net_up() to have run (sceNetInit done). */
static int xproc_up(void)
{
    int s = sceNetSocket("spike-xproc", SCE_NET_AF_INET, SCE_NET_SOCK_STREAM,
                         SCE_NET_IPPROTO_TCP);
    if (s < 0) {
        slog("xproc: socket failed 0x%08X", (unsigned)s);
        return s;
    }
    int nbio = 1;
    sceNetSetsockopt(s, SCE_NET_SOL_SOCKET, SCE_NET_SO_NBIO, &nbio,
                     sizeof nbio);

    SceNetSockaddrIn sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_len = sizeof sin;
    sin.sin_family = SCE_NET_AF_INET;
    sin.sin_port = sceNetHtons(XPROC_PORT);
    sin.sin_addr.s_addr = sceNetHtonl(0x7F000001); /* 127.0.0.1, like LocalAPI */
    int rc = sceNetBind(s, (SceNetSockaddr *)&sin, sizeof sin);
    slog("xproc: bind 127.0.0.1:%d -> 0x%08X", XPROC_PORT, (unsigned)rc);
    if (rc >= 0) {
        rc = sceNetListen(s, 2);
        slog("xproc: listen -> 0x%08X", (unsigned)rc);
    }
    if (rc < 0) {
        sceNetSocketClose(s);
        return rc;
    }
    return s;
}

/* One accept-poll. Returns 1 if a client was served. */
static int xproc_poll(int lsock, unsigned *hits)
{
    SceNetSockaddrIn cli;
    unsigned clilen = sizeof cli;
    memset(&cli, 0, sizeof cli);
    int c = sceNetAccept(lsock, (SceNetSockaddr *)&cli, &clilen);
    if (c < 0) {
        return 0; /* EWOULDBLOCK — nothing pending */
    }
    /* Accepted socket: make it blocking with a short recv timeout. */
    int nbio = 0;
    sceNetSetsockopt(c, SCE_NET_SOL_SOCKET, SCE_NET_SO_NBIO, &nbio,
                     sizeof nbio);
    int to = 500 * 1000;
    sceNetSetsockopt(c, SCE_NET_SOL_SOCKET, SCE_NET_SO_RCVTIMEO, &to,
                     sizeof to);

    char req[256];
    int n = sceNetRecv(c, req, sizeof req - 1, 0);
    static const char resp[] = "HTTP/1.1 200 OK\r\nConnection: close\r\n"
                               "Content-Length: 19\r\n\r\nbgapp xproc says hi";
    sceNetSend(c, resp, sizeof resp - 1, 0);
    sceNetSocketClose(c);
    (*hits)++;
    slog("xproc: served hit #%u (%d bytes req, peer=0x%08X)", *hits, n,
         (unsigned)sceNetNtohl(cli.sin_addr.s_addr));
    return 1;
}

int main(void)
{
    sceIoMkdir("ux0:data", 0777);
    sceIoMkdir("ux0:data/tailscale-vita", 0777);
    slog("bgapp: ALIVE (gdd process started, heap=%uMB)", SPIKE_HEAP_MB);

    int rc = sceSysmoduleLoadModule(SCE_SYSMODULE_NOTIFICATION_UTIL);
    slog("bgapp: load NOTIFICATION_UTIL -> 0x%08X", (unsigned)rc);
    rc = sceNotificationUtilBgAppInitialize();
    slog("bgapp: NotificationUtilBgAppInitialize -> 0x%08X", (unsigned)rc);

    probe_memory();
    int sock = net_up();
    int xsock = xproc_up();

    unsigned echoes = 0;
    unsigned xhits = 0;
    unsigned last_beat = 0;
    unsigned notify_tries = 1; /* net_up already sent one */
    char pkt[512];

    for (;;) {
        /* BGFTP's stay-alive: cancel the auto-suspend timer every loop.
         * The console will not sleep while the bgapp runs. */
        sceKernelPowerTick(SCE_KERNEL_POWER_TICK_DISABLE_AUTO_SUSPEND);

        if (sock >= 0) {
            SceNetSockaddrIn from;
            unsigned fromlen = sizeof from;
            memset(&from, 0, sizeof from);
            int n = sceNetRecvfrom(sock, pkt, sizeof pkt - 1, 0,
                                   (SceNetSockaddr *)&from, &fromlen);
            if (n > 0) {
                echoes++;
                char reply[128];
                int rl = sceClibSnprintf(reply, sizeof reply,
                                         "bgapp up=%us echoes=%u\n", up_s(),
                                         echoes);
                sceNetSendto(sock, reply, rl, 0, (SceNetSockaddr *)&from,
                             fromlen);
                slog("echo #%u (%d bytes in)", echoes, n);
            }
        } else {
            sceKernelDelayThread(1 * 1000 * 1000);
        }

        if (xsock >= 0) {
            while (xproc_poll(xsock, &xhits)) {
            }
        }

        unsigned now = up_s();
        if (now - last_beat >= 30) {
            last_beat = now;
            slog("heartbeat echoes=%u xhits=%u", echoes, xhits);
            /* 0x80106301 timing experiment: retry the boot notification
             * on heartbeats until one lands (max 5 attempts). */
            if (!g_notify_ok && notify_tries < 5) {
                notify_tries++;
                char msg[64];
                sceClibSnprintf(msg, sizeof msg,
                                "TS bgapp spike retry #%u", notify_tries);
                int nrc = notify(msg);
                slog("notify retry #%u -> 0x%08X", notify_tries,
                     (unsigned)nrc);
            }
        }
    }

    return 0; /* unreachable */
}
