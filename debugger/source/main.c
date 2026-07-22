// SPDX-License-Identifier: GPL-3.0-only

#include "protocol.h"
#include "sdk_shim.h"
#include "net.h"
#include "version.h"

extern int  cmd_handler(int fd, struct cmd_packet *packet, unsigned char client_idx);
extern void print_ascii_banner(void);

extern void (*__init_array_start[])(void) __attribute__((weak));
extern void (*__init_array_end[])(void)   __attribute__((weak));
static void run_init_array_once(void)
{
    static int done = 0;
    if (done) return;
    done = 1;
    if (!__init_array_start) return;
    for (void (**p)(void) = __init_array_start; p < __init_array_end; ++p)
        if (*p) (*p)();
}
extern void server_state_init(void);
extern void *alloc_client(void);
extern void free_client(void *svc);
extern void turboscan_startup_cleanup(void);
extern int  dispatch_debug_events(void);
extern void *klog_server_thread(void *arg);
extern int  g_klog_listen_fd;

#include "debug_state.h"

struct server_client {
    uint32_t active;
    int      fd;
    uint32_t debugging;
    uint8_t  client_addr[16];
    uint8_t  pad_1c[4];
    uint8_t  dbgctx[0x358];
};

extern void    *curdbgcli;
extern void    *curdbgctx;
extern uint32_t g_debug_attached;
extern void    *g_server_mutex;
extern void    *g_proc_rw_mutex;
extern void    *g_debug_arbiter_mutex;

#define SERVER_PORT       744
#define SERVER_MAXCLIENTS 12
extern struct server_client g_clients[SERVER_MAXCLIENTS];

#define PACKET_MAGIC      0xFFAABBCCu

static void notify(const char *msg) {
    typedef struct { char useless1[45]; char message[3075]; } req_t;
    req_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.message, msg, sizeof(req.message) - 1);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

void configure_socket(int fd) {
    int32_t one = 1;
    setsockopt(fd, 6,      1,      &one, 4);
    one = 1;
    setsockopt(fd, 0xFFFF, 4,      &one, 4);
    one = 1;

    setsockopt(fd, 0xFFFF, 0x0800, &one, 4);
}

static int handle_client(struct server_client *svc) {
    int fd = svc->fd;
    struct timeval tv;
    fd_set sfd;

    while (1) {

        tv.tv_sec  = 0;
        tv.tv_usec = 100;
        FD_ZERO(&sfd);
        FD_SET(fd, &sfd);
        errno = 0;
        select(fd + 1, &sfd, NULL, NULL, &tv);

        if (FD_ISSET(fd, &sfd)) {
            struct cmd_packet packet;
            memset(&packet, 0, 12);

            if (net_recv_all(fd, &packet, 12, 1) < 0) return 0;
            if (errno == ECONNRESET)                  return 0;
            if (packet.magic != PACKET_MAGIC)         continue;

            packet.data = NULL;
            void *data  = NULL;

            if (packet.datalen != 0) {
                if (packet.datalen > 0x100000) {
                    net_send_int32(fd, 0xF0000002u );
                    continue;
                }
                data = malloc(packet.datalen);
                if (!data) {
                    net_send_int32(fd, CMD_DATA_NULL);
                    continue;
                }
                if (net_recv_all(fd, data, (int)packet.datalen, 1) < 0) {
                    free(data);
                    return 0;
                }
                packet.data = data;
            }

            unsigned char client_idx = (unsigned char)((svc->active - 1) & 0xFFu);

            int _needs_dbg_lock = ((packet.cmd & 0xFFFF0000u) == 0xBDBB0000u);
            if (_needs_dbg_lock) {
                scePthreadMutexLock(&g_debug_arbiter_mutex);
                scePthreadMutexLock(&g_proc_rw_mutex);
                scePthreadMutexLock(&g_server_mutex);
            }
            if (g_debug_attached == 0
                && g_debug_phase == DEBUG_PHASE_DETACHED
                && packet.cmd == CMD_DEBUG_ATTACH) {
                curdbgcli = svc;
                curdbgctx = (void *)((char *)svc + 0x20);
            }
            int rc = cmd_handler(fd, &packet, client_idx);
            if (_needs_dbg_lock) {
                scePthreadMutexUnlock(&g_server_mutex);
                scePthreadMutexUnlock(&g_proc_rw_mutex);
                scePthreadMutexUnlock(&g_debug_arbiter_mutex);
            }
            if (data) free(data);
            if (rc != 0) return rc;

            if (svc->debugging
                && (g_stopgo_resume_signal != 0xFFFFFFFFu
                    || g_debug_pending_wait_valid)) {
                scePthreadMutexLock(&g_debug_arbiter_mutex);
                scePthreadMutexLock(&g_proc_rw_mutex);
                scePthreadMutexLock(&g_server_mutex);
                int dde_rc = dispatch_debug_events();
                scePthreadMutexUnlock(&g_server_mutex);
                scePthreadMutexUnlock(&g_proc_rw_mutex);
                scePthreadMutexUnlock(&g_debug_arbiter_mutex);
                if (dde_rc != 0) return 0;
            }
            continue;
        }

        if (svc->debugging) {
            scePthreadMutexLock(&g_debug_arbiter_mutex);
            scePthreadMutexLock(&g_proc_rw_mutex);
            scePthreadMutexLock(&g_server_mutex);
            int dde_rc = dispatch_debug_events();
            scePthreadMutexUnlock(&g_server_mutex);
            scePthreadMutexUnlock(&g_proc_rw_mutex);
            scePthreadMutexUnlock(&g_debug_arbiter_mutex);
            if (dde_rc != 0) return 0;
        }
        if (errno == ECONNRESET) return 0;

        sceKernelUsleep(svc->debugging ? 250 : 10000);
    }
}

static void *client_thread_main(void *arg) {
    struct server_client *svc = (struct server_client *)arg;
    handle_client(svc);
    free_client(svc);
    return NULL;
}

struct pld_sockaddr_in {
    uint8_t  sin_len;
    uint8_t  sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t  sin_zero[8];
};

static int g_bcast_fd = -1;

static void *broadcast_thread(void *arg) {
    (void)arg;

    struct pld_sockaddr_in sa;
    sa.sin_len    = 0x10;
    sa.sin_family = 2;
    sa.sin_port   = sceNetHtons(0x3F2);
    sa.sin_addr   = 0;

    memset(&sa.sin_zero[2], 0, 6);

    g_bcast_fd = sceNetSocket((const char *)0, 2, 2, 0);
    if (g_bcast_fd < 0) return (void *)0;

    int32_t one = 1;
    sceNetSetsockopt(g_bcast_fd, 0xFFFF, 0x20, &one, 4);
    one = 1;
    sceNetSetsockopt(g_bcast_fd, 0xFFFF, 4,    &one, 4);
    one = 1;
    sceNetSetsockopt(g_bcast_fd, 6,      1,    &one, 4);

    errno = 0;
    if (sceNetBind(g_bcast_fd, &sa, 0x10) != 0) return (void *)0;

    int local_fd = g_bcast_fd;

    for (;;) {
        scePthreadYield();

        struct pld_sockaddr_in peer;
        uint32_t peer_len = 0x10;
        uint32_t magic    = 0;

        int n = sceNetRecvfrom(local_fd, &magic, 4, 0, &peer, &peer_len);
        if (n < 0) {

            int err = *sceNetErrnoLoc();
            if (err == 0xA3 || err == EBADF) return (void *)0;
        } else if (magic == 0xFFFFAAAAu) {
            sceNetSendto(local_fd, &magic, 4, 0, &peer, peer_len);
        }
        sceKernelSleep(1);
    }

}

static int start_server(void) {

    turboscan_startup_cleanup();              /* reclaim any orphaned /data snapshot files */

    {
        ScePthread bcast_tid;
        if (scePthreadCreate(&bcast_tid, NULL, broadcast_thread,
                             NULL, "ps5debug_bcast") == 0) {
            scePthreadDetach(bcast_tid);
        }
    }

    int srv = sceNetSocket((const char *)0, 2 , 1 , 0);
    if (srv < 0) {
        notify("ps5debug: sceNetSocket() failed");
        return 1;
    }

    int32_t one = 1;
    sceNetSetsockopt(srv, 0xFFFF, 4, &one, 4);
    one = 1;
    sceNetSetsockopt(srv, 6,      1, &one, 4);

    struct pld_sockaddr_in sa;
    sa.sin_len    = 0x10;
    sa.sin_family = 2;
    sa.sin_port   = sceNetHtons(SERVER_PORT);
    sa.sin_addr   = 0;

    memset(&sa.sin_zero[2], 0, 6);

    if (sceNetBind(srv, &sa, 0x10) != 0) {
        notify("ps5debug: sceNetBind(744) failed");
        sceNetSocketClose(srv);
        return 1;
    }
    if (sceNetListen(srv, 8) != 0) {
        notify("ps5debug: sceNetListen() failed");
        sceNetSocketClose(srv);
        return 1;
    }

    while (1) {
        struct pld_sockaddr_in cli;
        uint32_t cli_len = 0x10;
        int fd = sceNetAccept(srv, &cli, &cli_len);

        if (fd < 0) {
            int err = *sceNetErrnoLoc();
            if (err == 0xA3) goto teardown;
            continue;
        }
        if (fd == 0) continue;

        int32_t one_a = 1;
        sceNetSetsockopt(fd, 6, 1, &one_a, 4);
        one_a = 1;

        sceNetSetsockopt(fd, 0xFFFF, 0x0800, &one_a, 4);

        struct server_client *slot = (struct server_client *)alloc_client();
        if (!slot) {
            sceNetSocketClose(fd);
            continue;
        }
        slot->fd        = fd;
        slot->debugging = 0;
        memcpy(slot->client_addr, &cli, sizeof(cli) > 16 ? 16 : sizeof(cli));
        memset(slot->dbgctx, 0, sizeof(slot->dbgctx));

        ScePthread thr;
        if (scePthreadCreate(&thr, NULL, client_thread_main,
                             slot, "ps5debug_client") == 0) {
            scePthreadDetach(thr);
        } else {
            handle_client(slot);
            free_client(slot);
        }
    }

teardown:

    for (int i = 0; i < SERVER_MAXCLIENTS; i++) {
        if (g_clients[i].active != 0) {
            g_clients[i].active = 0;
            close(g_clients[i].fd);
        }
    }
    sceNetSocketClose(srv);
    if (g_bcast_fd >= 0) {
        sceNetSocketAbort(g_bcast_fd, 3);
        sceNetSocketClose(g_bcast_fd);

    }
    if (g_klog_listen_fd >= 0) {

        sceNetSocketAbort(g_klog_listen_fd, 3);
    }
    return 0;
}

static void debugger_server_loop(void) {
    static const char disconnect_msg[] = "ps5debug-NG disconnected.";

    uint32_t fw       = kernel_get_fw_version();
    uint16_t fw_high  = (uint16_t)(fw >> 16);
    unsigned fw_major = ((fw_high >> 12) & 0xF) * 10 + ((fw_high >> 8) & 0xF);
    unsigned fw_minor = ((fw_high >>  4) & 0xF) * 10 +  (fw_high       & 0xF);

    char loaded_msg[256];
    snprintf(loaded_msg, sizeof(loaded_msg),
             PS5DEBUG_NG_BRAND_STR " loaded!\n"
             "Firmware: %u.%02u\n"
             "Coded by OpenSourcereR\n"
             "Special thanks to\n"
             "golden, Ctn,  SiSTRo, EchoStretch, \n"
             "Sonic-Iso & Pharaoh2k!  \xE2\x9D\xA4\n",
             fw_major, fw_minor);

    char     ip_buf[16];
    uint32_t retry = 0;

    for (;;) {
        memset(ip_buf, 0, 0x10);
        net_get_ip_address(ip_buf);

        if (strlen(ip_buf) > 4) {

            {
                ScePthread klog_tid;
                if (scePthreadCreate(&klog_tid, NULL, klog_server_thread,
                                     NULL, "ps5debug_klog") == 0) {
                    scePthreadDetach(klog_tid);
                }
            }

            g_stopgo_resume_signal = 0xFFFFFFFFu;
            g_stopgo_resume_pid    = 0;

            notify(loaded_msg);

            (void)start_server();
            retry = 0;
            continue;
        }

        uint32_t next = retry + 1;
        if (retry == 0) {
            notify(disconnect_msg);
            sceKernelSleep(2);
        } else if (next > 99) {
            sceKernelSleep(1000);
        } else {
            sceKernelSleep(2);
        }
        retry = next;
    }
}

extern int hijack_mode(void);

static void *debugger_server_loop_thread(void *arg) {
    (void)arg;
    debugger_server_loop();
    return NULL;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    run_init_array_once();

    print_ascii_banner();
    server_state_init();

    if (hijack_mode()) {
        ScePthread tid;
        if (scePthreadCreate(&tid, NULL, debugger_server_loop_thread,
                             NULL, "ps5debug_main") == 0) {
            scePthreadDetach(tid);
        }
        return 0;
    }

    debugger_server_loop();
    return 0;
}
