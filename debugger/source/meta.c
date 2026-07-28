// SPDX-License-Identifier: GPL-3.0-only

#include "protocol.h"
#include "sdk_shim.h"
#include "net.h"
#include "proc.h"
#include "debug_state.h"
#include "version.h"

extern int kern_handle(int fd, struct cmd_packet *packet);
extern int console_handle(int fd, struct cmd_packet *packet);
__attribute__((weak)) int debug_handle(int fd, struct cmd_packet *packet);

__attribute__((weak)) int  dispatch_debug_events(void) { return 0; }
__attribute__((weak)) void debug_full_teardown(void *dbgctx) { (void)dbgctx; }

int handle_version(int fd, struct cmd_packet *packet) {
    (void)packet;
    char     ver[] = "1.3";
    uint32_t len   = (uint32_t)(sizeof(ver) - 1);
    net_send_all(fd, &len, sizeof(uint32_t));
    net_send_all(fd, ver, (int)len);
    return 0;
}

int handle_branding(int fd, struct cmd_packet *packet) {
    (void)packet;
    /* Capability 1.1 adds content-verified process writes. */
    static const char brand[] = PS5DEBUG_NG_BRAND_STR "\0" "1.1";
    uint32_t len = (uint32_t)(sizeof(brand) - 1);
    net_send_all(fd, &len, sizeof(uint32_t));
    net_send_all(fd, brand, (int)len);
    return 0;
}

int handle_platform_id(int fd, struct cmd_packet *packet) {
    (void)packet;
    uint16_t v = 5;
    net_send_all(fd, &v, 2);
    return 0;
}

int handle_fw_version(int fd, struct cmd_packet *packet) {
    (void)packet;
    uint32_t fw      = kernel_get_fw_version();
    uint16_t fw_high = (uint16_t)(fw >> 16);
    uint16_t fw_dec  = (uint16_t)(((fw_high >> 12) & 0xF) * 1000
                                + ((fw_high >>  8) & 0xF) *  100
                                + ((fw_high >>  4) & 0xF) *   10
                                +  (fw_high        & 0xF));
    net_send_all(fd, &fw_dec, 2);
    return 0;
}

int cmd_handler(int fd, struct cmd_packet *packet, unsigned char client_idx) {
    uint32_t cmd = packet->cmd;

    if (!VALID_CMD(cmd)) return 1;

    switch (cmd) {
        case CMD_VERSION:     return handle_version(fd, packet);
        case CMD_FW_VERSION:  return handle_fw_version(fd, packet);
        case CMD_BRANDING:    return handle_branding(fd, packet);
        case CMD_PLATFORM_ID: return handle_platform_id(fd, packet);
        case CMD_PROC_NOP:    net_send_int32(fd, CMD_SUCCESS); return 0;
    }

    if (VALID_PROC_CMD(cmd))    return proc_handle(fd, packet, client_idx);
    if (VALID_DEBUG_CMD(cmd) && debug_handle) return debug_handle(fd, packet);
    if (VALID_KERN_CMD(cmd))    return kern_handle(fd, packet);
    if (VALID_CONSOLE_CMD(cmd)) return console_handle(fd, packet);

    return 0;
}

#define SERVER_PORT          744
#define SERVER_MAXCLIENTS    12
#define SERVER_CLIENT_STRIDE 0x378

struct server_client {
    uint32_t active;
    int      fd;
    uint32_t debugging;
    uint8_t  client_addr[16];
    uint8_t  pad_1c[4];
    uint8_t  dbgctx[0x358];
};

struct server_client g_clients[SERVER_MAXCLIENTS];

void    *curdbgcli       = NULL;
void    *curdbgctx       = NULL;
uint32_t g_debug_attached = 0;
void    *g_server_mutex  = NULL;
void    *g_proc_rw_mutex = NULL;
void    *g_debug_arbiter_mutex = NULL;
void    *kr_fast_mutex   = NULL;

uint32_t g_stopgo_mode          = 0;
uint32_t g_stopgo_target_pid    = 0;
uint32_t g_stopgo_last_signal   = 0xFFFFFFFFu;
uint32_t g_stopgo_resume_pid    = 0;
uint32_t g_stopgo_resume_signal = 0xFFFFFFFFu;

volatile uint32_t g_debug_phase              = DEBUG_PHASE_DETACHED;
volatile uint32_t g_debug_pending_wait_valid = 0;
uint32_t          g_debug_pending_wait_pid   = 0;
int32_t           g_debug_pending_wait_status = 0;

void server_state_init(void) {
    if (g_proc_rw_mutex == NULL) {
        scePthreadMutexInit(&g_proc_rw_mutex, NULL, "ps5d_procrw");
    }
    if (g_server_mutex == NULL) {
        scePthreadMutexInit(&g_server_mutex, NULL, "ps5d_server");
    }
    if (g_debug_arbiter_mutex == NULL) {
        scePthreadMutexInit(&g_debug_arbiter_mutex, NULL, "ps5d_debug_arbiter");
    }
    if (kr_fast_mutex == NULL) {
        scePthreadMutexInit(&kr_fast_mutex, NULL, "ps5d_krfast");
    }
    memset(g_clients, 0, sizeof(g_clients));
    g_debug_attached       = 0;
    g_stopgo_resume_signal = 0xFFFFFFFFu;
    g_stopgo_resume_pid    = 0;
    g_stopgo_last_signal   = 0xFFFFFFFFu;
    g_stopgo_target_pid    = 0;
    g_stopgo_mode          = 0;
    g_debug_phase          = DEBUG_PHASE_DETACHED;
    g_debug_pending_wait_valid = 0;
    g_debug_pending_wait_pid   = 0;
    g_debug_pending_wait_status = 0;
    curdbgcli              = NULL;
    curdbgctx              = NULL;
}

void *alloc_client(void) {
    for (int idx = 0; idx < SERVER_MAXCLIENTS; idx++) {
        if (g_clients[idx].active == 0) {
            g_clients[idx].active = (uint32_t)(idx + 1);
            return &g_clients[idx];
        }
    }
    return NULL;
}

void free_client(void *svc_) {
    struct server_client *svc = (struct server_client *)svc_;

    // free any server-resident turbo-scan session + persistent aliasing arena for this
    // connection (leak/UAF guard)
    long slot = svc - g_clients;
    if (slot >= 0 && slot < SERVER_MAXCLIENTS) {
        turboscan_session_free_idx((unsigned char)slot);
        turboscan_alias_free_idx((unsigned char)slot);
    }

    svc->active = 0;

    close(svc->fd);
    if (svc->debugging != 0) {
        scePthreadMutexLock(&g_debug_arbiter_mutex);
        debug_full_teardown(svc->dbgctx);
        scePthreadMutexUnlock(&g_debug_arbiter_mutex);
    }
    memset(svc, 0, SERVER_CLIENT_STRIDE);
}
