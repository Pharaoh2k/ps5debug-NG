// SPDX-License-Identifier: GPL-3.0-only

#ifndef PORT_FLAT_DEBUG_STATE_H
#define PORT_FLAT_DEBUG_STATE_H

#include <stdint.h>

enum debug_target_phase {
    DEBUG_PHASE_DETACHED = 0,
    DEBUG_PHASE_ATTACHING,
    DEBUG_PHASE_RUNNING,
    DEBUG_PHASE_RESUMING,
    DEBUG_PHASE_PROCESSING_EVENT,
    DEBUG_PHASE_EVENT_PENDING,
    DEBUG_PHASE_EVENT_STOPPED,
    DEBUG_PHASE_STEPPING,
    DEBUG_PHASE_RPC_ACTIVE,
    DEBUG_PHASE_DETACHING,
    DEBUG_PHASE_BROKEN
};

/* Internal return used to fail remote calls without retrying when the debugger
   owns a target stop. It never appears on the wire; handlers return CMD_ERROR. */
#define PROC_RPC_ERR_DEBUG_STATE (-2)

extern uint32_t g_stopgo_mode;
extern uint32_t g_stopgo_target_pid;
extern uint32_t g_stopgo_last_signal;
extern uint32_t g_stopgo_resume_pid;
extern uint32_t g_stopgo_resume_signal;

extern volatile uint32_t g_debug_phase;
extern volatile uint32_t g_debug_pending_wait_valid;
extern uint32_t          g_debug_pending_wait_pid;
extern int32_t           g_debug_pending_wait_status;
extern void             *g_debug_arbiter_mutex;

#endif
