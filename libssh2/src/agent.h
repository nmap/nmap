#ifndef __LIBSSH2_AGENT_H
#define __LIBSSH2_AGENT_H
/*
 * Copyright (c) 2009 by Daiki Ueno
 * Copyright (C) 2010-2014 by Daniel Stenberg
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#include "libssh2_priv.h"
#include "misc.h"
#include "session.h"
#ifdef WIN32
#include <stdlib.h>
#endif

/* non-blocking mode on agent connection is not yet implemented, but
   for future use. */
typedef enum {
    agent_NB_state_init = 0,
    agent_NB_state_request_created,
    agent_NB_state_request_length_sent,
    agent_NB_state_request_sent,
    agent_NB_state_response_length_received,
    agent_NB_state_response_received
} agent_nonblocking_states;

typedef struct agent_transaction_ctx {
    unsigned char *request;
    size_t request_len;
    unsigned char *response;
    size_t response_len;
    agent_nonblocking_states state;
    size_t send_recv_total;
} *agent_transaction_ctx_t;

typedef int (*agent_connect_func)(LIBSSH2_AGENT *agent);
typedef int (*agent_transact_func)(LIBSSH2_AGENT *agent,
                                   agent_transaction_ctx_t transctx);
typedef int (*agent_disconnect_func)(LIBSSH2_AGENT *agent);

struct agent_publickey {
    struct list_node node;

    /* this is the struct we expose externally */
    struct libssh2_agent_publickey external;
};

struct agent_ops {
    agent_connect_func connect;
    agent_transact_func transact;
    agent_disconnect_func disconnect;
};

struct _LIBSSH2_AGENT
{
    LIBSSH2_SESSION *session;  /* the session this "belongs to" */

    libssh2_socket_t fd;

    struct agent_ops *ops;

    struct agent_transaction_ctx transctx;
    struct agent_publickey *identity;
    struct list_head head;              /* list of public keys */

    char *identity_agent_path; /* Path to a custom identity agent socket */

#ifdef WIN32
    OVERLAPPED overlapped;
    HANDLE pipe;
    BOOL pending_io;
#endif
};

#ifdef WIN32
extern struct agent_ops agent_ops_openssh;
#endif

#endif /* __LIBSSH2_AGENT_H */
