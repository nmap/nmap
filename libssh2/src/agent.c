/*
 * Copyright (C) Daiki Ueno
 * Copyright (C) Daniel Stenberg
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
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libssh2_priv.h"

#include <errno.h>
#include <stdlib.h>  /* for getenv() */

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#else
/* Use the existence of sys/un.h as a test if Unix domain socket is
   supported.  winsock*.h define PF_UNIX/AF_UNIX but do not actually
   support them. */
#undef PF_UNIX
#endif

#if defined(_WIN32) && !defined(LIBSSH2_WINDOWS_UWP)
#define HAVE_WIN32_AGENTS
#endif

#include "userauth.h"
#include "session.h"

#if 0
/* Requests from client to agent for protocol 1 key operations */
#define SSH_AGENTC_REQUEST_RSA_IDENTITIES 1
#define SSH_AGENTC_RSA_CHALLENGE 3
#define SSH_AGENTC_ADD_RSA_IDENTITY 7
#define SSH_AGENTC_REMOVE_RSA_IDENTITY 8
#define SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES 9
#define SSH_AGENTC_ADD_RSA_ID_CONSTRAINED 24
#endif

/* Requests from client to agent for protocol 2 key operations */
#define SSH2_AGENTC_REQUEST_IDENTITIES 11
#define SSH2_AGENTC_SIGN_REQUEST 13
#if 0
#define SSH2_AGENTC_ADD_IDENTITY 17
#define SSH2_AGENTC_REMOVE_IDENTITY 18
#define SSH2_AGENTC_REMOVE_ALL_IDENTITIES 19
#define SSH2_AGENTC_ADD_ID_CONSTRAINED 25

/* Key-type independent requests from client to agent */
#define SSH_AGENTC_ADD_SMARTCARD_KEY 20
#define SSH_AGENTC_REMOVE_SMARTCARD_KEY 21
#define SSH_AGENTC_LOCK 22
#define SSH_AGENTC_UNLOCK 23
#define SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED 26

/* Generic replies from agent to client */
#define SSH_AGENT_FAILURE 5
#define SSH_AGENT_SUCCESS 6

/* Replies from agent to client for protocol 1 key operations */
#define SSH_AGENT_RSA_IDENTITIES_ANSWER 2
#define SSH_AGENT_RSA_RESPONSE 4

/* Key constraint identifiers */
#define SSH_AGENT_CONSTRAIN_LIFETIME 1
#define SSH_AGENT_CONSTRAIN_CONFIRM 2
#endif

/* Replies from agent to client for protocol 2 key operations */
#define SSH2_AGENT_IDENTITIES_ANSWER 12
#define SSH2_AGENT_SIGN_RESPONSE 14

/* Signature request methods */
#define SSH_AGENT_RSA_SHA2_256 2
#define SSH_AGENT_RSA_SHA2_512 4

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
    const agent_connect_func connect;
    const agent_transact_func transact;
    const agent_disconnect_func disconnect;
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

#ifdef HAVE_WIN32_AGENTS
    OVERLAPPED overlapped;
    HANDLE pipe;
    BOOL pending_io;
#endif
};

#include "agent_win.c"

#ifdef PF_UNIX
static int
agent_connect_unix(LIBSSH2_AGENT *agent)
{
    const char *path;
    struct sockaddr_un s_un;

    path = agent->identity_agent_path;
    if(!path) {
        path = getenv("SSH_AUTH_SOCK");
        if(!path)
            return _libssh2_error(agent->session, LIBSSH2_ERROR_BAD_USE,
                                  "no auth sock variable");
    }

    agent->fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if(agent->fd < 0)
        return _libssh2_error(agent->session, LIBSSH2_ERROR_BAD_SOCKET,
                              "failed creating socket");

    s_un.sun_family = AF_UNIX;
    strncpy(s_un.sun_path, path, sizeof(s_un.sun_path));
    s_un.sun_path[sizeof(s_un.sun_path)-1] = 0; /* make sure there's a trailing
                                                   zero */
    if(connect(agent->fd, (struct sockaddr*)(&s_un), sizeof(s_un)) != 0) {
        close(agent->fd);
        return _libssh2_error(agent->session, LIBSSH2_ERROR_AGENT_PROTOCOL,
                              "failed connecting with agent");
    }

    return LIBSSH2_ERROR_NONE;
}

#define RECV_SEND_ALL(func, socket, buffer, length, flags, abstract) \
    do {                                                             \
        size_t finished = 0;                                         \
                                                                     \
        while(finished < length) {                                   \
            ssize_t rc;                                              \
            rc = func(socket,                                        \
                      (char *)buffer + finished, length - finished,  \
                      flags, abstract);                              \
            if(rc < 0)                                               \
                return rc;                                           \
                                                                     \
            finished += rc;                                          \
        }                                                            \
                                                                     \
        return finished;                                             \
    } while(0)

static ssize_t _send_all(LIBSSH2_SEND_FUNC(func), libssh2_socket_t socket,
                         const void *buffer, size_t length,
                         int flags, void **abstract)
{
    RECV_SEND_ALL(func, socket, buffer, length, flags, abstract);
}

static ssize_t _recv_all(LIBSSH2_RECV_FUNC(func), libssh2_socket_t socket,
                         void *buffer, size_t length,
                         int flags, void **abstract)
{
    RECV_SEND_ALL(func, socket, buffer, length, flags, abstract);
}

#undef RECV_SEND_ALL

static int
agent_transact_unix(LIBSSH2_AGENT *agent, agent_transaction_ctx_t transctx)
{
    unsigned char buf[4];
    int rc;

    /* Send the length of the request */
    if(transctx->state == agent_NB_state_request_created) {
        _libssh2_htonu32(buf, (uint32_t)transctx->request_len);
        rc = (int)_send_all(agent->session->send, agent->fd,
                            buf, sizeof(buf), 0,
                            &agent->session->abstract);
        if(rc == -EAGAIN)
            return LIBSSH2_ERROR_EAGAIN;
        else if(rc < 0)
            return _libssh2_error(agent->session, LIBSSH2_ERROR_SOCKET_SEND,
                                  "agent send failed");
        transctx->state = agent_NB_state_request_length_sent;
    }

    /* Send the request body */
    if(transctx->state == agent_NB_state_request_length_sent) {
        rc = (int)_send_all(agent->session->send, agent->fd,
                            transctx->request, transctx->request_len, 0,
                            &agent->session->abstract);
        if(rc == -EAGAIN)
            return LIBSSH2_ERROR_EAGAIN;
        else if(rc < 0)
            return _libssh2_error(agent->session, LIBSSH2_ERROR_SOCKET_SEND,
                                  "agent send failed");
        transctx->state = agent_NB_state_request_sent;
    }

    /* Receive the length of a response */
    if(transctx->state == agent_NB_state_request_sent) {
        rc = (int)_recv_all(agent->session->recv, agent->fd,
                            buf, sizeof(buf), 0,
                            &agent->session->abstract);
        if(rc < 0) {
            if(rc == -EAGAIN)
                return LIBSSH2_ERROR_EAGAIN;
            return _libssh2_error(agent->session, LIBSSH2_ERROR_SOCKET_RECV,
                                  "agent recv failed");
        }
        transctx->response_len = _libssh2_ntohu32(buf);
        transctx->response = LIBSSH2_ALLOC(agent->session,
                                           transctx->response_len);
        if(!transctx->response)
            return LIBSSH2_ERROR_ALLOC;

        transctx->state = agent_NB_state_response_length_received;
    }

    /* Receive the response body */
    if(transctx->state == agent_NB_state_response_length_received) {
        rc = (int)_recv_all(agent->session->recv, agent->fd,
                            transctx->response, transctx->response_len, 0,
                            &agent->session->abstract);
        if(rc < 0) {
            if(rc == -EAGAIN)
                return LIBSSH2_ERROR_EAGAIN;
            return _libssh2_error(agent->session, LIBSSH2_ERROR_SOCKET_SEND,
                                  "agent recv failed");
        }
        transctx->state = agent_NB_state_response_received;
    }

    return 0;
}

static int
agent_disconnect_unix(LIBSSH2_AGENT *agent)
{
    int ret;
    ret = close(agent->fd);
    if(ret != -1)
        agent->fd = LIBSSH2_INVALID_SOCKET;
    else
        return _libssh2_error(agent->session, LIBSSH2_ERROR_SOCKET_DISCONNECT,
                              "failed closing the agent socket");
    return LIBSSH2_ERROR_NONE;
}

static struct agent_ops agent_ops_unix = {
    agent_connect_unix,
    agent_transact_unix,
    agent_disconnect_unix
};
#endif  /* PF_UNIX */

#ifdef HAVE_WIN32_AGENTS
/* Code to talk to Pageant was taken from PuTTY.
 *
 * Portions copyright Robert de Bath, Joris van Rantwijk, Delian
 * Delchev, Andreas Schultz, Jeroen Massar, Wez Furlong, Nicolas
 * Barry, Justin Bradford, Ben Harris, Malcolm Smith, Ahmad Khalifa,
 * Markus Kuhn, Colin Watson, and CORE SDI S.A.
 */
#define PAGEANT_COPYDATA_ID 0x804e50ba   /* random goop */
#define PAGEANT_MAX_MSGLEN  8192

static int
agent_connect_pageant(LIBSSH2_AGENT *agent)
{
    HWND hwnd;
    hwnd = FindWindowA("Pageant", "Pageant");
    if(!hwnd)
        return _libssh2_error(agent->session, LIBSSH2_ERROR_AGENT_PROTOCOL,
                              "failed connecting agent");
    agent->fd = 0;         /* Mark as the connection has been established */
    return LIBSSH2_ERROR_NONE;
}

static int
agent_transact_pageant(LIBSSH2_AGENT *agent, agent_transaction_ctx_t transctx)
{
    HWND hwnd;
    char mapname[23];
    HANDLE filemap;
    unsigned char *p;
    unsigned char *p2;
    LRESULT id;
    COPYDATASTRUCT cds;

    if(!transctx || 4 + transctx->request_len > PAGEANT_MAX_MSGLEN)
        return _libssh2_error(agent->session, LIBSSH2_ERROR_INVAL,
                              "illegal input");

    hwnd = FindWindowA("Pageant", "Pageant");
    if(!hwnd)
        return _libssh2_error(agent->session, LIBSSH2_ERROR_AGENT_PROTOCOL,
                              "found no pageant");

    snprintf(mapname, sizeof(mapname),
             "PageantRequest%08x", (unsigned)GetCurrentThreadId());
    filemap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                 0, PAGEANT_MAX_MSGLEN, mapname);

    if(!filemap || filemap == INVALID_HANDLE_VALUE)
        return _libssh2_error(agent->session, LIBSSH2_ERROR_AGENT_PROTOCOL,
                              "failed setting up pageant filemap");

    p2 = p = MapViewOfFile(filemap, FILE_MAP_WRITE, 0, 0, 0);
    if(!p || !p2) {
        CloseHandle(filemap);
        return _libssh2_error(agent->session, LIBSSH2_ERROR_AGENT_PROTOCOL,
                              "failed to open pageant filemap for writing");
    }

    _libssh2_store_str(&p2, (const char *)transctx->request,
                       transctx->request_len);

    cds.dwData = PAGEANT_COPYDATA_ID;
    cds.cbData = (DWORD)(1 + strlen(mapname));
    cds.lpData = mapname;

    id = SendMessage(hwnd, WM_COPYDATA, (WPARAM) NULL, (LPARAM) &cds);
    if(id > 0) {
        transctx->response_len = _libssh2_ntohu32(p);
        if(transctx->response_len > PAGEANT_MAX_MSGLEN) {
            UnmapViewOfFile(p);
            CloseHandle(filemap);
            return _libssh2_error(agent->session, LIBSSH2_ERROR_AGENT_PROTOCOL,
                                  "agent setup fail");
        }
        transctx->response = LIBSSH2_ALLOC(agent->session,
                                           transctx->response_len);
        if(!transctx->response) {
            UnmapViewOfFile(p);
            CloseHandle(filemap);
            return _libssh2_error(agent->session, LIBSSH2_ERROR_ALLOC,
                                  "agent malloc");
        }
        memcpy(transctx->response, p + 4, transctx->response_len);
    }

    UnmapViewOfFile(p);
    CloseHandle(filemap);
    return 0;
}

static int
agent_disconnect_pageant(LIBSSH2_AGENT *agent)
{
    agent->fd = LIBSSH2_INVALID_SOCKET;
    return 0;
}

static struct agent_ops agent_ops_pageant = {
    agent_connect_pageant,
    agent_transact_pageant,
    agent_disconnect_pageant
};
#endif /* HAVE_WIN32_AGENTS */

static struct {
    const char *name;
    struct agent_ops *ops;
} supported_backends[] = {
#ifdef HAVE_WIN32_AGENTS
    {"Pageant", &agent_ops_pageant},
    {"OpenSSH", &agent_ops_openssh},
#endif /* HAVE_WIN32_AGENTS */
#ifdef PF_UNIX
    {"Unix", &agent_ops_unix},
#endif  /* PF_UNIX */
    {NULL, NULL}
};

static int
agent_sign(LIBSSH2_SESSION *session, unsigned char **sig, size_t *sig_len,
           const unsigned char *data, size_t data_len, void **abstract)
{
    LIBSSH2_AGENT *agent = (LIBSSH2_AGENT *) (*abstract);
    agent_transaction_ctx_t transctx = &agent->transctx;
    struct agent_publickey *identity = agent->identity;
    ssize_t len = 1 + 4 + identity->external.blob_len + 4 + data_len + 4;
    ssize_t method_len;
    unsigned char *s;
    int rc;
    unsigned char *method_name = NULL;
    uint32_t sign_flags = 0;
    ssize_t plain_len;

    /* Create a request to sign the data */
    if(transctx->state == agent_NB_state_init) {
        s = transctx->request = LIBSSH2_ALLOC(session, len);
        if(!transctx->request)
            return _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                                  "out of memory");

        *s++ = SSH2_AGENTC_SIGN_REQUEST;
        /* key blob */
        _libssh2_store_str(&s, (const char *)identity->external.blob,
                           identity->external.blob_len);
        /* data */
        _libssh2_store_str(&s, (const char *)data, data_len);

        /* flags */
        if(session->userauth_pblc_method_len > 0 &&
            session->userauth_pblc_method) {
            if(session->userauth_pblc_method_len == 12 &&
                !memcmp(session->userauth_pblc_method, "rsa-sha2-512", 12)) {
                sign_flags = SSH_AGENT_RSA_SHA2_512;
            }
            else if(session->userauth_pblc_method_len == 12 &&
                !memcmp(session->userauth_pblc_method, "rsa-sha2-256", 12)) {
                sign_flags = SSH_AGENT_RSA_SHA2_256;
            }
        }
        _libssh2_store_u32(&s, sign_flags);

        transctx->request_len = s - transctx->request;
        transctx->send_recv_total = 0;
        transctx->state = agent_NB_state_request_created;
    }

    /* Make sure to be re-called as a result of EAGAIN. */
    if(*transctx->request != SSH2_AGENTC_SIGN_REQUEST)
        return _libssh2_error(session, LIBSSH2_ERROR_BAD_USE,
                              "illegal request");

    if(!agent->ops)
        /* if no agent has been connected, bail out */
        return _libssh2_error(session, LIBSSH2_ERROR_BAD_USE,
                              "agent not connected");

    rc = agent->ops->transact(agent, transctx);
    if(rc) {
        goto error;
    }
    LIBSSH2_FREE(session, transctx->request);
    transctx->request = NULL;

    len = transctx->response_len;
    s = transctx->response;
    len--;
    if(len < 0) {
        rc = LIBSSH2_ERROR_AGENT_PROTOCOL;
        goto error;
    }
    if(*s != SSH2_AGENT_SIGN_RESPONSE) {
        rc = LIBSSH2_ERROR_AGENT_PROTOCOL;
        goto error;
    }
    s++;

    /* Skip the entire length of the signature */
    len -= 4;
    if(len < 0) {
        rc = LIBSSH2_ERROR_AGENT_PROTOCOL;
        goto error;
    }
    s += 4;

    /* Skip signing method */
    len -= 4;
    if(len < 0) {
        rc = LIBSSH2_ERROR_AGENT_PROTOCOL;
        goto error;
    }
    method_len = _libssh2_ntohu32(s);
    s += 4;
    len -= method_len;
    if(len < 0) {
        rc = LIBSSH2_ERROR_AGENT_PROTOCOL;
        goto error;
    }

    /* method name */
    method_name = LIBSSH2_ALLOC(session, method_len);
    if(!method_name) {
        rc = LIBSSH2_ERROR_ALLOC;
        goto error;
    }
    memcpy(method_name, s, method_len);
    s += method_len;

    plain_len = plain_method((char *)session->userauth_pblc_method,
                             session->userauth_pblc_method_len);

    /* check to see if we match requested */
    if(((size_t)method_len != session->userauth_pblc_method_len &&
        method_len != plain_len) ||
       memcmp(method_name, session->userauth_pblc_method, method_len)) {
        _libssh2_debug((session,
                       LIBSSH2_TRACE_KEX,
                       "Agent sign method %.*s",
                       (int)method_len, method_name));

        rc = LIBSSH2_ERROR_ALGO_UNSUPPORTED;
        goto error;
    }

    /* Read the signature */
    len -= 4;
    if(len < 0) {
        rc = LIBSSH2_ERROR_AGENT_PROTOCOL;
        goto error;
    }
    *sig_len = _libssh2_ntohu32(s);
    s += 4;
    len -= *sig_len;
    if(len < 0) {
        rc = LIBSSH2_ERROR_AGENT_PROTOCOL;
        goto error;
    }

    *sig = LIBSSH2_ALLOC(session, *sig_len);
    if(!*sig) {
        rc = LIBSSH2_ERROR_ALLOC;
        goto error;
    }
    memcpy(*sig, s, *sig_len);

error:

    if(method_name)
        LIBSSH2_FREE(session, method_name);

    LIBSSH2_FREE(session, transctx->request);
    transctx->request = NULL;

    LIBSSH2_FREE(session, transctx->response);
    transctx->response = NULL;

    transctx->state = agent_NB_state_init;

    return _libssh2_error(session, rc, "agent sign failure");
}

static int
agent_list_identities(LIBSSH2_AGENT *agent)
{
    agent_transaction_ctx_t transctx = &agent->transctx;
    ssize_t len, num_identities;
    unsigned char *s;
    int rc;
    unsigned char c = SSH2_AGENTC_REQUEST_IDENTITIES;

    /* Create a request to list identities */
    if(transctx->state == agent_NB_state_init) {
        transctx->request = &c;
        transctx->request_len = 1;
        transctx->send_recv_total = 0;
        transctx->state = agent_NB_state_request_created;
    }

    /* Make sure to be re-called as a result of EAGAIN. */
    if(*transctx->request != SSH2_AGENTC_REQUEST_IDENTITIES)
        return _libssh2_error(agent->session, LIBSSH2_ERROR_BAD_USE,
                              "illegal agent request");

    if(!agent->ops)
        /* if no agent has been connected, bail out */
        return _libssh2_error(agent->session, LIBSSH2_ERROR_BAD_USE,
                              "agent not connected");

    rc = agent->ops->transact(agent, transctx);
    if(rc) {
        LIBSSH2_FREE(agent->session, transctx->response);
        transctx->response = NULL;
        return rc;
    }
    transctx->request = NULL;

    len = transctx->response_len;
    s = transctx->response;
    len--;
    if(len < 0) {
        rc = LIBSSH2_ERROR_AGENT_PROTOCOL;
        goto error;
    }
    if(*s != SSH2_AGENT_IDENTITIES_ANSWER) {
        rc = LIBSSH2_ERROR_AGENT_PROTOCOL;
        goto error;
    }
    s++;

    /* Read the length of identities */
    len -= 4;
    if(len < 0) {
        rc = LIBSSH2_ERROR_AGENT_PROTOCOL;
        goto error;
    }
    num_identities = _libssh2_ntohu32(s);
    s += 4;

    while(num_identities--) {
        struct agent_publickey *identity;
        size_t comment_len;

        /* Read the length of the blob */
        len -= 4;
        if(len < 0) {
            rc = LIBSSH2_ERROR_AGENT_PROTOCOL;
            goto error;
        }
        identity = LIBSSH2_ALLOC(agent->session, sizeof(*identity));
        if(!identity) {
            rc = LIBSSH2_ERROR_ALLOC;
            goto error;
        }
        identity->external.blob_len = _libssh2_ntohu32(s);
        s += 4;

        /* Read the blob */
        len -= identity->external.blob_len;
        if(len < 0) {
            rc = LIBSSH2_ERROR_AGENT_PROTOCOL;
            LIBSSH2_FREE(agent->session, identity);
            goto error;
        }

        identity->external.blob = LIBSSH2_ALLOC(agent->session,
                                                identity->external.blob_len);
        if(!identity->external.blob) {
            rc = LIBSSH2_ERROR_ALLOC;
            LIBSSH2_FREE(agent->session, identity);
            goto error;
        }
        memcpy(identity->external.blob, s, identity->external.blob_len);
        s += identity->external.blob_len;

        /* Read the length of the comment */
        len -= 4;
        if(len < 0) {
            rc = LIBSSH2_ERROR_AGENT_PROTOCOL;
            LIBSSH2_FREE(agent->session, identity->external.blob);
            LIBSSH2_FREE(agent->session, identity);
            goto error;
        }
        comment_len = _libssh2_ntohu32(s);
        s += 4;

        if(comment_len > (size_t)len) {
            rc = LIBSSH2_ERROR_AGENT_PROTOCOL;
            LIBSSH2_FREE(agent->session, identity->external.blob);
            LIBSSH2_FREE(agent->session, identity);
            goto error;
        }
        /* Read the comment */
        len -= comment_len;

        identity->external.comment = LIBSSH2_ALLOC(agent->session,
                                                   comment_len + 1);
        if(!identity->external.comment) {
            rc = LIBSSH2_ERROR_ALLOC;
            LIBSSH2_FREE(agent->session, identity->external.blob);
            LIBSSH2_FREE(agent->session, identity);
            goto error;
        }
        identity->external.comment[comment_len] = '\0';
        memcpy(identity->external.comment, s, comment_len);
        s += comment_len;

        _libssh2_list_add(&agent->head, &identity->node);
    }
error:
    LIBSSH2_FREE(agent->session, transctx->response);
    transctx->response = NULL;

    return _libssh2_error(agent->session, rc,
                          "agent list id failed");
}

static void
agent_free_identities(LIBSSH2_AGENT *agent)
{
    struct agent_publickey *node;
    struct agent_publickey *next;

    for(node = _libssh2_list_first(&agent->head); node; node = next) {
        next = _libssh2_list_next(&node->node);
        LIBSSH2_FREE(agent->session, node->external.blob);
        LIBSSH2_FREE(agent->session, node->external.comment);
        LIBSSH2_FREE(agent->session, node);
    }
    _libssh2_list_init(&agent->head);
}

#define AGENT_PUBLICKEY_MAGIC 0x3bdefed2
/*
 * agent_publickey_to_external
 *
 * Copies data from the internal to the external representation struct.
 *
 */
static struct libssh2_agent_publickey *
agent_publickey_to_external(struct agent_publickey *node)
{
    struct libssh2_agent_publickey *ext = &node->external;

    ext->magic = AGENT_PUBLICKEY_MAGIC;
    ext->node = node;

    return ext;
}

/*
 * libssh2_agent_init
 *
 * Init an ssh-agent handle. Returns the pointer to the handle.
 *
 */
LIBSSH2_API LIBSSH2_AGENT *
libssh2_agent_init(LIBSSH2_SESSION *session)
{
    LIBSSH2_AGENT *agent;

    agent = LIBSSH2_CALLOC(session, sizeof(*agent));
    if(!agent) {
        _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                       "Unable to allocate space for agent connection");
        return NULL;
    }
    agent->fd = LIBSSH2_INVALID_SOCKET;
    agent->session = session;
    agent->identity_agent_path = NULL;
    _libssh2_list_init(&agent->head);

#ifdef HAVE_WIN32_AGENTS
    agent->pipe = INVALID_HANDLE_VALUE;
    memset(&agent->overlapped, 0, sizeof(OVERLAPPED));
    agent->pending_io = FALSE;
#endif

    return agent;
}

/*
 * libssh2_agent_connect
 *
 * Connect to an ssh-agent.
 *
 * Returns 0 if succeeded, or a negative value for error.
 */
LIBSSH2_API int
libssh2_agent_connect(LIBSSH2_AGENT *agent)
{
    int i, rc = -1;
    for(i = 0; supported_backends[i].name; i++) {
        agent->ops = supported_backends[i].ops;
        rc = (agent->ops->connect)(agent);
        if(!rc)
            return 0;
    }
    return rc;
}

/*
 * libssh2_agent_list_identities
 *
 * Request ssh-agent to list identities.
 *
 * Returns 0 if succeeded, or a negative value for error.
 */
LIBSSH2_API int
libssh2_agent_list_identities(LIBSSH2_AGENT *agent)
{
    memset(&agent->transctx, 0, sizeof(agent->transctx));
    /* Abandon the last fetched identities */
    agent_free_identities(agent);
    return agent_list_identities(agent);
}

/*
 * libssh2_agent_get_identity
 *
 * Traverse the internal list of public keys. Pass NULL to 'prev' to get
 * the first one. Or pass a pointer to the previously returned one to get the
 * next.
 *
 * Returns:
 * 0 if a fine public key was stored in 'store'
 * 1 if end of public keys
 * [negative] on errors
 */
LIBSSH2_API int
libssh2_agent_get_identity(LIBSSH2_AGENT *agent,
                           struct libssh2_agent_publickey **ext,
                           struct libssh2_agent_publickey *oprev)
{
    struct agent_publickey *node;
    if(oprev && oprev->node) {
        /* we have a starting point */
        struct agent_publickey *prev = oprev->node;

        /* get the next node in the list */
        node = _libssh2_list_next(&prev->node);
    }
    else
        node = _libssh2_list_first(&agent->head);

    if(!node)
        /* no (more) node */
        return 1;

    *ext = agent_publickey_to_external(node);

    return 0;
}

/*
 * libssh2_agent_userauth
 *
 * Do publickey user authentication with the help of ssh-agent.
 *
 * Returns 0 if succeeded, or a negative value for error.
 */
LIBSSH2_API int
libssh2_agent_userauth(LIBSSH2_AGENT *agent,
                       const char *username,
                       struct libssh2_agent_publickey *identity)
{
    void *abstract = agent;
    int rc;

    if(agent->session->userauth_pblc_state == libssh2_NB_state_idle) {
        memset(&agent->transctx, 0, sizeof(agent->transctx));
        agent->identity = identity->node;
    }

    BLOCK_ADJUST(rc, agent->session,
                 _libssh2_userauth_publickey(agent->session, username,
                                             strlen(username),
                                             identity->blob,
                                             identity->blob_len,
                                             agent_sign,
                                             &abstract));
    return rc;
}

/*
 * libssh2_agent_sign
 *
 * Sign a payload using a system-installed ssh-agent.
 *
 * Returns 0 if succeeded, or a negative value for error.
 */
LIBSSH2_API int
libssh2_agent_sign(LIBSSH2_AGENT *agent,
                   struct libssh2_agent_publickey *identity,
                   unsigned char **sig,
                   size_t *s_len,
                   const unsigned char *data,
                   size_t d_len,
                   const char *method,
                   unsigned int method_len)
{
    void *abstract = agent;
    int rc;
    uint32_t methodLen;

    if(agent->session->userauth_pblc_state == libssh2_NB_state_idle) {
        memset(&agent->transctx, 0, sizeof(agent->transctx));
        agent->identity = identity->node;
    }

    if(identity->blob_len < sizeof(uint32_t)) {
        return LIBSSH2_ERROR_BUFFER_TOO_SMALL;
    }

    methodLen = _libssh2_ntohu32(identity->blob);

    if(identity->blob_len < sizeof(uint32_t) + methodLen) {
        return LIBSSH2_ERROR_BUFFER_TOO_SMALL;
    }

    agent->session->userauth_pblc_method_len = method_len;
    agent->session->userauth_pblc_method = LIBSSH2_ALLOC(agent->session,
                                                         method_len);

    memcpy(agent->session->userauth_pblc_method, method, methodLen);

    rc = agent_sign(agent->session, sig, s_len, data, d_len, &abstract);

    LIBSSH2_FREE(agent->session, agent->session->userauth_pblc_method);
    agent->session->userauth_pblc_method = NULL;
    agent->session->userauth_pblc_method_len = 0;

    return rc;
}

/*
 * libssh2_agent_disconnect
 *
 * Close a connection to an ssh-agent.
 *
 * Returns 0 if succeeded, or a negative value for error.
 */
LIBSSH2_API int
libssh2_agent_disconnect(LIBSSH2_AGENT *agent)
{
    if(agent->ops && agent->fd != LIBSSH2_INVALID_SOCKET)
        return agent->ops->disconnect(agent);
    return 0;
}

/*
 * libssh2_agent_free
 *
 * Free an ssh-agent handle.  This function also frees the internal
 * collection of public keys.
 */
LIBSSH2_API void
libssh2_agent_free(LIBSSH2_AGENT *agent)
{
    /* Allow connection freeing when the socket has lost its connection */
    if(agent->fd != LIBSSH2_INVALID_SOCKET) {
        libssh2_agent_disconnect(agent);
    }

    if(agent->identity_agent_path)
        LIBSSH2_FREE(agent->session, agent->identity_agent_path);

    agent_free_identities(agent);
    LIBSSH2_FREE(agent->session, agent);
}

/*
 * libssh2_agent_set_identity_path
 *
 * Allows a custom agent socket path beyond SSH_AUTH_SOCK env
 *
 */
LIBSSH2_API void
libssh2_agent_set_identity_path(LIBSSH2_AGENT *agent, const char *path)
{
    if(agent->identity_agent_path) {
        LIBSSH2_FREE(agent->session, agent->identity_agent_path);
        agent->identity_agent_path = NULL;
    }

    if(path) {
        size_t path_len = strlen(path);
        if(path_len < SIZE_MAX - 1) {
            char *path_buf = LIBSSH2_ALLOC(agent->session, path_len + 1);
            memcpy(path_buf, path, path_len);
            path_buf[path_len] = '\0';
            agent->identity_agent_path = path_buf;
        }
    }
}

/*
 * libssh2_agent_get_identity_path
 *
 * Returns the custom agent socket path if set
 *
 */
LIBSSH2_API const char *libssh2_agent_get_identity_path(LIBSSH2_AGENT *agent)
{
    return agent->identity_agent_path;
}
