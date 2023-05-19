/***************************************************************************
 * ncat_listen.c -- --listen mode.                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2023 Nmap Software LLC ("The Nmap
 * Project"). Nmap is also a registered trademark of the Nmap Project.
 *
 * This program is distributed under the terms of the Nmap Public Source
 * License (NPSL). The exact license text applying to a particular Nmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Nmap or source code control
 * revision. More Nmap copyright/legal information is available from
 * https://nmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://nmap.org/npsl/ . This
 * header summarizes some key points from the Nmap license, but is no
 * substitute for the actual license text.
 *
 * Nmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://nmap.org.
 *
 * The Nmap license generally prohibits companies from using and
 * redistributing Nmap in commercial products, but we sell a special Nmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://nmap.org/oem/
 *
 * If you have received a written Nmap license agreement or contract
 * stating terms other than these (such as an Nmap OEM license), you may
 * choose to use and redistribute Nmap under those terms instead.
 *
 * The official Nmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Nmap Windows builds may not be redistributed
 * without special permission (such as an Nmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to submit your changes as a Github PR
 * or by email to the dev@nmap.org mailing list for possible incorporation into
 * the main distribution. Unless you specify otherwise, it is understood that
 * you are offering us very broad rights to use your submissions as described in
 * the Nmap Public Source License Contributor Agreement. This is important
 * because we fund the project by selling licenses with various terms, and also
 * because the inability to relicense code has caused devastating problems for
 * other Free Software projects (such as KDE and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/

/* $Id$ */

#include "ncat.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <limits.h>
#ifndef WIN32
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#else
#include <fcntl.h>
#endif

#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifdef WIN32
/* Define missing constant for shutdown(2).
 * See:
 * http://msdn.microsoft.com/en-us/library/windows/desktop/ms740481%28v=vs.85%29.aspx
 */
#define SHUT_WR SD_SEND
#endif

/* read_fds is the clients we are accepting data from. broadcast_fds is the
   clients were are sending data to. broadcast_fds doesn't include the listening
   socket and stdin. Network clients are not added to read_fds when --send-only
   is used, because they would be always selected without having data read.
   write_fds is the list of clients that are waiting for some kind of response
   from us, like a pending ssl negotiation. */
static fd_set master_readfds, master_writefds, master_broadcastfds;
#ifdef HAVE_OPENSSL
/* sslpending_fds contains the list of ssl sockets that are waiting to complete
   the ssl handshake */
static fd_set sslpending_fds;
#endif

/* These are bookkeeping data structures that are parallel to read_fds and
   broadcast_fds. */
static fd_list_t client_fdlist, broadcast_fdlist;

static int listen_socket[NUM_LISTEN_ADDRS];
/* Has stdin seen EOF? */
static int stdin_eof = 0;
static int crlf_state = 0;

static void handle_connection(int socket_accept, int type, fd_set *listen_fds);
static int read_stdin(void);
static int read_socket(int recv_fd);
static void post_handle_connection(struct fdinfo *sinfo);
static void close_fd(struct fdinfo *fdn, int eof);
static void read_and_broadcast(int recv_socket);
static void shutdown_sockets(int how);
static int chat_announce_connect(const struct fdinfo *fdi);
static int chat_announce_disconnect(int fd);
static char *chat_filter(char *buf, size_t size, int fd, int *nwritten);

/* The number of connected clients is the difference of conn_inc and conn_dec.
   It is split up into two variables for signal safety. conn_dec is modified
   (asynchronously) only in signal handlers and conn_inc is modified
   (synchronously) only in the main program. get_conn_count loops while conn_dec
   is being modified. */
static unsigned int conn_inc = 0;
static volatile unsigned int conn_dec = 0;
static volatile sig_atomic_t conn_dec_changed;

static void decrease_conn_count(void)
{
    conn_dec_changed = 1;
    conn_dec++;
}

static int get_conn_count(void)
{
    unsigned int count;

    /* conn_dec is modified in a signal handler, so loop until it stops
       changing. */
    do {
        conn_dec_changed = 0;
        count = conn_inc - conn_dec;
    } while (conn_dec_changed);
    ncat_assert(count <= INT_MAX);

    return count;
}

#ifndef WIN32
static void sigchld_handler(int signum)
{
    while (waitpid(-1, NULL, WNOHANG) > 0)
        decrease_conn_count();
}
#endif

int new_listen_socket(int type, int proto, const union sockaddr_u *addr, fd_set *listen_fds)
{
  struct fdinfo fdi = {0};
  fdi.fd = do_listen(type, proto, addr);
  if (fdi.fd < 0) {
    return -1;
  }
  fdi.remoteaddr = *addr; /* actually our local addr, but whatevs */

  /* Make our listening socket non-blocking because there are timing issues
   * which could cause us to block on accept() even though select() says it's
   * readable.  See UNPv1 2nd ed, p422 for more.
   */
  unblock_socket(fdi.fd);

  /* setup select sets and max fd */
  checked_fd_set(fdi.fd, &master_readfds);
  add_fdinfo(&client_fdlist, &fdi);

  checked_fd_set(fdi.fd, listen_fds);

  return fdi.fd;
}

int ncat_listen()
{
    int rc, i, j, fds_ready;
    fd_set listen_fds;
    struct timeval tv;
    struct timeval *tvp = NULL;
    unsigned int num_sockets;
    int proto = o.proto;
    int type = o.proto == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;

    if (o.httpserver)
        return ncat_http_server();

#if HAVE_SYS_UN_H
    if (o.af == AF_UNIX)
        proto = 0;
#endif
#if HAVE_LINUX_VM_SOCKETS_H
    if (o.af == AF_VSOCK)
        proto = 0;
#endif
    /* clear out structs */
    FD_ZERO(&master_readfds);
    FD_ZERO(&master_writefds);
    FD_ZERO(&master_broadcastfds);
    FD_ZERO(&listen_fds);
#ifdef HAVE_OPENSSL
    FD_ZERO(&sslpending_fds);
#endif
    zmem(&client_fdlist, sizeof(client_fdlist));
    zmem(&broadcast_fdlist, sizeof(broadcast_fdlist));

#ifdef WIN32
    set_pseudo_sigchld_handler(decrease_conn_count);
#else
    /* Reap on SIGCHLD */
    Signal(SIGCHLD, sigchld_handler);
    /* Ignore the SIGPIPE that occurs when a client disconnects suddenly and we
       send data to it before noticing. */
    Signal(SIGPIPE, SIG_IGN);
#endif

#ifdef HAVE_OPENSSL
    if (o.ssl)
    {
        if (o.sslalpn)
            bye("ALPN is not supported in listen mode\n");
        setup_ssl_listen(type == SOCK_STREAM ? SSLv23_server_method() : DTLS_server_method());
    }
#endif

/* Not sure if this problem exists on Windows, but fcntl and /dev/null don't */
#ifndef WIN32
    /* Check whether stdin is closed. Because we treat this fd specially, we
     * can't risk it being reopened for an incoming connection, so we'll hold
     * it open instead. */
    if (fcntl(STDIN_FILENO, F_GETFD) == -1 && errno == EBADF) {
      logdebug("stdin is closed, attempting to reserve STDIN_FILENO\n");
      rc = open("/dev/null", O_RDONLY);
      if (rc >= 0 && rc != STDIN_FILENO) {
        /* Oh well, we tried */
        logdebug("Couldn't reserve STDIN_FILENO\n");
        close(rc);
      }
    }
#endif

    /* We need a list of fds to keep current fdmax. The second parameter is a
       number added to the supplied connection limit, that will compensate
       maxfds for the added by default listen and stdin sockets. */
    init_fdlist(&client_fdlist, sadd(o.conn_limit, num_listenaddrs + 1));

    for (i = 0; i < NUM_LISTEN_ADDRS; i++)
        listen_socket[i] = -1;

    num_sockets = 0;
    for (i = 0; i < num_listenaddrs; i++) {
        /* setup the main listening socket */
        listen_socket[num_sockets] = new_listen_socket(type, proto, &listenaddrs[i], &listen_fds);
        if (listen_socket[num_sockets] == -1) {
            if (o.debug > 0)
                logdebug("do_listen(\"%s\"): %s\n", socktop(&listenaddrs[i], 0), socket_strerror(socket_errno()));
            continue;
        }
        num_sockets++;
    }
    if (num_sockets == 0) {
        if (num_listenaddrs == 1)
            bye("Unable to open listening socket on %s: %s", socktop(&listenaddrs[0], 0), socket_strerror(socket_errno()));
        else
            bye("Unable to open any listening sockets.");
    }

    add_fd(&client_fdlist, STDIN_FILENO);

    init_fdlist(&broadcast_fdlist, o.conn_limit);

    if (o.idletimeout > 0)
        tvp = &tv;

    while (client_fdlist.nfds > 1 || get_conn_count() > 0) {
        /* We pass these temporary descriptor sets to fselect, since fselect
           modifies the sets it receives. */
        fd_set readfds = master_readfds, writefds = master_writefds;


        if (o.debug > 1)
            logdebug("selecting, fdmax %d\n", client_fdlist.fdmax);

        if (o.debug > 1 && o.broker)
            logdebug("Broker connection count is %d\n", get_conn_count());

        if (o.idletimeout > 0)
            ms_to_timeval(tvp, o.idletimeout);

        /* The idle timer should only be running when there are active connections */
        if (get_conn_count())
            fds_ready = fselect(client_fdlist.fdmax + 1, &readfds, &writefds, NULL, tvp);
        else
            fds_ready = fselect(client_fdlist.fdmax + 1, &readfds, &writefds, NULL, NULL);

        if (o.debug > 1)
            logdebug("select returned %d fds ready\n", fds_ready);

        if (fds_ready == 0)
            bye("Idle timeout expired (%d ms).", o.idletimeout);

        /* If client_fdlist.state increases, the list has changed and we
         * need to go over it again. */
restart_fd_loop:
        client_fdlist.state = 0;
        for (i = 0; i < client_fdlist.nfds && fds_ready > 0; i++) {
            struct fdinfo *fdi = &client_fdlist.fds[i];
            int cfd = fdi->fd;
            /* If we saw an error, close this fd */
            if (fdi->lasterr != 0) {
                close_fd(fdi, 0);
                goto restart_fd_loop;
            }
            /* Loop through descriptors until there's something to read */
            if (!checked_fd_isset(cfd, &readfds) && !checked_fd_isset(cfd, &writefds))
                continue;

            if (o.debug > 1)
                logdebug("fd %d is ready\n", cfd);

#ifdef HAVE_OPENSSL
            /* Is this an ssl socket pending a handshake? If so handle it. */
            if (o.ssl && checked_fd_isset(cfd, &sslpending_fds)) {
                checked_fd_clr(cfd, &master_readfds);
                checked_fd_clr(cfd, &master_writefds);
                switch (ssl_handshake(fdi)) {
                case NCAT_SSL_HANDSHAKE_COMPLETED:
                    /* Clear from sslpending_fds once ssl is established */
                    checked_fd_clr(cfd, &sslpending_fds);
                    post_handle_connection(fdi);
                    break;
                case NCAT_SSL_HANDSHAKE_PENDING_WRITE:
                    checked_fd_set(cfd, &master_writefds);
                    break;
                case NCAT_SSL_HANDSHAKE_PENDING_READ:
                    checked_fd_set(cfd, &master_readfds);
                    break;
                case NCAT_SSL_HANDSHAKE_FAILED:
                default:
                    SSL_free(fdi->ssl);
                    Close(fdi->fd);
                    checked_fd_clr(cfd, &sslpending_fds);
                    checked_fd_clr(cfd, &master_readfds);
                    rm_fd(&client_fdlist, cfd);
                    /* Are we in single listening mode(without -k)? If so
                       then we should quit also. */
                    if (!o.keepopen && !o.broker)
                        return 1;
                    --conn_inc;
                    break;
                }
            } else
#endif
            if (checked_fd_isset(cfd, &listen_fds)) {
                /* we have a new connection request */
                handle_connection(cfd, type, &listen_fds);
            } else if (cfd == STDIN_FILENO) {
                if (o.broker) {
                    read_and_broadcast(cfd);
                } else {
                    /* Read from stdin and write to all clients. */
                    rc = read_stdin();
                    if (rc == 0) {
                        if (o.proto != IPPROTO_TCP || (o.proto == IPPROTO_TCP && o.sendonly)) {
                            /* There will be nothing more to send. If we're not
                               receiving anything, we can quit here. */
                            return 0;
                        }
                        if (!o.noshutdown && type == SOCK_STREAM) shutdown_sockets(SHUT_WR);
                    }
                    if (rc < 0)
                        return 1;
                }
            } else if (!o.sendonly) {
                if (o.broker) {
                    read_and_broadcast(cfd);
                } else {
                    /* Read from a client and write to stdout. */
                    rc = read_socket(cfd);
                    if (rc <= 0 && !o.keepopen)
                        return rc == 0 ? 0 : 1;
                }
            }

            fds_ready--;
            if (client_fdlist.state > 0)
                goto restart_fd_loop;

            /* Check if any send errors were logged. */
            for (j = 0; j < broadcast_fdlist.nfds; j++) {
                fdi = &broadcast_fdlist.fds[j];
                if (fdi->lasterr != 0) {
                    close_fd(fdi, 0);
                    /* close_fd mucks with client_fdlist, so jump back and
                     * start the loop over */
                    goto restart_fd_loop;
                }
            }
        }
    }

    return 0;
}

/* Accept a connection on a listening socket. Allow or deny the connection.
   Fork a command if o.cmdexec is set. Otherwise, add the new socket to the
   watch set. */
static void handle_connection(int socket_accept, int type, fd_set *listen_fds)
{
    struct fdinfo s = { 0 };
    int conn_count;

    zmem(&s, sizeof(s));

    s.ss_len = sizeof(s.remoteaddr.storage);

    errno = 0;
    if (type == SOCK_STREAM) {
      s.fd = accept(socket_accept, &s.remoteaddr.sockaddr, &s.ss_len);
    }
    else {
      char buf[4] = {0};
      int nbytes = recvfrom(socket_accept, buf, sizeof(buf), MSG_PEEK,
          &s.remoteaddr.sockaddr, &s.ss_len);
      if (nbytes < 0) {
        loguser("%s.\n", socket_strerror(socket_errno()));
        return;
      }
      /*
       * We're using connected udp. This has the down side of only
       * being able to handle one udp client at a time
       */
      Connect(socket_accept, &s.remoteaddr.sockaddr, s.ss_len);
      s.fd = socket_accept;
      /* If we expect new connections, we'll have to open a new listening
       * socket to replace the one we just connected to a single client. */
      if ((o.keepopen || o.broker)
#if HAVE_SYS_UN_H
          /* unless it's a UNIX socket, since we get EADDRINUSE when we try to bind */
          && s.remoteaddr.storage.ss_family != AF_UNIX
#endif
        ) {
        int i;
        for (i = 0; i < num_listenaddrs; i++) {
          if (listen_socket[i] == socket_accept) {
            struct fdinfo *lfdi = get_fdinfo(&client_fdlist, socket_accept);
            union sockaddr_u localaddr = lfdi->remoteaddr;
            listen_socket[i] = new_listen_socket(type, (o.af == AF_INET || o.af == AF_INET6) ? o.proto : 0, &localaddr, listen_fds);
            if (listen_socket[i] < 0) {
              bye("do_listen(\"%s\"): %s\n", socktop(&listenaddrs[i], 0), socket_strerror(socket_errno()));
              return;
            }
            break;
          }
        }
      }
      /* Remove this socket from listening */
      checked_fd_clr(socket_accept, &master_readfds);
      checked_fd_clr(socket_accept, listen_fds);
      rm_fd(&client_fdlist, socket_accept);
    }

    if (s.fd < 0) {
        if (o.debug)
            logdebug("Error in accept: %s\n", strerror(errno));

        close(s.fd);
        return;
    }

    if (!o.keepopen && !o.broker) {
        int i;
        for (i = 0; i < num_listenaddrs; i++) {
            /* If */
            if (listen_socket[i] >= 0 && checked_fd_isset(listen_socket[i], listen_fds)) {
              Close(listen_socket[i]);
              checked_fd_clr(listen_socket[i], &master_readfds);
              rm_fd(&client_fdlist, listen_socket[i]);
              listen_socket[i] = -1;
            }
        }
    }

    if (o.verbose) {
        loguser("Connection from %s", socktop(&s.remoteaddr, s.ss_len));
        if (o.chat)
            loguser_noprefix(" on file descriptor %d", s.fd);
        loguser_noprefix(".\n");
    }

    /* Check conditions that might cause us to deny the connection. */
    conn_count = get_conn_count();
    if (conn_count >= o.conn_limit) {
        if (o.verbose)
            loguser("New connection denied: connection limit reached (%d)\n", conn_count);
        Close(s.fd);
        return;
    }
    if (!allow_access(&s.remoteaddr)) {
        if (o.verbose)
            loguser("New connection denied: not allowed\n");
        Close(s.fd);
        return;
    }

    conn_inc++;

    unblock_socket(s.fd);

#ifdef HAVE_OPENSSL
    if (o.ssl) {
        /* Add the socket to the necessary descriptor lists. */
        checked_fd_set(s.fd, &sslpending_fds);
        checked_fd_set(s.fd, &master_readfds);
        checked_fd_set(s.fd, &master_writefds);
        /* Add it to our list of fds too for maintaining maxfd. */
        if (add_fdinfo(&client_fdlist, &s) < 0)
            bye("add_fdinfo() failed.");
    } else
#endif
        post_handle_connection(&s);
}

/* This function handles the post connection specific actions that are needed
 * after a socket has been initialized(normal socket or ssl socket). */
static void post_handle_connection(struct fdinfo *sinfo)
{
    /*
     * Are we executing a command? If so then don't add this guy
     * to our descriptor list or set.
     */
    if (o.cmdexec) {
#ifdef HAVE_OPENSSL
      /* We added this in handle_connection, but at this point the ssl
       * connection has taken over. Stop tracking.
       */
      if (o.ssl) {
        rm_fd(&client_fdlist, sinfo->fd);
      }
#endif
        if (o.keepopen)
            netrun(sinfo, o.cmdexec);
        else
            netexec(sinfo, o.cmdexec);
    } else {
        /* Now that a client is connected, pay attention to stdin. */
        if (!stdin_eof)
            checked_fd_set(STDIN_FILENO, &master_readfds);
        if (!o.sendonly) {
            /* add to our lists */
            checked_fd_set(sinfo->fd, &master_readfds);
            /* add it to our list of fds for maintaining maxfd */
#ifdef HAVE_OPENSSL
            /* Don't add it twice (see handle_connection above) */
            if (!o.ssl) {
#endif
            if (add_fdinfo(&client_fdlist, sinfo) < 0)
                bye("add_fdinfo() failed.");
#ifdef HAVE_OPENSSL
            }
#endif
        }
        checked_fd_set(sinfo->fd, &master_broadcastfds);
        if (add_fdinfo(&broadcast_fdlist, sinfo) < 0)
            bye("add_fdinfo() failed.");

        if (o.chat)
            chat_announce_connect(sinfo);
    }
}

static void close_fd(struct fdinfo *fdn, int eof) {
    /* rm_fd invalidates fdn, so save what we need here. */
    int fd = fdn->fd;
    if (o.debug)
        logdebug("Closing connection.\n");
#ifdef HAVE_OPENSSL
    if (o.ssl && fdn->ssl) {
        if (eof)
            SSL_shutdown(fdn->ssl);
        SSL_free(fdn->ssl);
    }
#endif
    Close(fd);
    checked_fd_clr(fd, &master_readfds);
    rm_fd(&client_fdlist, fd);
    checked_fd_clr(fd, &master_broadcastfds);
    rm_fd(&broadcast_fdlist, fd);

    conn_inc--;
    if (get_conn_count() == 0)
        checked_fd_clr(STDIN_FILENO, &master_readfds);

    if (o.chat)
        chat_announce_disconnect(fd);
}

/* Read from stdin and broadcast to all client sockets. Return the number of
   bytes read, or -1 on error. */
int read_stdin(void)
{
    int nbytes;
    char buf[DEFAULT_TCP_BUF_LEN];
    char *tempbuf = NULL;

    nbytes = read(STDIN_FILENO, buf, sizeof(buf));
    if (nbytes <= 0) {
        if (nbytes < 0 && o.verbose)
            logdebug("Error reading from stdin: %s\n", strerror(errno));
        if (nbytes == 0 && o.debug)
            logdebug("EOF on stdin\n");

        /* Don't close the file because that allows a socket to be fd 0. */
        checked_fd_clr(STDIN_FILENO, &master_readfds);
        /* Buf mark that we've seen EOF so it doesn't get re-added to the
           select list. */
        stdin_eof = 1;

        return nbytes;
    }

    if (o.crlf)
        fix_line_endings((char *) buf, &nbytes, &tempbuf, &crlf_state);

    if (o.linedelay)
        ncat_delay_timer(o.linedelay);

    /* Write to everything in the broadcast set. */
    if (tempbuf != NULL) {
        ncat_broadcast(&master_broadcastfds, &broadcast_fdlist, tempbuf, nbytes);
        free(tempbuf);
        tempbuf = NULL;
    } else {
        ncat_broadcast(&master_broadcastfds, &broadcast_fdlist, buf, nbytes);
    }

    return nbytes;
}

/* Read from a client socket and write to stdout. Return the number of bytes
   read from the socket, or -1 on error. */
int read_socket(int recv_fd)
{
    char buf[DEFAULT_TCP_BUF_LEN];
    struct fdinfo *fdn;
    int nbytes, pending;

    fdn = get_fdinfo(&client_fdlist, recv_fd);
    ncat_assert(fdn != NULL);

    nbytes = 0;
    do {
        int n;

        n = ncat_recv(fdn, buf, sizeof(buf), &pending);
        if (n <= 0) {
            /* return value can be 0 without meaning EOF in some cases such as SSL
             * renegotiations that require read/write socket operations but do not
             * have any application data. */
            if(n == 0 && fdn->lasterr == 0) {
                continue; /* Check pending */
            }
            close_fd(fdn, n == 0);
            return n;
        }
        else {
            Write(STDOUT_FILENO, buf, n);
            nbytes += n;
        }
    } while (pending);

    return nbytes;
}


//---------------
/* Read from recv_fd and broadcast whatever is read to all other descriptors in
   read_fds, with the exception of stdin, listen_socket, and recv_fd itself.
   Handles EOL translation and chat mode. On read error or end of stream,
   closes the socket and removes it from the read_fds list. */
static void read_and_broadcast(int recv_fd)
{
    struct fdinfo *fdn;
    int pending;

    fdn = get_fdinfo(&client_fdlist, recv_fd);
    ncat_assert(fdn != NULL);

    /* Loop while ncat_recv indicates data is pending. */
    do {
        char buf[DEFAULT_TCP_BUF_LEN];
        char *chatbuf, *outbuf;
        char *tempbuf = NULL;
        fd_set broadcastfds;
        int n;

        /* Behavior differs depending on whether this is stdin or a socket. */
        if (recv_fd == STDIN_FILENO) {
            n = read(recv_fd, buf, sizeof(buf));
            if (n <= 0) {
                if (n < 0 && o.verbose)
                    logdebug("Error reading from stdin: %s\n", strerror(errno));
                if (n == 0 && o.debug)
                    logdebug("EOF on stdin\n");

                /* Don't close the file because that allows a socket to be
                   fd 0. */
                checked_fd_clr(recv_fd, &master_readfds);
                /* But mark that we've seen EOF so it doesn't get re-added to
                   the select list. */
                stdin_eof = 1;

                return;
            }

            if (o.crlf)
                fix_line_endings((char *) buf, &n, &tempbuf, &crlf_state);

            pending = 0;
        } else {
            /* From a connected socket, not stdin. */
            n = ncat_recv(fdn, buf, sizeof(buf), &pending);

            if (n <= 0) {
                /* return value can be 0 without meaning EOF in some cases such as SSL
                 * renegotiations that require read/write socket operations but do not
                 * have any application data. */
                if(n == 0 && fdn->lasterr == 0) {
                    continue; /* Check pending */
                }
                close_fd(fdn, n == 0);
                return;
            }
        }

        if (o.debug > 1)
            logdebug("Handling data from client %d.\n", recv_fd);

        chatbuf = NULL;
        /* tempbuf is in use if we read from STDIN and fixed EOL */
        if (tempbuf == NULL)
            outbuf = buf;
        else
            outbuf = tempbuf;

        if (o.chat) {
            chatbuf = chat_filter(outbuf, n, recv_fd, &n);
            if (chatbuf == NULL) {
                if (o.verbose)
                    logdebug("Error formatting chat message from fd %d\n", recv_fd);
            } else {
                outbuf = chatbuf;
            }
        }

        /* Send to everyone except the one who sent this message. */
        broadcastfds = master_broadcastfds;
        checked_fd_clr(recv_fd, &broadcastfds);
        ncat_broadcast(&broadcastfds, &broadcast_fdlist, outbuf, n);

        free(chatbuf);
        free(tempbuf);
        tempbuf = NULL;
    } while (pending);
}

static void shutdown_sockets(int how)
{
    struct fdinfo *fdn;
    int i;

    for (i = 0; i <= broadcast_fdlist.fdmax; i++) {
        if (!checked_fd_isset(i, &master_broadcastfds))
            continue;

        fdn = get_fdinfo(&broadcast_fdlist, i);
        ncat_assert(fdn != NULL);
        shutdown(fdn->fd, how);
    }
}

/* Announce the new connection and who is already connected. */
static int chat_announce_connect(const struct fdinfo *fdi)
{
    char *buf = NULL;
    size_t size = 0, offset = 0;
    int i, count, ret;

    strbuf_sprintf(&buf, &size, &offset,
        "<announce> %s is connected as <user%d>.\n", socktop(&fdi->remoteaddr, fdi->ss_len), fdi->fd);

    strbuf_sprintf(&buf, &size, &offset, "<announce> already connected: ");
    count = 0;
    for (i = 0; i <= client_fdlist.fdmax; i++) {
        union sockaddr_u tsu;
        socklen_t len = sizeof(tsu.storage);

        if (i == fdi->fd || !checked_fd_isset(i, &master_broadcastfds))
            continue;

        if (getpeername(i, &tsu.sockaddr, &len) == -1)
            bye("getpeername for sd %d failed: %s.", i, strerror(errno));

        if (count > 0)
            strbuf_sprintf(&buf, &size, &offset, ", ");

        strbuf_sprintf(&buf, &size, &offset, "%s as <user%d>", socktop(&tsu, len), i);

        count++;
    }
    if (count == 0)
        strbuf_sprintf(&buf, &size, &offset, "nobody");
    strbuf_sprintf(&buf, &size, &offset, ".\n");

    ret = ncat_broadcast(&master_broadcastfds, &broadcast_fdlist, buf, offset);

    free(buf);

    return ret;
}

static int chat_announce_disconnect(int fd)
{
    char buf[128];
    int n;

    n = Snprintf(buf, sizeof(buf),
        "<announce> <user%d> is disconnected.\n", fd);
    if (n < 0 || n >= sizeof(buf))
        return -1;

    return ncat_broadcast(&master_broadcastfds, &broadcast_fdlist, buf, n);
}

/*
 * This is stupid. But it's just a bit of fun.
 *
 * The file descriptor of the sender is prepended to the
 * message sent to clients, so you can distinguish
 * each other with a degree of sanity. This gives a
 * similar effect to an IRC session. But stupider.
 */
static char *chat_filter(char *buf, size_t size, int fd, int *nwritten)
{
    char *result = NULL;
    size_t n = 0;
    const char *p;
    int i;

    n = 32;
    result = (char *) safe_malloc(n);
    i = Snprintf(result, n, "<user%d> ", fd);

    /* Escape control characters. */
    for (p = buf; p - buf < size; p++) {
        char repl[32];
        int repl_len;

        if (isprint((int) (unsigned char) *p) || *p == '\r' || *p == '\n' || *p == '\t') {
            repl[0] = *p;
            repl_len = 1;
        } else {
            repl_len = Snprintf(repl, sizeof(repl), "\\%03o", (unsigned char) *p);
        }

        if (i + repl_len > n) {
            n = (i + repl_len) * 2;
            result = (char *) safe_realloc(result, n + 1);
        }
        memcpy(result + i, repl, repl_len);
        i += repl_len;
    }
    /* Trim to length. (Also does initial allocation when str is empty.) */
    result = (char *) safe_realloc(result, i + 1);
    result[i] = '\0';

    *nwritten = i;

    return result;
}
