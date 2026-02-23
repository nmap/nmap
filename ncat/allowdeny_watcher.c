/***************************************************************************
 * allowdeny_watcher.c -- Cross-platform watcher for Ncat ACL files        *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2025 Nmap Software LLC ("The Nmap
 * Project"). Nmap is also a registered trademark of the Nmap Project.
 *
 * This program is distributed under the terms of the Nmap Public Source
 * License (NPSL). The exact license text applying to a particular Nmap
 * release or source code control revision is contained in the LICENSE file
 * distributed with that version of Nmap or source code control revision.
 * More Nmap copyright/legal information is available from
 * https://nmap.org/book/man-legal.html, and further information on the NPSL
 * license itself can be found at https://nmap.org/npsl/ . This header
 * summarizes some key points from the Nmap license, but is no substitute
 * for the actual license text.
 *
 * Nmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://nmap.org.
 *
 * The Nmap license generally prohibits companies from using and
 * redistributing Nmap in commercial products, but we sell a special Nmap
 * OEM Edition with a more permissive license and special features for this
 * purpose. See https://nmap.org/oem/
 *
 * If you have received a written Nmap license agreement or contract stating
 * terms other than these (such as an Nmap OEM license), you may choose to
 * use and redistribute Nmap under those terms instead.
 *
 * The official Nmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Nmap Windows builds may not be redistributed
 * without special permission (such as an Nmap OEM license).
 *
 * Source is provided to this software because we believe users have a right
 * to know exactly what a program is going to do before they run it. This
 * also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and
 * add new features. You are highly encouraged to submit your changes as a
 * Github PR or by email to the dev@nmap.org mailing list for possible
 * incorporation into the main distribution. Unless you specify otherwise,
 * it is understood that you are offering us very broad rights to use your
 * submissions as described in the Nmap Public Source License Contributor
 * Agreement. This is important because we fund the project by selling
 * licenses with various terms, and also because the inability to relicense
 * code has caused devastating problems for other Free Software projects
 * (such as KDE and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/

#include "allowdeny_watcher.h"
#include "ncat_core.h"
#include "util.h"
#include "sys_wrap.h"

#ifdef WIN32
/* Windows headers */
#include <windows.h>
#else  /* POSIX */
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/inotify.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <sys/event.h>
#include <fcntl.h>
#endif
#endif

/* ------------------------------------------------------------------------- */
/* Internal helpers                                                          */
/* ------------------------------------------------------------------------- */

struct watcher_paths {
    char *allow_path;
    char *deny_path;
};

#ifndef WIN32
pthread_mutex_t g_allowdeny_mutex = PTHREAD_MUTEX_INITIALIZER;

static void reload_rules(const struct watcher_paths *wp)
{
    /* Build new addrsets */
    struct addrset *new_allow = NULL;
    struct addrset *new_deny  = NULL;

    if (wp->allow_path) {
        FILE *fd = fopen(wp->allow_path, "r");
        if (fd) {
            new_allow = addrset_new();
            if (!addrset_add_file(new_allow, fd, o.af, !o.nodns)) {
                loguser("[WARN] Error parsing allow file %s, keeping old set.\n", wp->allow_path);
                addrset_free(new_allow);
                new_allow = NULL;
            }
            fclose(fd);
        }
    }

    if (wp->deny_path) {
        FILE *fd = fopen(wp->deny_path, "r");
        if (fd) {
            new_deny = addrset_new();
            if (!addrset_add_file(new_deny, fd, o.af, !o.nodns)) {
                loguser("[WARN] Error parsing deny file %s, keeping old set.\n", wp->deny_path);
                addrset_free(new_deny);
                new_deny = NULL;
            }
            fclose(fd);
        }
    }

    /* Swap in atomically under mutex */
    pthread_mutex_lock(&g_allowdeny_mutex);
    if (new_allow) {
        addrset_free(o.allowset);
        o.allowset = new_allow;
    }
    if (new_deny) {
        addrset_free(o.denyset);
        o.denyset = new_deny;
    }
    pthread_mutex_unlock(&g_allowdeny_mutex);

    /* Log reload time */
    time_t now = time(NULL);
    char tsbuf[32];
    struct tm tmval;
    localtime_r(&now, &tmval);
    strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%d %H:%M:%S", &tmval);

    loguser("[INFO] Re-loaded allow/deny rules (modified at %s)\n", tsbuf);
}

/* ---------------------- LINUX INOTIFY IMPLEMENTATION -------------------- */
#if defined(__linux__)
static void *watcher_thread(void *arg)
{
    struct watcher_paths *wp = (struct watcher_paths *)arg;

    int infd = inotify_init1(IN_NONBLOCK);
    if (infd < 0) {
        loguser("[WARN] Failed to init inotify: %s\n", strerror(errno));
        free(wp);
        return NULL;
    }

    int wd_allow = -1, wd_deny = -1;
    if (wp->allow_path)
        wd_allow = inotify_add_watch(infd, wp->allow_path, IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVE_SELF | IN_DELETE_SELF);
    if (wp->deny_path)
        wd_deny = inotify_add_watch(infd, wp->deny_path, IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVE_SELF | IN_DELETE_SELF);

    if (wd_allow < 0 && wp->allow_path)
        loguser("[WARN] Cannot watch %s: %s\n", wp->allow_path, strerror(errno));
    if (wd_deny < 0 && wp->deny_path)
        loguser("[WARN] Cannot watch %s: %s\n", wp->deny_path, strerror(errno));

    /* Main loop */
    const size_t bufsize = 4096;
    char *buf = (char *)safe_malloc(bufsize);

    while (1) {
        ssize_t len = read(infd, buf, bufsize);
        if (len <= 0) {
            if (errno == EAGAIN || errno == EINTR) {
                /* Sleep briefly to avoid busy loop */
                usleep(200 * 1000);
                continue;
            }
            else {
                break;
            }
        }

        for (char *p = buf; p < buf + len;) {
            struct inotify_event *ev = (struct inotify_event *)p;
            if (ev->mask & (IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVE_SELF | IN_DELETE_SELF)) {
                reload_rules(wp);
            }

            p += sizeof(struct inotify_event) + ev->len;
        }
    }

    free(buf);
    close(infd);
    free(wp);
    return NULL;
}
#endif /* linux */

/* ---------------------- BSD KQUEUE IMPLEMENTATION ---------------------- */
#if !defined(WIN32) && (defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__))
static void *watcher_thread(void *arg)
{
    struct watcher_paths *wp = (struct watcher_paths *)arg;

    int kq = kqueue();
    if (kq < 0) {
        loguser("[WARN] kqueue init failed: %s\n", strerror(errno));
        free(wp);
        return NULL;
    }

    /* Watch the *directory* containing the file instead of the file itself.
       This reliably catches atomic-replace (mv) sequences which may not
       generate NOTE_WRITE for the original vnode. */
    int fd_allow = -1, fd_deny = -1;

    if (wp->allow_path) {
        char *adir = Strdup(wp->allow_path);
        char *slash = strrchr(adir, '/');
        if (slash)
            *slash = '\0';
        fd_allow = open(adir[0] ? adir : ".", O_EVTONLY);
        free(adir);
    }

    if (wp->deny_path) {
        char *ddir = Strdup(wp->deny_path);
        char *slash = strrchr(ddir, '/');
        if (slash)
            *slash = '\0';
        fd_deny = open(ddir[0] ? ddir : ".", O_EVTONLY);
        free(ddir);
    }

    struct kevent evlist[2];
    int nev = 0;
    const uint32_t flags = NOTE_WRITE | NOTE_DELETE | NOTE_EXTEND | NOTE_RENAME;
    if (fd_allow >= 0)
        EV_SET(&evlist[nev++], fd_allow, EVFILT_VNODE, EV_ADD | EV_ENABLE | EV_CLEAR, flags, 0, NULL);
    if (fd_deny >= 0)
        EV_SET(&evlist[nev++], fd_deny, EVFILT_VNODE, EV_ADD | EV_ENABLE | EV_CLEAR, flags, 0, NULL);

    if (nev == 0) {
        close(kq);
        free(wp);
        return NULL;
    }

    if (kevent(kq, evlist, nev, NULL, 0, NULL) < 0) {
        loguser("[WARN] kevent register failed: %s\n", strerror(errno));
        close(kq);
        free(wp);
        return NULL;
    }

    for (;;) {
        struct kevent ev;
        int n = kevent(kq, NULL, 0, &ev, 1, NULL);
        if (n == -1) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n > 0) {
            reload_rules(wp);
        }
    }

    if (fd_allow >= 0) close(fd_allow);
    if (fd_deny >= 0) close(fd_deny);
    close(kq);
    free(wp);
    return NULL;
}
#endif /* BSD */

#endif /* !WIN32 */

/* ---------------------- WINDOWS IMPLEMENTATION ------------------------- */
#ifdef WIN32
static DWORD WINAPI watcher_thread_win(LPVOID param)
{
    struct watcher_paths *wp = (struct watcher_paths *)param;

    /* Extract directory path */
    char dir[MAX_PATH];
    strncpy(dir, wp->allow_path ? wp->allow_path : wp->deny_path, MAX_PATH - 1);
    dir[MAX_PATH-1] = '\0';
    char *lastSep = strrchr(dir, '\\');
    if (!lastSep) lastSep = strrchr(dir, '/');
    if (lastSep) *lastSep = '\0';

    HANDLE hDir = CreateFileA(dir, FILE_LIST_DIRECTORY,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hDir == INVALID_HANDLE_VALUE) {
        loguser("[WARN] Unable to watch directory %s (err=%lu)\n", dir, GetLastError());
        free(wp);
        return 0;
    }

    BYTE buf[1024];
    DWORD bytesReturned;
    while (1) {
        if (!ReadDirectoryChangesW(hDir, buf, sizeof(buf), FALSE,
                                   FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME,
                                   &bytesReturned, NULL, NULL)) {
            Sleep(200);
            continue;
        }
        reload_rules(wp);
    }

    CloseHandle(hDir);
    free(wp);
    return 0;
}
#endif /* WIN32 */

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */

int start_allowdeny_watcher(const char *allow_path, const char *deny_path)
{
    /* If the feature is not requested, simply do nothing. Caller will ensure
       not to call us when flag is absent, but be tolerant. */
    if (allow_path == NULL && deny_path == NULL)
        return 0;

    struct watcher_paths *wp = (struct watcher_paths *)safe_malloc(sizeof(*wp));
    wp->allow_path = allow_path ? Strdup(allow_path) : NULL;
    wp->deny_path  = deny_path  ? Strdup(deny_path)  : NULL;

#if defined(__linux__)
    pthread_t tid;
    if (pthread_create(&tid, NULL, watcher_thread, wp) != 0) {
        bye("Failed to create watcher thread: %s", strerror(errno));
    }
    pthread_detach(tid);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    pthread_t tid;
    if (pthread_create(&tid, NULL, watcher_thread, wp) != 0) {
        bye("Failed to create watcher thread: %s", strerror(errno));
    }
    pthread_detach(tid);
#elif defined(WIN32)
    HANDLE th = CreateThread(NULL, 0, watcher_thread_win, wp, 0, NULL);
    if (th == NULL) {
        loguser("[WARN] Failed to start watcher thread (err=%lu)\n", GetLastError());
        free(wp);
        return -1;
    }
    CloseHandle(th);
#endif

    return 0;
}