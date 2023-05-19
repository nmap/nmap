/***************************************************************************
 * ncat_win.c -- Windows-specific functions.                               *
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

#include "nbase.h"
#include "ncat.h"

int ncat_openlog(const char *logfile, int append)
{
    if (append)
        return Open(logfile, O_BINARY | O_WRONLY | O_CREAT | O_APPEND, 0664);
    else
        return Open(logfile, O_BINARY | O_WRONLY | O_CREAT | O_TRUNC, 0664);
}

void set_lf_mode(void)
{
    /* _O_TEXT (the default setting) converts \r\n to \n on input, making the
       terminal look like a Unix terminal. However, use _O_BINARY if stdin is
       not a terminal, to avoid breaking data from a pipe or other source. */
    if (isatty(STDIN_FILENO))
        _setmode(STDIN_FILENO, _O_TEXT);
    else
        _setmode(STDIN_FILENO, _O_BINARY);
    /* Do not translate \n to \r\n on output. */
    _setmode(STDOUT_FILENO, _O_BINARY);
}

#ifdef HAVE_OPENSSL

int ssl_load_default_ca_certs(SSL_CTX *ctx)
{
    char buf[1024];
    char *bundlename;
    int n, rc;
    size_t size, offset;

    /* Get the executable's filename. */
    n = GetModuleFileName(GetModuleHandle(0), buf, sizeof(buf));
    if (n == 0 || n == sizeof(buf))
        return -1;

    bundlename = path_get_dirname(buf);
    bundlename = (char *) safe_realloc(bundlename, 1024);
    offset = strlen(bundlename);
    size = offset + 1;
    strbuf_sprintf(&bundlename, &size, &offset, "\\%s", NCAT_CA_CERTS_FILE);

    if (o.debug)
        logdebug("Using trusted CA certificates from %s.\n", bundlename);
    rc = SSL_CTX_load_verify_locations(ctx, bundlename, NULL);
    if (rc != 1) {
        if (o.debug)
            logdebug("Unable to load trusted CA certificates from %s: %s\n",
                bundlename, ERR_error_string(ERR_get_error(), NULL));
    }
    free(bundlename);

    return rc == 1 ? 0 : -1;
}
#endif
