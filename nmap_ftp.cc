
/***************************************************************************
 * nmap_ftp.cc -- Nmap's FTP routines used for FTP bounce scan (-b)
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the Nmap Project (Insecure.Com LLC) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  Nmap will always be available Open Source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects (such as KDE and NASM).  We also       *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */
#include "nmap.h"
#include "nmap_ftp.h"
#include "output.h"
#include "NmapOps.h"
#include "nmap_error.h"
#include "tcpip.h"
#include "Target.h"
#include "nmap_tty.h"
extern NmapOps o;

struct ftpinfo get_default_ftpinfo(void) {
#if (defined(IN_ADDR_DEEPSTRUCT) || defined(SOLARIS))
  /* Note that struct in_addr in solaris is 3 levels deep just to store an
   * unsigned int! */
  struct ftpinfo ftp = { FTPUSER, FTPPASS, "",  { { { 0 } } } , 21, 0};
#else
  struct ftpinfo ftp = { FTPUSER, FTPPASS, "", { 0 }, 21, 0};
#endif
  return ftp;
}

/* parse a URL stype ftp string of the form user:pass@server:portno */
int parse_bounce_argument(struct ftpinfo *ftp, char *url) {
  char *p = url, *q, *s;

  if ((q = strrchr(url, '@'))) { /* we have user and/or pass */
    *q++ = '\0';

    if ((s = strchr(p, ':'))) { /* we have user AND pass */
      *s++ = '\0';
      strncpy(ftp->pass, s, 255);
    } else { /* we ONLY have user */
      log_write(LOG_STDOUT, "Assuming %s is a username, and using the default password: %s\n",
                p, ftp->pass);
    }

    strncpy(ftp->user, p, 63);
  } else {
    q = url;
  }

  /* q points to beginning of server name */
  if ((s = strchr(q, ':'))) { /* we have portno */
    *s++ = '\0';
    ftp->port = atoi(s);
  }

  strncpy(ftp->server_name, q, FQDN_LEN+1);

  ftp->user[63] = ftp->pass[255] = ftp->server_name[FQDN_LEN] = 0;

  return 1;
}

int ftp_anon_connect(struct ftpinfo *ftp) {
  int sd;
  struct sockaddr_in sock;
  int res;
  char recvbuf[2048];
  char command[512];

  if (o.verbose || o.debugging)
    log_write(LOG_STDOUT, "Attempting connection to ftp://%s:%s@%s:%i\n",
              ftp->user, ftp->pass, ftp->server_name, ftp->port);

  if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    gh_perror("Couldn't create %s socket", __func__);
    return 0;
  }
  socket_bindtodevice(sd, o.device);

  sock.sin_family = AF_INET;
  sock.sin_addr.s_addr = ftp->server.s_addr;
  sock.sin_port = htons(ftp->port);
  res = connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in));
  if (res < 0)
    fatal("Your FTP bounce proxy server won't talk to us!");
  if (o.verbose || o.debugging)
    log_write(LOG_STDOUT, "Connected:");
  while ((res = recvtime(sd, recvbuf, sizeof(recvbuf) - 1, 7, NULL)) > 0) {
    if (o.debugging || o.verbose) {
      recvbuf[res] = '\0';
      log_write(LOG_STDOUT, "%s", recvbuf);
    }
  }
  if (res < 0)
    pfatal("recv problem from FTP bounce server");

  Snprintf(command, 511, "USER %s\r\n", ftp->user);

  send(sd, command, strlen(command), 0);
  res = recvtime(sd, recvbuf, sizeof(recvbuf) - 1, 12, NULL);
  if (res <= 0)
    pfatal("recv problem from FTP bounce server");
  recvbuf[res] = '\0';
  if (o.debugging)
    log_write(LOG_STDOUT, "sent username, received: %s", recvbuf);
  if (recvbuf[0] == '5')
    fatal("Your FTP bounce server doesn't like the username \"%s\"", ftp->user);

  if (!strncmp(recvbuf, "230", 3)) {
    // 230 User logged in
    // No need to send PASS
    if (o.verbose)
      log_write(LOG_STDOUT, "Login credentials accepted by FTP server!\n");
    ftp->sd = sd;
    return sd;
  }
  Snprintf(command, 511, "PASS %s\r\n", ftp->pass);

  send(sd, command, strlen(command), 0);
  res = recvtime(sd, recvbuf, sizeof(recvbuf) - 1, 12, NULL);
  if (res < 0)
    pfatal("recv problem from FTP bounce server");
  if (!res) {
    error("Timeout from bounce server ...");
  } else {
    recvbuf[res] = '\0';
    if (o.debugging)
      log_write(LOG_STDOUT, "sent password, received: %s", recvbuf);
    if (recvbuf[0] == '5')
      fatal("Your FTP bounce server refused login combo (%s/%s)", ftp->user, ftp->pass);
  }
  while ((res = recvtime(sd, recvbuf, sizeof(recvbuf) - 1, 2, NULL)) > 0) {
    if (o.debugging) {
      recvbuf[res] = '\0';
      log_write(LOG_STDOUT, "%s", recvbuf);
    }
  }
  if (res < 0)
    pfatal("recv problem from FTP bounce server");
  if (o.verbose)
    log_write(LOG_STDOUT, "Login credentials accepted by FTP server!\n");

  ftp->sd = sd;
  return sd;
}

/* FTP bounce attack scan.  This function is rather lame and should be
   rewritten.  But I don't think it is used much anyway.  If I'm going to
   allow FTP bounce scan, I should really allow SOCKS proxy scan.  */
void bounce_scan(Target *target, u16 *portarray, int numports,
                 struct ftpinfo *ftp) {
  o.current_scantype = BOUNCE_SCAN;

  ScanProgressMeter *SPM;
  int res , sd = ftp->sd,  i = 0;
  const char *t = (const char *)target->v4hostip();
  int retriesleft = FTP_RETRIES;
  char recvbuf[2048];
  char targetstr[20];
  char command[512];
  unsigned short portno, p1, p2;
  int timedout;
  bool privok = false;

  if (numports == 0)
    return; /* nothing to scan for */

  Snprintf(targetstr, 20, "%d,%d,%d,%d,", UC(t[0]), UC(t[1]), UC(t[2]), UC(t[3]));

  SPM = new ScanProgressMeter(scantype2str(BOUNCE_SCAN));
  for (i = 0; i < numports; i++) {

    /* Check for timeout */
    if (target->timedOut(NULL)) {
      Snprintf(recvbuf, sizeof(recvbuf), "Target timed out");
      SPM->endTask(NULL, recvbuf);
      delete SPM;
      return;
    }

    portno = htons(portarray[i]);
    p1 = ((unsigned char *) &portno)[0];
    p2 = ((unsigned char *) &portno)[1];
    Snprintf(command, 512, "PORT %s%i,%i\r\n", targetstr, p1, p2);
    if (o.debugging)
      log_write(LOG_STDOUT, "Attempting command: %s", command);
    if (send(sd, command, strlen(command), 0) < 0 ) {
      gh_perror("send in %s", __func__);
      if (retriesleft) {
        if (o.verbose || o.debugging)
          log_write(LOG_STDOUT, "Our FTP proxy server hung up on us!  retrying\n");
        retriesleft--;
        close(sd);
        ftp->sd = ftp_anon_connect(ftp);
        if (ftp->sd < 0) {
          Snprintf(recvbuf, sizeof(recvbuf), "Error connecting");
          SPM->endTask(NULL, recvbuf);
          delete SPM;
          return;
        }
        sd = ftp->sd;
        i--;
      } else {
        error("Our socket descriptor is dead and we are out of retries. Giving up.");
        close(sd);
        ftp->sd = -1;
        Snprintf(recvbuf, sizeof(recvbuf), "Max retries exceeded");
        SPM->endTask(NULL, recvbuf);
        delete SPM;
        return;
      }
    } else { /* Our send is good */
      res = recvtime(sd, recvbuf, 2048, 15, NULL);
      if (res <= 0) {
        perror("recv problem from FTP bounce server");
      } else { /* our recv is good */
        recvbuf[res] = '\0';
        if (o.debugging)
          log_write(LOG_STDOUT, "result of port query on port %i: %s",
                                     portarray[i],  recvbuf);
        if (recvbuf[0] == '5' && !privok) {
          if (portarray[i] > 1023) {
            fatal("Your FTP bounce server sucks, it won't let us feed bogus ports!");
          } else {
            error("Your FTP bounce server doesn't allow privileged ports, skipping them.");
            while (i < numports && portarray[i] < 1024) i++;
            if (i >= numports) {
              fatal("And you didn't want to scan any unprivileged ports.  Giving up.");
            }
          }
        } else { /* Not an error message */
          if (portarray[i] < 1024) {
            privok = true;
          }
          if (send(sd, "LIST\r\n", 6, 0) > 0 ) {
            res = recvtime(sd, recvbuf, 2048, 12, &timedout);
            if (res < 0) {
              perror("recv problem from FTP bounce server");
            } else if (res == 0) {
              recvbuf[res] = '\0';
              if (timedout)
                target->ports.setPortState(portarray[i], IPPROTO_TCP, PORT_FILTERED);
              else target->ports.setPortState(portarray[i], IPPROTO_TCP, PORT_CLOSED);
            } else {
              recvbuf[res] = '\0';
              if (o.debugging)
                log_write(LOG_STDOUT, "result of LIST: %s", recvbuf);
              if (!strncmp(recvbuf, "500", 3)) {
                /* oh dear, we are not aligned properly */
                if (o.verbose || o.debugging)
                  error("FTP command misalignment detected ... correcting.");
                res = recvtime(sd, recvbuf, 2048, 10, NULL);
              }
              if (recvbuf[0] == '1') {
                res = recvtime(sd, recvbuf, 2048, 10, &timedout);
                if (res < 0)
                  perror("recv problem from FTP bounce server");
                else if (timedout || res == 0) {
                  // Timed out waiting for LIST to complete; probably filtered.
                  if(send(sd, "ABOR\r\n", 6, 0) > 0) {
                    target->ports.setPortState(portarray[i], IPPROTO_TCP, PORT_FILTERED);
                  }
                  // Get response and discard
                  res = recvtime(sd, recvbuf, 2048, 10, &timedout);
                  recvbuf[0] = '\0';
                  goto nextport;
                }
                else {
                  recvbuf[res] = '\0';
                  if (res > 0) {
                    if (o.debugging)
                      log_write(LOG_STDOUT, "nxt line: %s", recvbuf);
                    if (recvbuf[0] == '4' && recvbuf[1] == '2' && recvbuf[2] == '6') {
                      target->ports.forgetPort(portarray[i], IPPROTO_TCP);
                      if (o.debugging || o.verbose)
                        log_write(LOG_STDOUT, "Changed my mind about port %i\n", portarray[i]);
                    }
                  }
                }
              }
              if (recvbuf[0] == '2') {
                target->ports.setPortState(portarray[i], IPPROTO_TCP, PORT_OPEN);
              } else {
                /* This means the port is closed ... */
                target->ports.setPortState(portarray[i], IPPROTO_TCP, PORT_CLOSED);
              }
            }
          }
        }
      }
    }
    nextport:
    if (SPM->mayBePrinted(NULL)) {
      SPM->printStatsIfNecessary((double) i / numports, NULL);
    }
    else if (keyWasPressed()) {
      SPM->printStats((double) i / numports, NULL);
      log_flush(LOG_STDOUT);
    }
  }

  Snprintf(recvbuf, sizeof(recvbuf), "%d total ports", numports);
  SPM->endTask(NULL, recvbuf);
  delete SPM;
  return;
}
