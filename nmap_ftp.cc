
/***************************************************************************
 * nmap_ftp.cc -- Nmap's FTP routines used for FTP bounce scan (-b)
 *                                                                         *
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
                  if (o.debugging)
                    log_write(LOG_STDOUT, "nxt line: %s", recvbuf);
                  if (recvbuf[0] == '4' && recvbuf[1] == '2' && recvbuf[2] == '6') {
                    target->ports.forgetPort(portarray[i], IPPROTO_TCP);
                    if (o.debugging || o.verbose)
                      log_write(LOG_STDOUT, "Changed my mind about port %i\n", portarray[i]);
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
