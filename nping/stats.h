
/***************************************************************************
 * PacketStats.h -- The PacketStats class handles packet statistics. It is *
 * intended to keep track of the number of packets and bytes sent and      *
 * received, keep track of start and finish times, etc.                    *
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
#ifndef __STATS_H__
#define __STATS_H__ 1

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "nping.h"

#ifndef WIN32
#include <sys/types.h>

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <sys/mman.h>
#include "nping_config.h"
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

/* Make sure we define a 64bit integer type */
#ifndef u64_t
    #if WIN32
      typedef unsigned __int64 u64_t;
    #else
      typedef unsigned long long u64_t;
    #endif
#endif

/* Timeval subtraction in microseconds */
#define TIMEVAL_SUBTRACT(a,b) (((a).tv_sec - (b).tv_sec) * 1000000 + (a).tv_usec - (b).tv_usec)
/* Timeval subtract in milliseconds */
#define TIMEVAL_MSEC_SUBTRACT(a,b) ((((a).tv_sec - (b).tv_sec) * 1000) + ((a).tv_usec - (b).tv_usec) / 1000)
/* Timeval subtract in seconds; truncate towards zero */
#define TIMEVAL_SEC_SUBTRACT(a,b) ((a).tv_sec - (b).tv_sec + (((a).tv_usec < (b).tv_usec) ? - 1 : 0))
/* Timeval subtract in fractional seconds; convert to float */
#define TIMEVAL_FSEC_SUBTRACT(a,b) ((a).tv_sec - (b).tv_sec + (((a).tv_usec - (b).tv_usec)/1000000.0))


class NpingTimer {

  private:
    struct timeval start_tv;
    struct timeval stop_tv;

  public:
    NpingTimer();
    ~NpingTimer();
    void reset();
    int start();
    int stop();
    double elapsed(struct timeval *now=NULL);
    bool is_started();
    bool is_stopped();


  private:
      bool timeval_set(const struct timeval *tv);
};


class NpingStats {

  private:
    u64_t packets_sent;
    u64_t packets_received;
    u64_t packets_echoed;

    u64_t bytes_sent;
    u64_t bytes_received;
    u64_t bytes_echoed;

    u32 echo_clients_served;

    NpingTimer tx_timer;  /* Timer for packet transmission.         */
    NpingTimer rx_timer;  /* Timer for packet reception.            */
    NpingTimer run_timer; /* Timer to measure Nping execution time. */

 public:
    NpingStats();
    ~NpingStats();

    void reset();

    int addSentPacket(u32 len);
    int addRecvPacket(u32 len);
    int addEchoedPacket(u32 len);
    int addEchoClientServed();

    int startClocks();
    int stopClocks();

    int startTxClock();
    int stopTxClock();

    int startRxClock();
    int stopRxClock();

    int startRuntime();
    int stopRuntime();

    double elapsedTx();
    double elapsedRx();
    double elapsedRuntime(struct timeval *now=NULL);

    u64_t getSentPackets();
    u64_t getSentBytes();

    u64_t getRecvPackets();
    u64_t getRecvBytes();

    u64_t getEchoedPackets();
    u64_t getEchoedBytes();
    u32 getEchoClientsServed();

    u64_t getLostPackets();
    double getLostPacketPercentage();
    double getLostPacketPercentage100();

    u64_t getUnmatchedPackets();
    double getUnmatchedPacketPercentage();
    double getUnmatchedPacketPercentage100();

    double getOverallTxPacketRate();
    double getOverallTxByteRate();

    double getOverallRxPacketRate();
    double getOverallRxByteRate();

};


#endif /* __STATS_H__ */
