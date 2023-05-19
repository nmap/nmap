
/***************************************************************************
 * timing.h -- Functions related to computing scan timing (such as keeping *
 * track of and adjusting smoothed round trip times, statistical           *
 * deviations, timeout values, etc.  Various user options (such as the     *
 * timing policy (-T)) also play a role in these calculations.             *
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

#ifndef NMAP_TIMING_H
#define NMAP_TIMING_H

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

#include <nbase.h> /* u32 */

/* Based on TCP congestion control techniques from RFC2581. */
struct ultra_timing_vals {
  double cwnd; /* Congestion window - in probes */
  int ssthresh; /* The threshold above which mode is changed from slow start
                   to congestion avoidance */
  /* The number of replies we would expect if every probe produced a reply. This
     is almost like the total number of probes sent but it is not incremented
     until a reply is received or a probe times out. This and
     num_replies_received are used to scale congestion window increments. */
  int num_replies_expected;
  /* The number of replies we've received to probes of any type. */
  int num_replies_received;
  /* Number of updates to this timing structure (generally packet receipts). */
  int num_updates;
  /* Last time values were adjusted for a drop (you usually only want
     to adjust again based on probes sent after that adjustment so a
     sudden batch of drops doesn't destroy timing.  Init to now */
  struct timeval last_drop;

  double cc_scale(const struct scan_performance_vars *perf);
  void ack(const struct scan_performance_vars *perf, double scale = 1.0);
  void drop(unsigned in_flight,
    const struct scan_performance_vars *perf, const struct timeval *now);
  void drop_group(unsigned in_flight,
    const struct scan_performance_vars *perf, const struct timeval *now);
};

/* These are mainly initializers for ultra_timing_vals. */
struct scan_performance_vars {
  int low_cwnd;  /* The lowest cwnd (congestion window) allowed */
  int host_initial_cwnd; /* Initial congestion window for ind. hosts */
  int group_initial_cwnd; /* Initial congestion window for all hosts as a group */
  int max_cwnd; /* I should never have more than this many probes
                   outstanding */
  int slow_incr; /* How many probes are incremented for each response
                    in slow start mode */
  int ca_incr; /* How many probes are incremented per (roughly) rtt in
                  congestion avoidance mode */
  int cc_scale_max; /* The maximum scaling factor for congestion window
                       increments. */
  int initial_ssthresh;
  double group_drop_cwnd_divisor; /* all-host group cwnd divided by this
                                     value if any packet drop occurs */
  double group_drop_ssthresh_divisor; /* used to drop the group ssthresh when
                                         any drop occurs */
  double host_drop_ssthresh_divisor; /* used to drop the host ssthresh when
                                         any drop occurs */

  /* Do initialization after the global NmapOps table has been filled in. */
  void init();
};

struct timeout_info {
  int srtt; /* Smoothed rtt estimate (microseconds) */
  int rttvar; /* Rout trip time variance */
  int timeout; /* Current timeout threshold (microseconds) */
};

/* Call this function on a newly allocated struct timeout_info to
   initialize the values appropriately */
void initialize_timeout_info(struct timeout_info *to);

/* Same as adjust_timeouts(), except this one allows you to specify
 the receive time too (which could be because it was received a while
 back or it could be for efficiency because the caller already knows
 the current time */
void adjust_timeouts2(const struct timeval *sent,
                      const struct timeval *received,
                      struct timeout_info *to);

/* Adjust our timeout values based on the time the latest probe took for a
   response.  We update our RTT averages, etc. */
void adjust_timeouts(struct timeval sent, struct timeout_info *to);

#define DEFAULT_CURRENT_RATE_HISTORY 5.0

/* Sleeps if necessary to ensure that it isn't called twice within less
   time than o.send_delay.  If it is passed a non-null tv, the POST-SLEEP
   time is recorded in it */
void enforce_scan_delay(struct timeval *tv);

/* This class measures current and lifetime average rates for some quantity. */
class RateMeter {
  public:
    RateMeter(double current_rate_history = DEFAULT_CURRENT_RATE_HISTORY);

    void start(const struct timeval *now = NULL);
    void stop(const struct timeval *now = NULL);
    void update(double amount, const struct timeval *now = NULL);
    double getOverallRate(const struct timeval *now = NULL) const;
    double getCurrentRate(const struct timeval *now = NULL, bool update = true);
    double getTotal(void) const;
    double elapsedTime(const struct timeval *now = NULL) const;

  private:
    /* How many seconds to look back when calculating the "current" rates. */
    double current_rate_history;

    /* When this meter started recording. */
    struct timeval start_tv;
    /* When this meter stopped recording. */
    struct timeval stop_tv;
    /* The last time the current sample rates were updated. */
    struct timeval last_update_tv;

    double total;
    double current_rate;

    static bool isSet(const struct timeval *tv);
};

/* A specialization of RateMeter that measures packet and byte rates. */
class PacketRateMeter {
  public:
    PacketRateMeter(double current_rate_history = DEFAULT_CURRENT_RATE_HISTORY);

    void start(const struct timeval *now = NULL);
    void stop(const struct timeval *now = NULL);
    void update(u32 len, const struct timeval *now = NULL);
    double getOverallPacketRate(const struct timeval *now = NULL) const;
    double getCurrentPacketRate(const struct timeval *now = NULL, bool update = true);
    double getOverallByteRate(const struct timeval *now = NULL) const;
    double getCurrentByteRate(const struct timeval *now = NULL, bool update = true);
    unsigned long long getNumPackets(void) const;
    unsigned long long getNumBytes(void) const;

  private:
    RateMeter packet_rate_meter;
    RateMeter byte_rate_meter;
};

class ScanProgressMeter {
 public:
  /* A COPY of stypestr is made and saved for when stats are printed */
  ScanProgressMeter(const char *stypestr);
  ~ScanProgressMeter();
/* Decides whether a timing report is likely to even be
   printed.  There are stringent limitations on how often they are
   printed, as well as the verbosity level that must exist.  So you
   might as well check this before spending much time computing
   progress info.  now can be NULL if caller doesn't have the current
   time handy.  Just because this function returns true does not mean
   that the next printStatsIfNecessary will always print something.
   It depends on whether time estimates have changed, which this func
   doesn't even know about. */
  bool mayBePrinted(const struct timeval *now);

/* Prints an estimate of when this scan will complete.  It only does
   so if mayBePrinted() is true, and it seems reasonable to do so
   because the estimate has changed significantly.  Returns whether
   or not a line was printed.*/
  bool printStatsIfNecessary(double perc_done, const struct timeval *now);

  /* Prints an estimate of when this scan will complete. */
  bool printStats(double perc_done, const struct timeval *now);

  /* Prints that this task is complete. */
  bool endTask(const struct timeval *now, const char *additional_info) { return beginOrEndTask(now, additional_info, false); }

  struct timeval begin; /* When this ScanProgressMeter was instantiated */
 private:
  struct timeval last_print_test; /* Last time printStatsIfNecessary was called */
  struct timeval last_print; /* The most recent time the ETC was printed */
  char *scantypestr;
  struct timeval last_est; /* The latest PRINTED estimate */

  bool beginOrEndTask(const struct timeval *now, const char *additional_info, bool beginning);
};

#endif /* NMAP_TIMING_H */

