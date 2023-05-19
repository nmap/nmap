
/***************************************************************************
 * timing.cc -- Functions related to computing scan timing (such as        *
 * keeping track of and adjusting smoothed round trip times, statistical   *
 * deviations, timeout values, etc.  Various user options (such as the     *
 * timing policy (-T)) also play a role in these calculations              *
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

#include "timing.h"
#include "NmapOps.h"
#include "utils.h"
#include "nmap_error.h"
#include "xml.h"

#include <math.h>
#include <limits>

extern NmapOps o;

/* Call this function on a newly allocated struct timeout_info to
   initialize the values appropriately */
void initialize_timeout_info(struct timeout_info *to) {
  to->srtt = -1;
  to->rttvar = -1;
  to->timeout = o.initialRttTimeout() * 1000;
}

/* Adjust our timeout values based on the time the latest probe took for a
   response.  We update our RTT averages, etc. */
void adjust_timeouts(struct timeval sent, struct timeout_info *to) {
  struct timeval received;
  gettimeofday(&received, NULL);

  adjust_timeouts2(&sent, &received, to);
  return;
}

/* Same as adjust_timeouts(), except this one allows you to specify
 the receive time too (which could be because it was received a while
 back or it could be for efficiency because the caller already knows
 the current time */
void adjust_timeouts2(const struct timeval *sent,
                      const struct timeval *received,
                      struct timeout_info *to) {
  long delta = 0;

  if (o.debugging > 3) {
    log_write(LOG_STDOUT, "Timeout vals: srtt: %d rttvar: %d to: %d ", to->srtt, to->rttvar, to->timeout);
  }

  delta = TIMEVAL_SUBTRACT(*received, *sent);

  /* Argh ... pcap receive time is sometimes a little off my
     getimeofday() results on various platforms :(.  So a packet may
     appear to be received as much as a hundredth of a second before
     it was sent.  So I will allow small negative RTT numbers */
  if (delta < 0 && delta > -50000) {
    if (o.debugging > 2)
      log_write(LOG_STDOUT, "Small negative delta (probably due to libpcap time / gettimeofday() discrepancy) - adjusting from %lius to %dus\n", delta, 10000);
    delta = 10000;
  }


  if (to->srtt == -1 && to->rttvar == -1) {
    /* We need to initialize the sucker ... */
    to->srtt = delta;
    to->rttvar = MAX(5000, MIN(to->srtt, 2000000));
    to->timeout = to->srtt + (to->rttvar << 2);
  } else {
    long rttdelta;

    if (delta >= 8000000 || delta < 0) {
      if (o.verbose)
        error("%s: packet supposedly had rtt of %ld microseconds.  Ignoring time.", __func__, delta);
      return;
    }
    rttdelta = delta - to->srtt;
    /* sanity check 2*/
    if (rttdelta > 1500000 && rttdelta > 3 * to->srtt + 2 * to->rttvar) {
      if (o.debugging) {
        log_write(LOG_STDOUT, "Bogus rttdelta: %ld (srtt %d) ... ignoring\n", rttdelta, to->srtt);
      }
      return;
    }
    to->srtt += rttdelta >> 3;
    to->rttvar += (ABS(rttdelta) - to->rttvar) >> 2;
    to->timeout = to->srtt + (to->rttvar << 2);
  }
  if (to->rttvar > 2300000) {
    error("RTTVAR has grown to over 2.3 seconds, decreasing to 2.0");
    to->rttvar = 2000000;
  }

  /* It hurts to do this ... it really does ... but otherwise we are being
     too risky */
  to->timeout = box(o.minRttTimeout() * 1000, o.maxRttTimeout() * 1000,
                    to->timeout);

  if (o.scan_delay)
    to->timeout = MAX((unsigned) to->timeout, o.scan_delay * 1000);

  if (o.debugging > 3) {
    log_write(LOG_STDOUT, "delta %ld ==> srtt: %d rttvar: %d to: %d\n", delta, to->srtt, to->rttvar, to->timeout);
  }

  /* if (to->srtt < 0 || to->rttvar < 0 || to->timeout < 0 || delta < -50000000 ||
      sent->tv_sec == 0 || received->tv_sec == 0 ) {
    fatal("Serious time computation problem in adjust_timeout ... received = (%ld, %ld) sent=(%ld,%ld) delta = %ld srtt = %d rttvar = %d to = %d", (long) received->tv_sec, (long)received->tv_usec, (long) sent->tv_sec, (long) sent->tv_usec, delta, to->srtt, to->rttvar, to->timeout);
  } */
}

/* Sleeps if necessary to ensure that it isn't called twice within less
   time than o.send_delay.  If it is passed a non-null tv, the POST-SLEEP
   time is recorded in it */
void enforce_scan_delay(struct timeval *tv) {
  static int init = -1;
  static struct timeval lastcall;
  struct timeval now;
  int time_diff;

  if (!o.scan_delay) {
    if (tv) gettimeofday(tv, NULL);
    return;
  }

  if (init == -1) {
    gettimeofday(&lastcall, NULL);
    init = 0;
    if (tv)
      memcpy(tv, &lastcall, sizeof(struct timeval));
    return;
  }

  gettimeofday(&now, NULL);
  time_diff = TIMEVAL_MSEC_SUBTRACT(now, lastcall);
  if (time_diff < (int) o.scan_delay) {
    if (o.debugging > 1) {
      log_write(LOG_PLAIN, "Sleeping for %d milliseconds in %s()\n", o.scan_delay - time_diff, __func__);
    }
    usleep((o.scan_delay - time_diff) * 1000);
    gettimeofday(&lastcall, NULL);
  } else
    memcpy(&lastcall, &now, sizeof(struct timeval));
  if (tv) {
    memcpy(tv, &lastcall, sizeof(struct timeval));
  }

  return;
}


/* Returns the scaling factor to use when incrementing the congestion
   window. */
double ultra_timing_vals::cc_scale(const struct scan_performance_vars *perf) {
  double ratio;

  assert(num_replies_received > 0);
  ratio = (double) num_replies_expected / num_replies_received;

  return MIN(ratio, perf->cc_scale_max);
}

/* Update congestion variables for the receipt of a reply. */
void ultra_timing_vals::ack(const struct scan_performance_vars *perf, double scale) {
  num_replies_received++;

  if (cwnd < ssthresh) {
    /* In slow start mode. "During slow start, a TCP increments cwnd by at most
       SMSS bytes for each ACK received that acknowledges new data." */
    cwnd += perf->slow_incr * cc_scale(perf) * scale;
    if (cwnd > ssthresh)
      cwnd = ssthresh;
  } else {
    /* Congestion avoidance mode. "During congestion avoidance, cwnd is
       incremented by 1 full-sized segment per round-trip time (RTT). The
       equation
         cwnd += SMSS*SMSS/cwnd
       provides an acceptable approximation to the underlying principle of
       increasing cwnd by 1 full-sized segment per RTT." */
    cwnd += perf->ca_incr / cwnd * cc_scale(perf) * scale;
  }
  if (cwnd > perf->max_cwnd)
    cwnd = perf->max_cwnd;
}

/* Update congestion variables for a detected drop. */
void ultra_timing_vals::drop(unsigned in_flight,
  const struct scan_performance_vars *perf, const struct timeval *now) {
  /* "When a TCP sender detects segment loss using the retransmission timer, the
     value of ssthresh MUST be set to no more than the value
       ssthresh = max (FlightSize / 2, 2*SMSS)
     Furthermore, upon a timeout cwnd MUST be set to no more than the loss
     window, LW, which equals 1 full-sized segment (regardless of the value of
     IW)." */
  cwnd = perf->low_cwnd;
  ssthresh = (int) MAX(in_flight / perf->host_drop_ssthresh_divisor, 2);
  last_drop = *now;
}

/* Update congestion variables for a detected drop, but less aggressively for
   group congestion control. */
void ultra_timing_vals::drop_group(unsigned in_flight,
  const struct scan_performance_vars *perf, const struct timeval *now) {
  cwnd = MAX(perf->low_cwnd, cwnd / perf->group_drop_cwnd_divisor);
  ssthresh = (int) MAX(in_flight / perf->group_drop_ssthresh_divisor, 2);
  last_drop = *now;
}

/* Do initialization after the global NmapOps table has been filled in. */
void scan_performance_vars::init() {
  /* TODO: I should revisit these values for tuning.  They should probably
     at least be affected by -T. */
  low_cwnd = o.min_parallelism ? o.min_parallelism : 1;
  max_cwnd = MAX(low_cwnd, o.max_parallelism ? o.max_parallelism : 300);
  group_initial_cwnd = box(low_cwnd, max_cwnd, 10);
  host_initial_cwnd = group_initial_cwnd;
  slow_incr = 1;
  /* The congestion window grows faster with more aggressive timing. */
  if (o.timing_level < 4)
    ca_incr = 1;
  else
    ca_incr = 2;
  cc_scale_max = 50;
  initial_ssthresh = 75;
  group_drop_cwnd_divisor = 2.0;
  /* Change the amount that ssthresh drops based on the timing level. */
  double ssthresh_divisor;
  if (o.timing_level <= 3)
    ssthresh_divisor = (3.0 / 2.0);
  else if (o.timing_level <= 4)
    ssthresh_divisor = (4.0 / 3.0);
  else
    ssthresh_divisor = (5.0 / 4.0);
  group_drop_ssthresh_divisor = ssthresh_divisor;
  host_drop_ssthresh_divisor = ssthresh_divisor;
}

/* current_rate_history defines how far back (in seconds) we look when
   calculating the current rate. */
RateMeter::RateMeter(double current_rate_history) {
  this->current_rate_history = current_rate_history;
  start_tv.tv_sec = 0;
  start_tv.tv_usec = 0;
  stop_tv.tv_sec = 0;
  stop_tv.tv_usec = 0;
  last_update_tv.tv_sec = 0;
  last_update_tv.tv_usec = 0;
  total = 0.0;
  current_rate = 0.0;
  assert(!isSet(&start_tv));
  assert(!isSet(&stop_tv));
}

void RateMeter::start(const struct timeval *now) {
  assert(!isSet(&start_tv));
  assert(!isSet(&stop_tv));
  if (now == NULL)
    gettimeofday(&start_tv, NULL);
  else
    start_tv = *now;
}

void RateMeter::stop(const struct timeval *now) {
  assert(isSet(&start_tv));
  assert(!isSet(&stop_tv));
  if (now == NULL)
    gettimeofday(&stop_tv, NULL);
  else
    stop_tv = *now;
}

/* Update the rates to reflect the given amount added to the total at the time
   now. If now is NULL, get the current time with gettimeofday. */
void RateMeter::update(double amount, const struct timeval *now) {
  struct timeval tv;
  double diff;
  double interval;
  double count;

  assert(isSet(&start_tv));
  assert(!isSet(&stop_tv));

  /* Update the total. */
  total += amount;

  if (now == NULL) {
    gettimeofday(&tv, NULL);
    now = &tv;
  }
  if (!isSet(&last_update_tv))
    last_update_tv = start_tv;

  /* Calculate the approximate moving average of how much was recorded in the
     last current_rate_history seconds. This average is what is returned as the
     "current" rate. */

  /* How long since the last update? */
  diff = TIMEVAL_SUBTRACT(*now, last_update_tv) / 1000000.0;

  if (diff < -current_rate_history)
    /* This happened farther in the past than we care about. */
    return;

  if (diff < 0.0) {
    /* If the event happened in the past, just add it into the total and don't
       change last_update_tv, as if it had happened at the same time as the most
       recent event. */
    now = &last_update_tv;
    diff = 0.0;
  }

  /* Find out how far back in time to look. We want to look back
     current_rate_history seconds, or to when the last update occurred,
     whichever is longer. However, we never look past the start. */
  struct timeval tmp;
  /* Find the time current_rate_history seconds after the start. That's our
     threshold for deciding how far back to look. */
  TIMEVAL_ADD(tmp, start_tv, (time_t) (current_rate_history * 1000000.0));
  if (TIMEVAL_AFTER(*now, tmp))
    interval = MAX(current_rate_history, diff);
  else
    interval = TIMEVAL_SUBTRACT(*now, start_tv) / 1000000.0;
  assert(diff <= interval + std::numeric_limits<double>::epsilon());
  /* If we record an amount in the very same instant that the timer is started,
     there's no way to calculate meaningful rates. Ignore it. */
  if (interval == 0.0)
    return;

  /* To calculate the approximate average of the rate over the last
     interval seconds, we assume that the rate was constant over that interval.
     We calculate how much would have been received in that interval, ignoring
     the first diff seconds' worth:
       (interval - diff) * current_rate.
     Then we add how much was received in the most recent diff seconds. Divide
     by the width of the interval to get the average. */
  count = (interval - diff) * current_rate + amount;
  current_rate = count / interval;

  last_update_tv = *now;
}

double RateMeter::getOverallRate(const struct timeval *now) const {
  double elapsed;

  elapsed = elapsedTime(now);
  if (elapsed <= 0.0)
    return 0.0;
  else
    return total / elapsed;
}

/* Get the "current" rate (actually a moving average of the last
   current_rate_history seconds). If update is true (its default value), lower
   the rate to account for the time since the last record. */
double RateMeter::getCurrentRate(const struct timeval *now, bool update) {
  if (update)
    this->update(0.0, now);

  return current_rate;
}

double RateMeter::getTotal(void) const {
  return total;
}

/* Get the number of seconds the meter has been running: if it has been stopped,
   the amount of time between start and stop, or if it is still running, the
   amount of time between start and now. */
double RateMeter::elapsedTime(const struct timeval *now) const {
  struct timeval tv;
  const struct timeval *end_tv;

  assert(isSet(&start_tv));

  if (isSet(&stop_tv)) {
    end_tv = &stop_tv;
  } else if (now == NULL) {
    gettimeofday(&tv, NULL);
    end_tv = &tv;
  } else {
    end_tv = now;
  }

  return TIMEVAL_SUBTRACT(*end_tv, start_tv) / 1000000.0;
}

/* Returns true if tv has been initialized; i.e., its members are not all
   zero. */
bool RateMeter::isSet(const struct timeval *tv) {
  return tv->tv_sec != 0 || tv->tv_usec != 0;
}

PacketRateMeter::PacketRateMeter(double current_rate_history) {
  packet_rate_meter = RateMeter(current_rate_history);
  byte_rate_meter = RateMeter(current_rate_history);
}

void PacketRateMeter::start(const struct timeval *now) {
  packet_rate_meter.start(now);
  byte_rate_meter.start(now);
}

void PacketRateMeter::stop(const struct timeval *now) {
  packet_rate_meter.stop(now);
  byte_rate_meter.stop(now);
}

/* Record one packet of length len. */
void PacketRateMeter::update(u32 len, const struct timeval *now) {
  packet_rate_meter.update(1, now);
  byte_rate_meter.update(len, now);
}

double PacketRateMeter::getOverallPacketRate(const struct timeval *now) const {
  return packet_rate_meter.getOverallRate(now);
}

double PacketRateMeter::getCurrentPacketRate(const struct timeval *now, bool update) {
  return packet_rate_meter.getCurrentRate(now, update);
}

double PacketRateMeter::getOverallByteRate(const struct timeval *now) const {
  return byte_rate_meter.getOverallRate(now);
}

double PacketRateMeter::getCurrentByteRate(const struct timeval *now, bool update) {
  return byte_rate_meter.getCurrentRate(now, update);
}

unsigned long long PacketRateMeter::getNumPackets(void) const {
  return (unsigned long long) packet_rate_meter.getTotal();
}

unsigned long long PacketRateMeter::getNumBytes(void) const {
  return (unsigned long long) byte_rate_meter.getTotal();
}

ScanProgressMeter::ScanProgressMeter(const char *stypestr) {
  scantypestr = strdup(stypestr);
  gettimeofday(&begin, NULL);
  last_print_test = begin;
  memset(&last_print, 0, sizeof(last_print));
  memset(&last_est, 0, sizeof(last_est));
  beginOrEndTask(&begin, NULL, true);
}

ScanProgressMeter::~ScanProgressMeter() {
  if (scantypestr) {
    free(scantypestr);
    scantypestr = NULL;
  }
}

/* Decides whether a timing report is likely to even be
   printed.  There are stringent limitations on how often they are
   printed, as well as the verbosity level that must exist.  So you
   might as well check this before spending much time computing
   progress info.  now can be NULL if caller doesn't have the current
   time handy.  Just because this function returns true does not mean
   that the next printStatsIfNecessary will always print something.
   It depends on whether time estimates have changed, which this func
   doesn't even know about. */
bool ScanProgressMeter::mayBePrinted(const struct timeval *now) {
  struct timeval tv;

  if (!o.verbose)
    return false;

  if (!now) {
    gettimeofday(&tv, NULL);
    now = (const struct timeval *) &tv;
  }

  if (last_print.tv_sec == 0) {
    /* We've never printed before -- the rules are less stringent */
    if (difftime(now->tv_sec, begin.tv_sec) > 30)
      return true;
    else
      return false;
  }

  if (difftime(now->tv_sec, last_print_test.tv_sec) < 3)
    return false;  /* No point even checking too often */

  /* We'd never want to print more than once per 30 seconds */
  if (difftime(now->tv_sec, last_print.tv_sec) < 30)
    return false;

  return true;
}

/* Return an estimate of the time remaining if a process was started at begin
   and is perc_done of the way finished. Returns inf if perc_done == 0.0. */
static double estimate_time_left(double perc_done,
                                 const struct timeval *begin,
                                 const struct timeval *now) {
  double time_used_s;
  double time_needed_s;

  time_used_s = difftime(now->tv_sec, begin->tv_sec);
  time_needed_s = time_used_s / perc_done;

  return time_needed_s - time_used_s;
}

/* Prints an estimate of when this scan will complete.  It only does
   so if mayBePrinted() is true, and it seems reasonable to do so
   because the estimate has changed significantly.  Returns whether
   or not a line was printed.*/
bool ScanProgressMeter::printStatsIfNecessary(double perc_done,
                                               const struct timeval *now) {
  struct timeval tvtmp;
  double time_left_s;
  bool printit = false;

  if (!now) {
    gettimeofday(&tvtmp, NULL);
    now = (const struct timeval *) &tvtmp;
  }

  if (!mayBePrinted(now))
    return false;

  last_print_test = *now;

  if (perc_done <= 0.003)
    return false; /* Need more info first */

  assert(perc_done <= 1.0);

  time_left_s = estimate_time_left(perc_done, &begin, now);

  if (time_left_s < 30)
    return false; /* No point in updating when it is virtually finished. */

  if (last_est.tv_sec == 0) {
    /* We don't have an estimate yet (probably means a low completion). */
    printit = true;
  } else if (TIMEVAL_AFTER(*now, last_est)) {
    /* The last estimate we printed has passed. Print a new one. */
    printit = true;
  } else {
    /* If the estimate changed by more than 3 minutes, and if that change
       represents at least 5% of the total time, print it. */
    double prev_est_total_time_s = difftime(last_est.tv_sec, begin.tv_sec);
    double prev_est_time_left_s = difftime(last_est.tv_sec, last_print.tv_sec);
    double change_abs_s = ABS(prev_est_time_left_s - time_left_s);
    if (o.debugging || (change_abs_s > 15 && change_abs_s > .05 * prev_est_total_time_s))
      printit = true;
  }

  if (printit) {
     return printStats(perc_done, now);
  }

  return false;
}

/* Prints an estimate of when this scan will complete.  */
bool ScanProgressMeter::printStats(double perc_done,
                                   const struct timeval *now) {
  struct timeval tvtmp;
  double time_left_s;
  time_t timet;
  struct tm ltime;
  int err;

  if (!now) {
    gettimeofday(&tvtmp, NULL);
    now = (const struct timeval *) &tvtmp;
  }

  last_print = *now;

  // If we're less than 1% done we probably don't have enough
  // data for decent timing estimates. Also with perc_done == 0
  // these elements will be nonsensical.
  if (perc_done < 0.01) {
    log_write(LOG_STDOUT, "%s Timing: About %.2f%% done\n",
        scantypestr, perc_done * 100);
    xml_open_start_tag("taskprogress");
    xml_attribute("task", "%s", scantypestr);
    xml_attribute("time", "%lu", (unsigned long) now->tv_sec);
    xml_attribute("percent", "%.2f", perc_done * 100);
    xml_close_empty_tag();
    xml_newline();
    log_flush(LOG_STDOUT|LOG_XML);
    return true;
  }

  /* Add 0.5 to get the effect of rounding in integer calculations. */
  time_left_s = estimate_time_left(perc_done, &begin, now) + 0.5;

  last_est = *now;
  last_est.tv_sec += (time_t)time_left_s;

  /* Get the estimated time of day at completion */
  timet = last_est.tv_sec;
  err = n_localtime(&timet, &ltime);

  if (!err) {
    log_write(LOG_STDOUT, "%s Timing: About %.2f%% done; ETC: %02d:%02d (%.f:%02.f:%02.f remaining)\n",
        scantypestr, perc_done * 100, ltime.tm_hour, ltime.tm_min,
        floor(time_left_s / 60.0 / 60.0),
        floor(fmod(time_left_s / 60.0, 60.0)),
        floor(fmod(time_left_s, 60.0)));
  }
  else {
    log_write(LOG_STDERR, "Timing error: n_localtime(%f): %s\n", (double) timet, strerror(err));
    log_write(LOG_STDOUT, "%s Timing: About %.2f%% done; ETC: Unknown (%.f:%02.f:%02.f remaining)\n",
        scantypestr, perc_done * 100,
        floor(time_left_s / 60.0 / 60.0),
        floor(fmod(time_left_s / 60.0, 60.0)),
        floor(fmod(time_left_s, 60.0)));
  }
  xml_open_start_tag("taskprogress");
  xml_attribute("task", "%s", scantypestr);
  xml_attribute("time", "%lu", (unsigned long) now->tv_sec);
  xml_attribute("percent", "%.2f", perc_done * 100);
  xml_attribute("remaining", "%.f", time_left_s);
  xml_attribute("etc", "%lu", (unsigned long) last_est.tv_sec);
  xml_close_empty_tag();
  xml_newline();
  log_flush(LOG_STDOUT|LOG_XML);

  return true;
}

/* Indicates that the task is beginning or ending, and that a message should
   be generated if appropriate.  Returns whether a message was printed.
   now may be NULL, if the caller doesn't have the current time handy.
   additional_info may be NULL if no additional information is necessary. */
bool ScanProgressMeter::beginOrEndTask(const struct timeval *now, const char *additional_info, bool beginning) {
  struct timeval tvtmp;
  struct tm tm;
  int err;
  time_t tv_sec;

  if (!o.verbose) {
    return false;
  }

  if (!now) {
    gettimeofday(&tvtmp, NULL);
    now = (const struct timeval *) &tvtmp;
  }

  tv_sec = now->tv_sec;
  err = n_localtime(&tv_sec, &tm);
  if (err)
    log_write(LOG_STDERR, "Timing error: n_localtime(%f): %s\n", (double) tv_sec, strerror(err));
  if (beginning) {
    if (!err)
      log_write(LOG_STDOUT, "Initiating %s at %02d:%02d", scantypestr, tm.tm_hour, tm.tm_min);
    else
      log_write(LOG_STDOUT, "Initiating %s", scantypestr);
    xml_open_start_tag("taskbegin");
    xml_attribute("task", "%s", scantypestr);
    xml_attribute("time", "%lu", (unsigned long) now->tv_sec);
    if (additional_info) {
      log_write(LOG_STDOUT, " (%s)", additional_info);
      xml_attribute("extrainfo", "%s", additional_info);
    }
    log_write(LOG_STDOUT, "\n");
    xml_close_empty_tag();
    xml_newline();
  } else {
    if (!err)
      log_write(LOG_STDOUT, "Completed %s at %02d:%02d, %.2fs elapsed", scantypestr, tm.tm_hour, tm.tm_min, TIMEVAL_MSEC_SUBTRACT(*now, begin) / 1000.0);
    else
      log_write(LOG_STDOUT, "Completed %s, %.2fs elapsed", scantypestr, TIMEVAL_MSEC_SUBTRACT(*now, begin) / 1000.0);
    xml_open_start_tag("taskend");
    xml_attribute("task", "%s", scantypestr);
    xml_attribute("time", "%lu", (unsigned long) now->tv_sec);
    if (additional_info) {
      log_write(LOG_STDOUT, " (%s)", additional_info);
      xml_attribute("extrainfo", "%s", additional_info);
    }
    log_write(LOG_STDOUT, "\n");
    xml_close_empty_tag();
    xml_newline();
  }
  log_flush(LOG_STDOUT|LOG_XML);
  return true;
}
