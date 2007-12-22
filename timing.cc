
/***************************************************************************
 * timing.cc -- Functions related to computing scan timing (such as        *
 * keeping track of and adjusting smoothed round trip times, statistical   *
 * deviations, timeout values, etc.  Various user options (such as the     *
 * timing policy (-T)) also play a role in these calculations              *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2008 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, and version detection.                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-fingerprints or nmap-service-probes.                          *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                * 
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is just meant to        *
 * clarify our interpretation of derived works with some common examples.  *
 * These restrictions only apply when you actually redistribute Nmap.  For *
 * example, nothing stops you from writing and selling a proprietary       *
 * front-end to Nmap.  Just distribute it by itself, and point people to   *
 * http://insecure.org/nmap/ to download Nmap.                             *
 *                                                                         *
 * We don't consider these to be added restrictions on top of the GPL, but *
 * just a clarification of how we interpret "derived works" as it applies  *
 * to our GPL-licensed Nmap product.  This is similar to the way Linus     *
 * Torvalds has announced his interpretation of how "derived works"        *
 * applies to Linux kernel modules.  Our interpretation refers only to     *
 * Nmap - we don't speak for any other GPL products.                       *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included Copying.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to fyodor@insecure.org for possible incorporation into the main         *
 * distribution.  By sending these changes to Fyodor or one the            *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering Fyodor and Insecure.Com LLC the unlimited, non-exclusive right *
 * to reuse, modify, and relicense the code.  Nmap will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).  We also occasionally relicense the    *
 * code to third parties as discussed above.  If you wish to specify       *
 * special license conditions of your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License for more details at                              *
 * http://www.gnu.org/copyleft/gpl.html , or in the COPYING file included  *
 * with Nmap.                                                              *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include "timing.h"
#include "NmapOps.h"
#include "utils.h"

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
  }
  else {
    if (delta >= 8000000 || delta < 0) {
      if (o.verbose)
	error("%s: packet supposedly had rtt of %lu microseconds.  Ignoring time.", __func__, delta);
      return;
    }
    delta -= to->srtt;
    /* sanity check 2*/
    if (delta > 1500000 && delta > 3 * to->srtt + 2 * to->rttvar) {
      /* WANKER ALERT! */
      if (o.debugging) {
	log_write(LOG_STDOUT, "Bogus delta: %ld (srtt %d) ... ignoring\n", delta, to->srtt);
      }
      return;
    }
    to->srtt += delta >> 3;
    to->rttvar += (ABS(delta) - to->rttvar) >> 2;
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

ScanProgressMeter::ScanProgressMeter(char *stypestr) {
  scantypestr = strdup(stypestr);
  gettimeofday(&begin, NULL);
  last_print_test = begin;
  memset(&last_print, 0, sizeof(last_print));
  memset(&last_est, 0, sizeof(last_print));
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
   that the next printStatsIfNeccessary will always print something.
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
    if (TIMEVAL_MSEC_SUBTRACT(*now, begin) > 30000)
      return true;
    else return false;
  } 

  if (TIMEVAL_MSEC_SUBTRACT(*now, last_print_test) < 3000) 
    return false;  /* No point even checking too often */

  /* We'd never want to print more than once per 30 seconds */
  if (TIMEVAL_MSEC_SUBTRACT(*now, last_print) < 30000)
    return false;

  return true;
}

/* Prints an estimate of when this scan will complete.  It only does
   so if mayBePrinted() is true, and it seems reasonable to do so
   because the estimate has changed significantly.  Returns whether
   or not a line was printed.*/
bool ScanProgressMeter::printStatsIfNeccessary(double perc_done, 
					       const struct timeval *now) {
  struct timeval tvtmp;
  long time_used_ms;
  long time_needed_ms;
  long time_left_ms;
  long prev_est_time_left_ms; /* Time left as per prev. estimate */
  long change_abs_ms; /* absolute value of change */
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

  /* OK, now lets estimate the time to finish */
  time_used_ms = TIMEVAL_MSEC_SUBTRACT(*now, begin);
  time_needed_ms = (int) ((double) time_used_ms / perc_done);
  time_left_ms = time_needed_ms - time_used_ms;

  if (time_left_ms < 30000)
    return false; /* No point in updating when it is virtually finished. */

  /* If we have not printed before, or if our previous ETC has elapsed, print
     a new one */
  if (last_print.tv_sec < 0)
    printit = true;
  else {
    /* If the estimate changed by more than X minutes, and if that
       change represents at least X% of the time remaining, print
       it.  */
    prev_est_time_left_ms = TIMEVAL_MSEC_SUBTRACT(last_est, *now);
    change_abs_ms = ABS(prev_est_time_left_ms - time_left_ms);
    if (prev_est_time_left_ms <= 0)
      printit = true;
    else if (o.debugging || (change_abs_ms > 180000 && change_abs_ms > .05 * MAX(time_left_ms, prev_est_time_left_ms)))
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
  long time_used_ms;
  long time_needed_ms;
  long time_left_ms;
  long sec_left;
  time_t timet;
  struct tm *ltime;

  if (!now) {
    gettimeofday(&tvtmp, NULL);
    now = (const struct timeval *) &tvtmp;
  }
  
  /* OK, now lets estimate the time to finish */
  time_used_ms = TIMEVAL_MSEC_SUBTRACT(*now, begin);
  time_needed_ms = (int) ((double) time_used_ms / perc_done);
  time_left_ms = time_needed_ms - time_used_ms;

    /* Here we go! */
    last_print = *now;
    TIMEVAL_MSEC_ADD(last_est, *now, time_left_ms);
    timet = last_est.tv_sec;
    ltime = localtime(&timet);
    assert(ltime);

    sec_left = time_left_ms / 1000;

    // If we're less than 1% done we probably don't have enough
    // data for decent timing estimates. Also with perc_done == 0
    // these elements will be nonsensical.
    if (perc_done < 0.01) {
      log_write(LOG_STDOUT, "%s Timing: About %.2f%% done\n", 
                scantypestr, perc_done * 100);
      log_flush(LOG_STDOUT);
    } else {
      log_write(LOG_STDOUT, "%s Timing: About %.2f%% done; ETC: %02d:%02d (%li:%02li:%02li remaining)\n", 
                scantypestr, perc_done * 100, ltime->tm_hour, ltime->tm_min, sec_left / 3600, 
                (sec_left % 3600) / 60, sec_left % 60);
      log_write(LOG_XML, "<taskprogress task=\"%s\" time=\"%lu\" percent=\"%.2f\" remaining=\"%li\" etc=\"%lu\" />\n",
		scantypestr, (unsigned long) now->tv_sec,
		perc_done * 100, sec_left, (unsigned long) last_est.tv_sec);
      log_flush(LOG_STDOUT|LOG_XML);
    }
    return true;
}

/* Indicates that the task is beginning or ending, and that a message should
   be generated if appropriate.  Returns whether a message was printed.
   now may be NULL, if the caller doesn't have the current time handy.
   additional_info may be NULL if no additional information is necessary. */
bool ScanProgressMeter::beginOrEndTask(const struct timeval *now, const char *additional_info, bool beginning) {
  struct timeval tvtmp;
  struct tm *tm;
  time_t tv_sec;

  if (!o.verbose) {
    return false;
  }

  if (!now) {
    gettimeofday(&tvtmp, NULL);
    now = (const struct timeval *) &tvtmp;
  }

  tv_sec = now->tv_sec;
  tm = localtime(&tv_sec);
  if (beginning) {
    log_write(LOG_STDOUT, "Initiating %s at %02d:%02d", scantypestr, tm->tm_hour, tm->tm_min);
    log_write(LOG_XML, "<taskbegin task=\"%s\" time=\"%lu\"", scantypestr, (unsigned long) now->tv_sec);
    if (additional_info) {
      log_write(LOG_STDOUT, " (%s)", additional_info);
      log_write(LOG_XML, " extrainfo=\"%s\"", additional_info);
    }
    log_write(LOG_STDOUT, "\n");
    log_write(LOG_XML, " />\n");
  } else {
    log_write(LOG_STDOUT, "Completed %s at %02d:%02d, %.2fs elapsed", scantypestr, tm->tm_hour, tm->tm_min, TIMEVAL_MSEC_SUBTRACT(*now, begin) / 1000.0);
    log_write(LOG_XML, "<taskend task=\"%s\" time=\"%lu\"", scantypestr, (unsigned long) now->tv_sec);
    if (additional_info) {
      log_write(LOG_STDOUT, " (%s)", additional_info);
      log_write(LOG_XML, " extrainfo=\"%s\"", additional_info);
    }
    log_write(LOG_STDOUT, "\n");
    log_write(LOG_XML, " />\n");
  }
  log_flush(LOG_STDOUT|LOG_XML);
  return true;
}
