
/***************************************************************************
 * output.h -- Some simple error and regular message output functions.     *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
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
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                *
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is meant to clarify our *
 * interpretation of derived works with some common examples.  Our         *
 * interpretation applies only to Nmap--we don't speak for other people's  *
 * GPL works.                                                              *
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
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
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
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/

/* This file contains the functions that are used to print stuff to stout or
 * stderr in Nping. All of them take a "level" and then a variable list of
 * argument. The "level" parameter states which is the minimum level of
 * verbosity that should NpingOps::vb contain to print the message to stdout.
 * For a more detailed explanation, check documentation of verbosity and
 * debugging levels in nping.h  */

#include "NpingOps.h"
#include "output.h"

extern NpingOps o;

#ifdef WIN32
#include <windows.h>
#endif /* WIN32 */


/** Print fatal error messages to stderr and then exits.
 * @warning This function does not return because it calls exit() */
int outFatal(int level, const char *str, ...) {
  va_list  list;
  char errstr[MAX_ERR_STR_LEN];
  memset(errstr,0, MAX_ERR_STR_LEN);

  va_start(list, str);
  fflush(stdout);
  fflush(stderr);

  int current_vb_level= o.getVerbosity();
  int current_dbg_level= o.getDebugging();

  /* If supplied level is more than current level, do nothing */
  if( level>=QT_4 && level<=VB_4 && level>current_vb_level )
    return OP_SUCCESS;
  if( level>=DBG_0 && level<=DBG_9 && level>current_dbg_level )
    return OP_SUCCESS;
  

  if ( (level>=QT_3 && level<=VB_4) || (level>=DBG_1 && level<=DBG_9) ){
    vfprintf(stderr, str, list);
    fprintf(stderr,"\n"); /* Print to stderr */
  }

  va_end(list);
  exit(EXIT_FAILURE);
  return OP_SUCCESS;
} /* End of outFatal() */


/** Prints recoverable error message to stderr and returns. This function
 *  inserts one \n newline automatically in every call. To avoid that
 *  behaviour it is possible to OR the supplied level with the constant
 *  NO_NEWLINE like this:
 *
 *  outError(QT_2|NO_NEWLINE, "I don't want newlines in this string");
 *                                                                           */
int outError(int level, const char *str, ...) {
  va_list  list;
  char errstr[MAX_ERR_STR_LEN];
  bool skipnewline=false;
  memset(errstr,0, MAX_ERR_STR_LEN);

  va_start(list, str);
  fflush(stdout);
  fflush(stderr);

  int current_vb_level= o.getVerbosity();
  int current_dbg_level= o.getDebugging();
  
  /* Determine if caller requested that we don't print a newline character */
  if ( level & NO_NEWLINE ){
    level ^= NO_NEWLINE; /* Unset the flag restoring the original level */
    skipnewline=true;
  }

  /* If supplied level is more than current level, do nothing */
  if( level>=QT_4 && level<=VB_4 && level>current_vb_level )
    return OP_SUCCESS;
  if( level>=DBG_0 && level<=DBG_9 && level>current_dbg_level )
    return OP_SUCCESS;
  
  /* Otherwise, print the info to stderr*/
  if ( (level>=QT_3 && level<=VB_4) || (level>=DBG_1 && level<=DBG_9) ){
    vfprintf(stderr, str, list); /* Print to stderr */
    if( !skipnewline )
        fprintf(stderr,"\n"); 
  }
  va_end(list);
  return OP_SUCCESS;
} /* End of outError() */


/** Print regular messages to stdout. This function inserts one \n newline
 *  automatically in every call. To avoid that behaviour it is possible to
 *  OR the supplied level with constant NO_NEWLINE like this:
 *
 *  outPrint(VB_2|NO_NEWLINE, "I don't want newlines in this string");
 *                                                                           */
int outPrint(int level, const char *str, ...){
  va_list  list;
  char errstr[MAX_ERR_STR_LEN];
  bool skipnewline=false;
  memset(errstr,0, MAX_ERR_STR_LEN);

  va_start(list, str);
  fflush(stdout);

  int current_vb_level= o.getVerbosity();
  int current_dbg_level= o.getDebugging();
  
  /* Determine if caller requested that we don't print a newline character */
  if ( level & NO_NEWLINE ){
    level ^= NO_NEWLINE; /* Unset the flag restoring the original level */
    skipnewline=true;
  }

  /* If supplied level is more than current level, do nothing */
  if( level>=QT_4 && level<=VB_4 && level>current_vb_level )
    return OP_SUCCESS;
  if( level>=DBG_0 && level<=DBG_9 && level>current_dbg_level )
    return OP_SUCCESS;
  
  /* Otherwise, print the info to stderr*/
  if ( (level>=QT_3 && level<=VB_4) || (level>=DBG_1 && level<=DBG_9) ){
    vfprintf(stdout, str, list); /* Print to stderr */
    if( !skipnewline )
        fprintf(stdout,"\n");
  }
  va_end(list);
  return OP_SUCCESS;
} /* End of outPrint() */


/*****************************************************************************/
/* The following functions are provided only for compatibility with some     */
/* code from Nmap. They should NOT be used in any new piece of code unless   */
/* the code you are writting needs to be shared with nmap.                   */
/*****************************************************************************/
/** Print fatal error messages to stderr and then exits.
 * @warning This function does not return because it calls exit() */
int fatal(const char *str, ...) {
  va_list  list;
  char errstr[MAX_ERR_STR_LEN];
  memset(errstr,0, MAX_ERR_STR_LEN);
  va_start(list, str);
  fflush(stdout);
  /* Print error msg to strerr */
  vfprintf(stderr, str, list);
  fprintf(stderr,"\n");
  va_end(list);
  exit(EXIT_FAILURE);
  return OP_SUCCESS;
} /* End of fatal() */


/** Print error messages to stderr and then return. */
int error(const char *str, ...) {
  va_list  list;
  char errstr[MAX_ERR_STR_LEN];
  memset(errstr,0, MAX_ERR_STR_LEN);
  va_start(list, str);
  fflush(stdout);
  /* Print error msg to strerr */
  vfprintf(stderr, str, list);
  fprintf(stderr,"\n");
  va_end(list);
  return OP_SUCCESS;
} /* End of error() */


/** Needed by struct interface_info *getinterfaces(int *howmany) in common.h
 * (taken originally from nmap tcpip.cc */
int pfatal(const char *str, ...) {
  va_list  list;
  char errstr[MAX_ERR_STR_LEN];
  memset(errstr,0, MAX_ERR_STR_LEN);
  va_start(list, str);
  fflush(stdout);
  /* Print error msg to strerr */
  vfprintf(stderr, str, list);
  fprintf(stderr,"\n");
  va_end(list);
  exit(EXIT_FAILURE);
  return OP_SUCCESS;
} /* End of fatal() */
