
/***************************************************************************
 * output.h -- Some simple error and regular message output functions.     *
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
int nping_fatal(int level, const char *str, ...) {
  va_list  list;
  char errstr[MAX_ERR_STR_LEN];
  memset(errstr,0, MAX_ERR_STR_LEN);

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
    va_start(list, str);
    vfprintf(stderr, str, list);
    va_end(list);
    fprintf(stderr,"\n"); /* Print to stderr */
  }

  exit(EXIT_FAILURE);
  return OP_SUCCESS;
} /* End of nping_fatal() */


/** Prints recoverable error message to stderr and returns. This function
 *  inserts one \n newline automatically in every call. To avoid that
 *  behaviour it is possible to OR the supplied level with the constant
 *  NO_NEWLINE like this:
 *
 *  nping_warning(QT_2|NO_NEWLINE, "I don't want newlines in this string");
 *                                                                           */
int nping_warning(int level, const char *str, ...) {
  va_list  list;
  char errstr[MAX_ERR_STR_LEN];
  bool skipnewline=false;
  memset(errstr,0, MAX_ERR_STR_LEN);

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
    va_start(list, str);
    vfprintf(stderr, str, list); /* Print to stderr */
    va_end(list);
    if( !skipnewline )
        fprintf(stderr,"\n"); 
  }
  return OP_SUCCESS;
} /* End of nping_warning() */


/** Print regular messages to stdout. This function inserts one \n newline
 *  automatically in every call. To avoid that behaviour it is possible to
 *  OR the supplied level with constant NO_NEWLINE like this:
 *
 *  nping_print(VB_2|NO_NEWLINE, "I don't want newlines in this string");
 *                                                                           */
int nping_print(int level, const char *str, ...){
  va_list  list;
  char errstr[MAX_ERR_STR_LEN];
  bool skipnewline=false;
  memset(errstr,0, MAX_ERR_STR_LEN);

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
    va_start(list, str);
    vfprintf(stdout, str, list); /* Print to stderr */
    va_end(list);
    if( !skipnewline )
        fprintf(stdout,"\n");
  }
  return OP_SUCCESS;
} /* End of nping_print() */


/*****************************************************************************/
/* The following functions are provided only for compatibility with some     */
/* code from Nmap. They should NOT be used in any new piece of code unless   */
/* the code you are writing needs to be shared with nmap.                    */
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
