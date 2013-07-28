
/***************************************************************************
 * output.h -- Some simple error and regular message output functions.     *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2013 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@insecure.com).  Dozens of software  *
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
 * including the special and conditions of the license text as well.       *
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
 * continued development of Nmap.  Please email sales@insecure.com for     *
 * further information.                                                    *
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
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
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
int nping_fatal(int level, const char *str, ...) {
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
} /* End of nping_print() */


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
