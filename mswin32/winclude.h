/***************************************************************************
 * winclude.h -- some windows include files and                            *
 * windows-compatabilty-related functions that are specific to Nmap.  Most *
 * of this has been moved into nbase so it can be shared.                  *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1995-2003 Insecure.Com LLC. This       *
 * program is free software; you can redistribute it and/or modify it      *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2.  This guarantees your right to     *
 * use, modify, and redistribute this software under certain conditions.   *
 * If this license is unacceptable to you, we may be willing to sell       *
 * alternative licenses (contact sales@insecure.com).  Most security       *
 * scanner vendors do, in fact, license Nmap technology such as our remote *
 * OS fingerprinting database and code.                                    *
 *                                                                         *
 * Note that we consider aggregation/inclusion/integration of Nmap into an *
 * executable installer to constitute a derived work and thus is subject   *
 * to the GPL restrictions.  We also consider certain programs that        *
 * tightly integrate with Nmap to constitute derivative works, even if     *
 * they only interface with Nmap by executing the Nmap binary and          *
 * interpreting its output rather than by direct linking.  If you are      *
 * interested in including Nmap with your proprietary software or          *
 * appliance, please contact us first to ensure that the licensing is      *
 * proper.                                                                 *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the (GPL) terms above, then that      *
 * alternative license agreement takes precedence over this comment.       *
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
 * insecure.org development mailing lists, it is assumed that you are      *
 * offering Fyodor and Insecure.Com LLC the unlimited, non-exclusive right *
 * to reuse, modify, and relicense the code.  Nmap will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).  We also occasionally relicense the    *
 * code to third parties as discussed above.  If you wish to specify       *
 * special license conditions of your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * You are welcome to use this code in your own GPL projects.  If you  use *
 * any significant amount of Nmap code, we would appreciate you crediting  *
 * the Nmap project on your web site and/or documentation.                 *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License for more details at                              *
 * http://www.gnu.org/copyleft/gpl.html .                                  *
 *                                                                         *
 ***************************************************************************/

/* $Id: */

#ifndef WINCLUDE_H
#define WINCLUDE_H

#include "nmap_winconfig.h"

#include <stdio.h>
#include <stdlib.h>

#include "nbase.h"

#include <gnuc.h>

#include <pcap.h>
#include <packet32.h>
#include <netinet/tcp.h>  
#include <netinet/udp.h>  

/* non-functioning stub function */
int fork();

#endif /* WINCLUDE_H */
