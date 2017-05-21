#ifndef WINFIX_H
#define WINFIX_H

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#ifndef EXTERNC
# ifdef __cplusplus
#  define EXTERNC extern "C"
# else
#  define EXTERNC extern
# endif
#endif

//	windows-specific options

#include <pcap.h>

/*   (exported) functions   */
/* The code that has no preconditions to being called, so it can be
   executed before even Nmap options parsing (so o.debugging and the
   like don't need to be used.  Its main function is to do
   WSAStartup() as some of the option parsing code does DNS
   resolution */
EXTERNC void win_pre_init();

/* Requires that win_pre_init() has already been called, also that
   options processing has been done so that o.debugging is
   available */
EXTERNC void win_init();
EXTERNC void win_barf(const char *msg);
#endif




