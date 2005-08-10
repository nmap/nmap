#ifndef WINFIX_H
#define WINFIX_H

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
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
EXTERNC void win_init();
EXTERNC void win_barf(const char *msg);
#endif


