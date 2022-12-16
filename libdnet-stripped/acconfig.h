@BOTTOM@

#include <sys/types.h>

#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
# include <windows.h>
#endif

#ifdef __svr4__
# define BSD_COMP	1
#endif

#if defined(__osf__) && !defined(_SOCKADDR_LEN)
# define _SOCKADDR_LEN	1
#endif

#ifndef HAVE_INET_PTON
int	inet_pton(int, const char *, void *);
#endif

#ifndef HAVE_STRLCPY
int	strlcpy(char *, const char *, int);
#endif

#ifndef HAVE_STRSEP
char	*strsep(char **, const char *);
#endif

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif
