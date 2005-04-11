dnl Type of 6th argument to recvfrom(). Usually int or socklen_t.
AC_DEFUN([RECVFROM_ARG6_TYPE],
[
   AC_LANG_PUSH(C++)
   AC_MSG_CHECKING([for type of 6th argument to recvfrom()])
   recvfrom6_t=
   for t in socklen_t int; do
     AC_TRY_COMPILE([
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>],[
$t arg;
recvfrom (0, NULL, 0, 0, NULL, &arg);],[
      recvfrom6_t="$t"
      break])
   done

   if test "x$recvfrom6_t" = x; then
     AC_MSG_WARN([Cannot find type for 6th argument to recvfrom(). Using socklen_t ptr])
     recvfrom6_t="socklen_t"
   fi

   AC_MSG_RESULT($recvfrom6_t)
   AC_DEFINE_UNQUOTED(recvfrom6_t, $recvfrom6_t,
     [Type of 6th argument to recvfrom()])
   AC_LANG_POP(C++)
])
