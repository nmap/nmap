#!/bin/sh
#this code is bassed off of the debian su-to-root command
#Joost Witteveen <joostje@debian.org>
#Morten Brix Pedersen
#Bill Allombert <ballombe@debian.org>

PRIV=root
COMMAND="zenmap $@"

euid=$(id -u)
privid=$(id -u $PRIV)
if test "$euid" = "$privid"; then
    $COMMAND
else
    if test -z "$SU_TO_ROOT_X"; then
      if which gksu >/dev/null 2>&1 ; then
        SU_TO_ROOT_X=gksu
        if test "X$KDE_FULL_SESSION" = "Xtrue" ; then
          if which kdesu >/dev/null 2>&1 ; then
            SU_TO_ROOT_X=kdesu
          elif test -x /usr/lib/kde4/libexec/kdesu ; then
            SU_TO_ROOT_X=kde4su
          fi;
        fi;
      elif which kdesu >/dev/null 2>&1 ; then 
        SU_TO_ROOT_X=kdesu
      elif test -x /usr/lib/kde4/libexec/kdesu ; then
        SU_TO_ROOT_X=kde4su
      elif which ktsuss >/dev/null 2>&1 ; then
        SU_TO_ROOT_X=ktsuss
      elif which xterm>/dev/null 2>&1 ;then
        if which sudo>/dev/null 2>&1 ;then
          SU_TO_ROOT_X=sdterm
        else
          SU_TO_ROOT_X=sterm
        fi;
      else
        SU_TO_ROOT_X=su-to-root
      fi
    fi
    case $SU_TO_ROOT_X in
      gksu) gksu -u "$PRIV" "$COMMAND";;
      kdesu) kdesu -u "$PRIV" -c "$COMMAND";;
      kde4su) /usr/lib/kde4/libexec/kdesu -u "$PRIV" -c "$COMMAND";;
      ktsuss) ktsuss -u "$PRIV" "$COMMAND";;
  # As a last resort, open a new xterm use sudo/su
      sdterm) xterm -e "sudo -u $PRIV $COMMAND";;
      sterm) xterm -e "su -l $PRIV -c $COMMAND";;
    esac;
fi

