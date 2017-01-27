#!/bin/sh

LOGFILE="log_ips.log"

MSG="[`date`] Incoming connection from $NCAT_REMOTE_ADDR:$NCAT_REMOTE_PORT"

echo $MSG >&2
echo $MSG >> $LOGFILE

echo "Yeah, hi."
