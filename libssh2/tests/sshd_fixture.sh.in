#!/bin/sh

# Written by Simon Josefsson.

# Start sshd, invoke parameters, saving exit code, kill sshd, and
# return exit code.

srcdir="@SSHD_TEST_CONFIG_DIR@"
SSHD="@SSHD_EXECUTABLE@"

cmd="\"$1\""

PRIVKEY=$srcdir/etc/user
export PRIVKEY
PUBKEY=$srcdir/etc/user.pub
export PUBKEY

if test -n "$DEBUG"; then
    libssh2_sshd_params="-d -d"
fi

chmod go-rwx "$srcdir"/etc/host*
"$SSHD" -f /dev/null -h "$srcdir/etc/host" \
    -o 'Port 4711' \
    -o 'Protocol 2' \
    -o "AuthorizedKeysFile \"$srcdir/etc/user.pub\"" \
    -o 'UsePrivilegeSeparation no' \
    -o 'StrictModes no' \
    -D \
    $libssh2_sshd_params &
sshdpid=$!

trap "kill ${sshdpid}; echo signal killing sshd; exit 1;" EXIT

: "started sshd (${sshdpid})"

sleep 3

if ! kill -0 ${sshdpid}
then
    echo "SSHD exited before test started"
    exit 1
fi

: Invoking $cmd...
eval "$cmd"
ec=$?
: Self-test exit code $ec

: "killing sshd (${sshdpid})"
kill "${sshdpid}" > /dev/null 2>&1
trap "" EXIT
exit $ec
