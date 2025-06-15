#!/bin/sh
# Test script for Ncat --watch-allow-deny / auto-reload feature
# Part of the Nmap Project - see LICENSE for terms

set -e

PORT=41001
TMP_ALLOW=$(mktemp ncat_allow_XXXX)
trap 'rm -f "$TMP_ALLOW"; kill $SERVER_PID 2>/dev/null || true' EXIT

# Initial allow rule permits localhost
printf "127.0.0.1\n" > "$TMP_ALLOW"

# Start Ncat server in background
../ncat -l $PORT --keep-open --recv-only --allowfile "$TMP_ALLOW" --watch-allow-deny 2>/dev/null &
SERVER_PID=$!

# Give it a moment to start
sleep 1

# First connection should succeed
if ! ../ncat 127.0.0.1 $PORT -z 2>/dev/null; then
  echo "Initial connection unexpectedly failed"
  exit 1
fi

# Overwrite via temp move to avoid partial read races
TMP2=$(mktemp ncat_allow2_XXXX)
printf "192.0.2.1\n" > "$TMP2"
mv "$TMP2" "$TMP_ALLOW"
# Wait (max 5 s) until connection is denied
tries=10
while [ $tries -gt 0 ]; do
  if printf "ping\n" | ../ncat 127.0.0.1 $PORT -w1 2>/dev/null; then
    # Still allowed -> retry after short delay
    sleep 0.5
    tries=$((tries-1))
  else
    echo "PASS watch-allow-deny"
    exit 0
  fi
done

echo "Connection still allowed after watcher delay"
exit 1