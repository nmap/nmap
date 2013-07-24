#!/bin/sh

# Print the contents of all environment variables set by Ncat.

echo "NCAT_REMOTE_ADDR=$NCAT_REMOTE_ADDR"
echo "NCAT_REMOTE_PORT=$NCAT_REMOTE_PORT"

echo "NCAT_LOCAL_ADDR=$NCAT_LOCAL_ADDR"
echo "NCAT_LOCAL_PORT=$NCAT_LOCAL_PORT"

echo "NCAT_PROTO=$NCAT_PROTO"
