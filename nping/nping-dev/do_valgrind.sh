#!/bin/bash
reset && sudo valgrind --leak-check=full --show-reachable=yes --track-fds=yes --read-var-info=yes  --sim-hints=lax-ioctls --track-origins=yes --malloc-fill=aa --suppressions=valgrind_supress.txt -v -v $1 $2 $3 $4 $5 $6 $7 $8 $9
