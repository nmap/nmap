#!/bin/sh

# Automated tests for the addrset functions in ncat_hostmatch.c. This
# program runs various addresses against different host specifications
# and checks that the output is what is expected.

ADDRSET=./addrset
TESTS=0
TEST_PASS=0
TEST_FAIL=0

# Takes as arguments a whitespace-separated list of host specifications
# and a space-separated list of expected matching addresses. Tests hosts
# are passed in stdin.
test_addrset() {
	specs=$1
	expected=$2
	result=$($ADDRSET $specs)
	ret=$?
	# Change newlines to spaces.
	result=$(echo $result)
	TESTS=$(expr $TESTS + 1);
	if [ "$ret" != "0" ]; then
		echo "FAIL $specs: $ADDRSET returned $ret."
		TEST_FAIL=$(expr $TEST_FAIL + 1)
	elif [ "$result" != "$expected" ]; then
		echo "FAIL $specs: \"$result\" !="
		echo "     \"$expected\"."
		TEST_FAIL=$(expr $TEST_FAIL + 1)
	else
		echo "PASS $specs"
		TEST_PASS=$(expr $TEST_PASS + 1)
	fi
}

# Takes as an argument a host specification with invalid syntax. The
# test passes if addrset returns with a non-zero exit code.
expect_fail() {
	specs=$1
	$ADDRSET $specs < /dev/null 2> /dev/null
	ret=$?
	TESTS=$(expr $TESTS + 1)
	if [ "$ret" = "0" ]; then
		echo "FAIL $ADDRSET $specs was expected to fail, but didn't."
		TEST_FAIL=$(expr $TEST_FAIL + 1)
	else
		echo "PASS $specs"
		TEST_PASS=$(expr $TEST_PASS + 1)
	fi
}

# seq replacement for systems without seq.
seq() {
	low=$1
	high=$2
	while [ $low -le $high ]; do
		echo $low
		low=$(expr $low + 1)
	done
}

# No specifications.
test_addrset "" "" <<EOF
1.1.1.1
2.2.2.2
EOF

# IPv4 address equality.
(for a in `seq 0 255`; do echo 192.168.0.$a; done) \
	| test_addrset "192.168.0.0" "192.168.0.0"

# IPv6 address equality.
(for a in `seq 0 255`; do printf "FE80:0000:0000:0000:0202:E3%02X:FE14:1102\n" $a; done) \
	| test_addrset "fe80::202:e3ff:fe14:1102" "FE80:0000:0000:0000:0202:E3FF:FE14:1102"

# IPv4 and IPv6 at once.
test_addrset "1.2.3.4 1:2:3::4" "1.2.3.4 1:2:3::4 1:2:3:0::4" <<EOF
0.0.0.0
1.2.3.4
::
1:2:3::4
1:2:3:0::4
f:e:d:c:b::a
EOF

# Simple IPv4 range.
(for a in `seq 0 255`; do echo 192.168.0.$a; done) \
	| test_addrset "192.168.0.1-5" "192.168.0.1 192.168.0.2 192.168.0.3 192.168.0.4 192.168.0.5"

# Addresses outside IPv4 range.
(for a in `seq 0 255`; do echo 192.168.0.$a; done) \
	| test_addrset "192.168.1.1-5" ""

# One-element range.
(for a in `seq 0 255`; do echo 192.168.0.$a; done) \
	| test_addrset "192.168-168.0.1" "192.168.0.1"

# Double IPv4 ranges.
(for a in `seq 0 255`; do echo 192.168.$a.$a; done) \
	| test_addrset "192.168.3-8.1-5" "192.168.3.3 192.168.4.4 192.168.5.5"

# Half-open range.
(for a in `seq 0 255`; do echo 192.168.$a.0; done) \
	| test_addrset "192.168.-3.0" "192.168.0.0 192.168.1.0 192.168.2.0 192.168.3.0"

# Half-open range.
(for a in `seq 0 255`; do echo 192.168.$a.0; done) \
	| test_addrset "192.168.252-.0" "192.168.252.0 192.168.253.0 192.168.254.0 192.168.255.0"

# Full-open range.
test_addrset "192.168.-.0" "192.168.0.0 192.168.10.0 192.168.100.0 192.168.255.0" <<EOF
192.168.0.0
192.168.10.0
192.168.100.0
192.168.255.0
192.168.0.1
1.2.3.4
EOF

# Comma ranges.
(for a in `seq 0 255`; do echo 192.168.0.$a; done) \
	| test_addrset "192.168.0.2,3,5,7,11" "192.168.0.2 192.168.0.3 192.168.0.5 192.168.0.7 192.168.0.11"

# Comma ranges combined with dash ranges.
test_addrset "192-200,202.0.0.1,3-5" "202.0.0.1 202.0.0.5 192.0.0.3" <<EOF
201.0.0.1
202.0.0.1
202.0.0.5
202.0.0.6
192.0.0.3
EOF

# Wildcard octet.
test_addrset "192.168.0.*" "192.168.0.3 192.168.0.200 192.168.0.255" <<EOF
1.2.3.4
192.168.0.3
192.168.0.200
192.161.0.0
192.168.0.255
EOF

# Two wildcards.
test_addrset "192.*.0.*" "192.168.0.3 192.168.0.200 192.161.0.0 192.168.0.255" <<EOF
1.2.3.4
192.168.0.3
192.168.0.200
192.161.0.0
192.168.0.255
EOF

# Many range types.
test_addrset "*.1-10,12.*.4-5,6,7" "1.2.3.4 4.5.6.7 70.10.4.4" <<EOF
1.2.3.4
4.5.6.7
70.11.4.4
70.10.4.4
255.255.255.255
EOF

# IPv4 CIDR netmask.
test_addrset "192.168.0.0/24" "192.168.0.5 192.168.0.90" <<EOF
192.168.0.5
192.168.0.90
192.168.1.5
1.2.3.4
EOF

# /32 netmask.
test_addrset "1.2.3.4/32" "1.2.3.4" <<EOF
192.168.0.10
192.168.0.90
192.168.1.5
1.2.3.4
EOF

# /0 netmask.
test_addrset "5.5.5.5/0" "0.0.0.0 123.123.123.123 255.255.255.255" <<EOF
0.0.0.0
123.123.123.123
255.255.255.255
EOF

# IPv4 range combined with CIDR netmask.
test_addrset "1-5.1-5.1-5.1-5/28" "1.2.3.4 1.2.3.5 1.2.3.7 1.2.3.0" <<EOF
1.2.3.4
1.2.3.5
6.1.2.3
1.2.3.7
1.2.3.0
EOF

# Exhaustive listing of a range with netmask.
(for a in `seq 0 255`; do echo 192.168.0.$a; done) \
	| test_addrset "192.168.0.5,30,191/30" \
"192.168.0.4 192.168.0.5 192.168.0.6 192.168.0.7 192.168.0.28 192.168.0.29 192.168.0.30 192.168.0.31 192.168.0.188 192.168.0.189 192.168.0.190 192.168.0.191"

# Exhaustive listing of a range with netmask, different octet.
(for a in `seq 0 255`; do echo 192.168.$a.0; done) \
	| test_addrset "192.168.5,30,191.0/22" \
"192.168.4.0 192.168.5.0 192.168.6.0 192.168.7.0 192.168.28.0 192.168.29.0 192.168.30.0 192.168.31.0 192.168.188.0 192.168.189.0 192.168.190.0 192.168.191.0"

# IPv6 CIDR netmask.
test_addrset "1:2::0003/120" "1:2::3 1:2::0 1:2::ff" <<EOF
1:2::3
1:2::0
1:2::ff
1:2::1ff
1:3::3
EOF

# IPv6 CIDR netmask.
test_addrset "1:2::3:4:5/95" "1:2::3:4:5 1:2::2:0:0 1:2::3:ffff:ffff" <<EOF
1:2::3:4:5
1:2::1:ffff:ffff
1:2::2:0:0
1:2::3:ffff:ffff
1:2::4:0:0
1:3::3
EOF

# IPv6 CIDR netmask.
test_addrset "11::2/15" "11::2:3:4:5 10::1 11:ffff:ffff:ffff:ffff:ffff:ffff:ffff" <<EOF
11::2:3:4:5
9:ffff:ffff:ffff:ffff:ffff:ffff:ffff
10::1
11:ffff:ffff:ffff:ffff:ffff:ffff:ffff
12::0
EOF

# /128 netmask.
test_addrset "1:2::0003/128" "1:2::3" <<EOF
1:2::3
1:2::0
1:2::ff
1:2::1ff
1:3::3
EOF

# /0 netmask.
test_addrset "1:2::0003/0" "1:2::3 1:2::0 1:2::ff 1:2::1ff 1:3::3 ff::00" <<EOF
1:2::3
1:2::0
1:2::ff
1:2::1ff
1:3::3
ff::00
EOF

# Name lookup.
test_addrset "scanme.nmap.org" "scanme.nmap.org" <<EOF
1:2::3:4
1.2.3.4
scanme.nmap.org
EOF

# Name lookup combined with CIDR netmask.
test_addrset "scanme.nmap.org/30" "scanme.nmap.org" <<EOF
1:2::3:4
1.2.3.4
scanme.nmap.org
EOF

# Name lookup combined with /0 CIDR netmask.
test_addrset "scanme.nmap.org/0" "1.2.3.4 scanme.nmap.org" <<EOF
1.2.3.4
scanme.nmap.org
EOF

expect_fail "."
expect_fail "-"
expect_fail ","
expect_fail "1.2.3.4,"
expect_fail ",1.2.3.4"
expect_fail "1.2.3.4.5"
expect_fail "1:2:3:4:5:6:7:8:9"
expect_fail "11::22::33"

expect_fail "256.256.256.256"
expect_fail "FFFFF::FFFFF"

# Backwards range.
expect_fail "10-5.2.3.4"

expect_fail "*10.10.10.10"
expect_fail "5-10-15.10.10.10"
expect_fail "-10-15.10.10.10"
expect_fail "10-15-.10.10.10"
expect_fail ",.6.7.8"
expect_fail "5,.5.5.5"
expect_fail ",5.5.5.5"
expect_fail ",5.5.5.5"
expect_fail "+1.2.3.4"
expect_fail "+1.+2.+3.+4"

expect_fail "1.2.3.4/"
expect_fail "1.2.3.4/33"
expect_fail "1.2.3.4/+24"
expect_fail "1.2.3.4/24abc"
expect_fail "1.2.3.4//24"
expect_fail "1.2.3.4/-0"
expect_fail "FF::FF/129"

# Specifications whose behavior is unspecified but not important; that
# is, if the behavior of these changed it wouldn't matter much to users.

# test_addrset "01.02.03.04" "1.2.3.4" <<EOF
# 1.2.3.4
# 5.6.7.8
# EOF
#
# test_addrset "1" "0.0.0.1" <<EOF
# 1.0.0.0
# 0.0.0.1
# 1.2.3.4
# EOF
#
# test_addrset "1.2" "1.0.0.2" <<EOF
# 1.0.0.2
# 1.2.0.0
# 1.2.3.4
# EOF
#
# test_addrset "1.2.3" "1.2.0.3" <<EOF
# 1.0.2.3
# 1.2.0.3
# 1.2.3.4
# EOF

if [ "$TEST_FAIL" -gt 0 ]; then
	echo "$TEST_PASS / $TESTS passed, $TEST_FAIL failed"
	exit 1
fi
echo "$TEST_PASS / $TESTS passed"
