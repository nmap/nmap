#/*****************************************************************************
# *                                                                           *
# *                                             o                             *
# *                                              o                            *
# *                                               o                           *
# *                                        o       o                          *
# *                                         o       o                         *
# *                                          o       o                        *
# *                                    o      o       o                       *
# *                                     o      o      o                       *
# *                         888b    888  o     o      o                       *
# *                         8888b   888  o     o      o                       *
# *                         88888b  888  o     o      o                       *
# *                         888Y88b 888               o                       *
# *                         888 Y88b888               o                       *
# *                         888  Y88888                                       *
# *                         888   Y8888                                       *
# *                         888    Y888                                       *
# *                                                                           *
# *                  --[NPING TEST SPECIFICATION]--                           *
# *                                                                           *
# *****************************************************************************/


# This document aims to list every Nping option and option syntax, with
# the purpose of faciliatating testing whether they all work as expected.

######################################
#  RUN-TIME PARAMETER CONFIGURATION  # 
######################################

# Target host specification. Can be just one host or varios hosts
# separated by whitespace
TARGETS="scanme.nmap.org"

# Global options to be passed to EVERY nping invokation. This is useful
# to specify things like verbosity level, etc.
GLOBALOPTS="-vvv -d1"

# Port numbers required by some executions. 
OPEN_PORT="80"
CLOSED_PORT="31337"
FILTERED_PORT="82"

# This var should be set to the name of a network interface that
# exists on the testing system.
EXISTING_NET_IFACE="eth0"

# Internal test state variables
CURRENT_TEST=""
FAILED_TESTS=""
PASSED_TESTS=""
TOTAL_TESTS_RUN=0
TOTAL_TESTS_PASSED=0
TOTAL_TESTS_FAILED=0
START_TIME=`date +"%s"`
END_TIME=0
ELAPSED_TIME=0


# Ask the user whether the test was passed or failed
request_userinput_test_status() {
    echo -n "[+] Was the test successful? [Y/N] "
    read TESTRESPONSE
    # Increment total counter 
    TOTAL_TESTS_RUN=`expr $TOTAL_TESTS_RUN + 1`

    if [ -z $TESTRESPONSE ]; then
        TESTRESPONSE="y"
    fi

    if [ $TESTRESPONSE = "n" -o $TESTRESPONSE = "N" ]; then
        FAILED_TESTS="$FAILED_TESTS$TEST_ID,"
        TOTAL_TESTS_FAILED=`expr $TOTAL_TESTS_FAILED + 1`
    else
        PASSED_TESTS="$PASSED_TESTS$TEST_ID,"
        TOTAL_TESTS_PASSED=`expr $TOTAL_TESTS_PASSED + 1`
    fi
}

# This function runs a single test and asks for success/failure confirmation.
# Usage: t <test_id> <test_desc> nping [args]...
t() {
    TEST_ID="$1"
    TEST_DESC="$2"
    shift
    shift
    echo "=======================TEST START======================="
    echo "[+] $TEST_ID: $TEST_DESC"
    echo "$@"
    # The next line runs the command.
    "$@"
    request_userinput_test_status
    echo "========================TEST END========================"
    echo ""
    echo ""
}


# Tests still to write.

# Traceroute. (What other options are possible here?)
# Miscellaneous.
#  |_ Include a few regular executions.


####################
#   TEST BATTERY   # 
####################


#### PRIVILEGE DETERMINATION AND DEFAULT BEHAVIOUR ####

t TCPPRIVS_1 "Test default ping as non root. Expected tcp-connect mode." \
nping $TARGETS $GLOBALOPTS

t TCPPRIVS_2 "Test default ping as root. Expected ICMP Echo ping." \
sudo nping $TARGETS $GLOBALOPTS

t TCPPRIVS_3 "Test default ping as non root (IPv6). Expected tcp-connect mode." \
nping -6 $TARGETS $GLOBALOPTS

t TCPPRIVS_4 "Test default ping as root (IPv6). Expected ICMP Echo ping." \
sudo nping -6 $TARGETS $GLOBALOPTS



#### TARGET SPECIFICATION ####

t TARGETSPEC_1 "Test single target spec (hostname)." \
sudo nping $GLOBALOPTS -c1 google.com

t TARGETSPEC_2 "Test single target spec (IP address)." \
sudo nping $GLOBALOPTS 192.168.1.1

t TARGETSPEC_3 "Test multiple target spec (two hostnames)." \
sudo nping $GLOBALOPTS -c1 --rate 10 google.com nmap.org

t TARGETSPEC_4 "Test multiple target spec (two IP addresses)." \
sudo nping $GLOBALOPTS -c1 --rate 10 192.168.1.1 192.168.1.99

t TARGETSPEC_5 "Test multiple target spec (IP range #1)." \
sudo nping $GLOBALOPTS -c1 --rate 10 192.168.1.1-10 

t TARGETSPEC_6 "Test multiple target spec (IP range #2)." \
sudo nping $GLOBALOPTS -c1 --rate 10 190-191.168.1-2.99-100 

t TARGETSPEC_7 "Test multiple target spec (IP range + hostname)." \
sudo nping $GLOBALOPTS -c1 --rate 10 192.168.1.1-10 google.com

t TARGETSPEC_8 "Test multiple target spec (hostname with CIDR notation)." \
sudo nping $GLOBALOPTS -c1 --rate 100 google.com/24

t TARGETSPEC_9 "Test multiple target spec (IP with CIDR notation)." \
sudo nping $GLOBALOPTS -c1 --rate 100 192.168.1.1/24

t TARGETSPEC_10 "Test multiple target spec (mixed specs)." \
sudo nping $GLOBALOPTS -c1 --rate 10 192.168.1.1 192.168.1.99-100 google.com/29 scanme.nmap.org

t TARGETSPEC_11 "Test unresolvable target spec. Expected: error message." \
sudo nping $GLOBALOPTS -c1 bogushostname

#Bug here. If our first target is not valid, then route_dst() fails. If we specify google.com first, then it works.
t TARGETSPEC_12a "Test unresolvable target spec (some good names and some bad ones). Expected: error message for some of the targets." \
sudo nping $GLOBALOPTS -c1 bogushostname google.com bogushostname2 insecure.org

t TARGETSPEC_12b "Test unresolvable target spec (some good names and some bad ones). Expected: error message for some of the targets." \
sudo nping $GLOBALOPTS -c1 google.com bogushostname bogushostname2 insecure.org

t TARGETSPEC_13 "Don't specify any target host. Expected: error message." \
sudo nping $GLOBALOPTS -c1

# These will all fail becasue -iL is not implemmented.
echo "google.com" > myhostlist.tmp
t TARGETSPEC_14 "Test single target spec with -iL (hostname)." \
sudo nping $GLOBALOPTS -c1 -iL myhostlist.tmp

echo "192.168.1.1" > myhostlist.tmp
t TARGETSPEC_15 "Test single target spec with -iL (IP address)." \
sudo nping $GLOBALOPTS -c1 -iL myhostlist.tmp

echo "google.com nmap.org" > myhostlist.tmp
t TARGETSPEC_16 "Test multiple target spec with -iL (two hostnames)." \
sudo nping $GLOBALOPTS -c1 -iL myhostlist.tmp

echo "192.168.1.1 192.168.1.99" > myhostlist.tmp
t TARGETSPEC_17 "Test multiple target spec with -iL (two IP addresses)." \
sudo nping $GLOBALOPTS -c1 -iL myhostlist.tmp

echo "192.168.1.1-10 " > myhostlist.tmp
t TARGETSPEC_18 "Test multiple target spec with -iL (IP range #1)." \
sudo nping $GLOBALOPTS -c1 --rate 10 -iL myhostlist.tmp

echo "192.168.1.1 192.168.1.99-100 google.com/29 scanme.nmap.org" > myhostlist.tmp
t TARGETSPEC_19 "Test multiple target spec with -iL (mixed specs)." \
sudo nping $GLOBALOPTS -c1 --rate 10 -iL myhostlist.tmp

rm -f myhostlist.tmp




#### TCP CONNECT MODE ####

t TCPCONNECT_1 "Explicit TCP-CONNECT mode specification. Expected default destination port: 80" \
sudo nping --tcp-connect $TARGETS $GLOBALOPTS

t TCPCONNECT_2 "TCP-CONNECT to an open port. Expected: Handshake complete messages." \
sudo nping --tcp-connect -p$OPEN_PORT $TARGETS $GLOBALOPTS

t TCPCONNECT_3 "TCP-CONNECT to a closed port. Expected: <<Possible TCP RST received from>> messages." \
sudo nping --tcp-connect -p$CLOSED_PORT $TARGETS $GLOBALOPTS

t TCPCONNECT_4 "TCP-CONNECT to a filtered port. Expected: Only <<Starting TCP Handshake>> messages." \
sudo nping --tcp-connect -p$FILTERED_PORT $TARGETS $GLOBALOPTS

t TCPCONNECT_5 "TCP-CONNECT with a source port, as a regular user. Expected warning message [NOT_PASSED]" \
nping --tcp-connect -g 1000 $TARGETS $GLOBALOPTS

t TCPCONNECT_6 "TCP-CONNECT with a source port, as root." \
sudo nping --tcp-connect -g 1000 $TARGETS $GLOBALOPTS

t TCPCONNECT_7 "TCP-CONNECT with the same source and target port, as root." \
sudo nping --tcp-connect -p 1000 -g 1000 $TARGETS $GLOBALOPTS


#### TCP MODE ####

t TCP_1 "TCP default flags and port. BPF filter?" \
sudo nping --tcp $TARGETS $GLOBALOPTS

t TCP_2 "TCP open port." \
sudo nping --tcp -p$OPEN_PORT $TARGETS $GLOBALOPTS

t TCP_3 "TCP closed port." \
sudo nping --tcp -p$CLOSED_PORT $TARGETS $GLOBALOPTS

t TCP_4 "TCP filtered port." \
sudo nping --tcp -p$FILTERED_PORT $TARGETS $GLOBALOPTS

t TCP_5 "TCP source port." \
sudo nping --tcp -g 1000 $TARGETS $GLOBALOPTS

t TCP_6 "TCP source and dest port combined." \
sudo nping --tcp -g 1000 -p1000 $TARGETS $GLOBALOPTS

# Test no flags, all flags individually, all flags at once.
t TCP_FLAG_empty "TCP flags empty string." \
sudo nping --tcp --flags "" $TARGETS $GLOBALOPTS
for flag in nil none cwr ecn ece urg ack psh rst syn fin all; do
  t TCP_FLAG_$flag "TCP flags $flag." \
  sudo nping --tcp --flags $flag $TARGETS $GLOBALOPTS
done
t TCP_FLAG_all_long "TCP flags cwr,ecn,ece,urg,ack,psh,rst,syn,fin." \
sudo nping --tcp --flags cwr,ecn,ece,urg,ack,psh,rst,syn,fin $TARGETS $GLOBALOPTS
for flag in c e u a p r s f; do
  t TCP_FLAG_$flag "TCP flags $flag." \
  sudo nping --tcp --flags $flag $TARGETS $GLOBALOPTS
done
t TCP_FLAG_all_short "TCP ceuaprsf." \
sudo nping --tcp --flags ceuaprsf $TARGETS $GLOBALOPTS

# Bogus flags.
t TCP_7 "TCP flags ,." \
sudo nping --tcp --flags , $TARGETS $GLOBALOPTS

t TCP_8 "TCP flags dumb." \
sudo nping --tcp --flags dumb $TARGETS $GLOBALOPTS

t TCP_9 "TCP flags dumb,." \
sudo nping --tcp --flags dumb, $TARGETS $GLOBALOPTS

t TCP_10 "TCP flags 0x00." \
sudo nping --tcp --flags 0x00 $TARGETS $GLOBALOPTS

t TCP_11 "TCP flags 0xff." \
sudo nping --tcp --flags 0xff $TARGETS $GLOBALOPTS

t TCP_12 "TCP flags 0x100." \
sudo nping --tcp --flags 0x100 $TARGETS $GLOBALOPTS

t TCP_13 "TCP flags -0x11." \
sudo nping --tcp --flags -0x11 $TARGETS $GLOBALOPTS

t TCP_14 "TCP flags rand." \
sudo nping --tcp --flags rand $TARGETS $GLOBALOPTS

t TCP_15 "TCP seq decimal." \
sudo nping --tcp --seq 12345678 $TARGETS $GLOBALOPTS

t TCP_16 "TCP seq hex." \
sudo nping --tcp --seq 0x12345678 $TARGETS $GLOBALOPTS

t TCP_17 "TCP seq negative." \
sudo nping --tcp --seq -1 $TARGETS $GLOBALOPTS

t TCP_18 "TCP seq too big." \
sudo nping --tcp --seq 10000000000 $TARGETS $GLOBALOPTS

t TCP_19 "TCP seq rand." \
sudo nping --tcp --seq rand $TARGETS $GLOBALOPTS

t TCP_20 "TCP ack decimal." \
sudo nping --tcp --ack 12345678 $TARGETS $GLOBALOPTS

t TCP_21 "TCP ack hex." \
sudo nping --tcp --ack 0x12345678 $TARGETS $GLOBALOPTS

t TCP_22 "TCP ack negative." \
sudo nping --tcp --ack -1 $TARGETS $GLOBALOPTS

t TCP_23 "TCP ack too big." \
sudo nping --tcp --ack 10000000000 $TARGETS $GLOBALOPTS

t TCP_24 "TCP ack rand." \
sudo nping --tcp --ack rand $TARGETS $GLOBALOPTS

t TCP_25 "TCP win decimal." \
sudo nping --tcp --win 1234 $TARGETS $GLOBALOPTS

t TCP_26 "TCP win hex." \
sudo nping --tcp --win 0x1234 $TARGETS $GLOBALOPTS

t TCP_27 "TCP win negative." \
sudo nping --tcp --win -1 $TARGETS $GLOBALOPTS

t TCP_28 "TCP win too big." \
sudo nping --tcp --win 70000 $TARGETS $GLOBALOPTS

t TCP_29 "TCP win rand." \
sudo nping --tcp --win rand $TARGETS $GLOBALOPTS

t TCP_30 "TCP badsum." \
sudo nping --tcp --badsum $TARGETS $GLOBALOPTS

t TCP_31 "TCP mss." \
sudo nping --tcp --mss 900 $TARGETS $GLOBALOPTS

t TCP_32 "TCP ws." \
sudo nping --tcp --ws 2 $TARGETS $GLOBALOPTS

t TCP_33 "TCP ts 1234,5678." \
sudo nping --tcp  --ts 1234,5678 $TARGETS $GLOBALOPTS

t TCP_34 "TCP ts rand,rand." \
sudo nping --tcp  --ts rand,rand $TARGETS $GLOBALOPTS

t TCP_35 "TCP ts 1234." \
sudo nping --tcp  --ts 1234 $TARGETS $GLOBALOPTS



#### UDP MODE ####

# Unprivileged execution
t UDP_UNPRIV_1 "Send UDP packet in unprivileged mode with default parameters. Expected: Packets to dport 40125 and <<UDP packet with 4 bytes>> messages." \
nping --udp $TARGETS $GLOBALOPTS

t UDP_UNPRIV_2 "Send UDP packet to custom dport. Expected: 4-byte UDP packets to port $OPEN_PORT and <<UDP packet with 4 bytes>> messages." \
nping --udp -p $OPEN_PORT $TARGETS $GLOBALOPTS

t UDP_UNPRIV_3 "Send UDP packet specifying a source port." \
nping --udp -g 9876 $TARGETS $GLOBALOPTS

t UDP_UNPRIV_4 "Send UDP packet specifying a both sport and dport." \
nping --udp -g 9876 -p 9999 $TARGETS $GLOBALOPTS

t UDP_UNPRIV_5 "Send UDP packet specifying a the same sport and dport." \
nping --udp -g 9999 -p 9999 $TARGETS $GLOBALOPTS

t UDP_UNPRIV_6 "Send UDP packet to a custom port with a custom payload. Expected: Packets to dport 9876 with 10byte payloads." \
nping --udp -p 9876 $TARGETS $GLOBALOPTS --data-string "0123456789"


# Privileged execution
t UDP_PRIV_1 "Send UDP packet specifying a source port (as root). Expected: Packets to dport 40125 and sport 9876" \
sudo nping --udp -g 9876 $TARGETS $GLOBALOPTS

t UDP_PRIV_2 "Send UDP packet specifying a destination port (as root). Expected: Packets to dport $OPEN_PORT and sport 53" \
sudo nping --udp -p$OPEN_PORT $TARGETS $GLOBALOPTS

t UDP_PRIV_3 "Send UDP packet in privileged mode, speciying sport and dport. Expected: Packets to dport 33 and sport 44." \
sudo nping --udp -p33 -g44 $TARGETS $GLOBALOPTS

t UDP_PRIV_4 "Send UDP packet in privileged mode, speciying dport==sport. Expected: Packets with sport==dport==$OPEN_PORT." \
sudo nping --udp -p$OPEN_PORT -g$OPEN_PORT $TARGETS $GLOBALOPTS

t UDP_PRIV_4 "Send UDP packet in privileged mode, with a bad checksum. Expected: Packets with bad checksum. [See in wireshark]" \
sudo nping --udp -p$OPEN_PORT --badsum $TARGETS $GLOBALOPTS


#### ICMP MODE ####

t ICMP_1 "Run icmp mode with no privileges. Expected: error message." \
nping --icmp $TARGETS $GLOBALOPTS

t ICMP_2 "Run ICMP mode with privileges. Expected: ICMP Echo packets (type=8/code=0)=to $TARGETS." \
sudo nping --icmp $TARGETS $GLOBALOPTS

t ICMP_3 "Run ICMP mode with explicit ICMP Echo especification. Expected: ICMP Echo packets (type=8/code=0)=to $TARGETS." \
sudo nping --icmp --icmp-type echo $TARGETS $GLOBALOPTS

    #sudo nping --icmp --icmp-type echo-request $TARGETS $GLOBALOPTS
    #sudo nping --icmp --icmp-type e $TARGETS $GLOBALOPTS
t ICMP_4 "Run ICMP mode with type Destination Unreachable." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type dest-unr
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type du
t ICMP_5 "Run ICMP mode with type Source Quench." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type source-quench

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type sour-que
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type sq
t ICMP_6 "Run ICMP mode with type Redirect." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type redirect

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type redi
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type r
t ICMP_7 "Run ICMP mode with explicit type Echo request." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo-request

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type e
t ICMP_8 "Run ICMP mode with type Echo reply." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo-reply

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo-rep
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type er
t ICMP_9 "Run ICMP mode with type Router Advertisement." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type router-advertisement

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type rout-adv
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra
t ICMP_3 "Run ICMP mode with type Router Solicitation." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type router-solicitation

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type rout-sol
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type rs
t ICMP_10 "Run ICMP mode with type time Exceeded." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type time-exceeded

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type time-exc
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type te
t ICMP_11 "Run ICMP mode with type Parameter Problem." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type parameter-problem

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type para-pro
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type pp
t ICMP_12 "Run ICMP mode with type Timestamp request." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type time
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type tm
t ICMP_13 "Run ICMP mode with type Timestamp reply." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp-reply

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type time-rep
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type tr
t ICMP_14 "Run ICMP mode with type Information request." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type information

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type info
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type i
t ICMP_15 "Run ICMP mode with type Information reply." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type information-reply

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type info-rep
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ir
t ICMP_16 "Run ICMP mode with type Network Mask request." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type mask-request

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type mask
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type m
t ICMP_17 "Run ICMP mode with type Network Mask reply." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type mask-reply

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type mask-rep
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type mr
t ICMP_18 "Run ICMP mode with type Traceroute request." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type traceroute

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type trace
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type tc
t ICMP_19 "Run ICMP mode with type Destination Unreachable and Code Network Unreachable." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code network-unreachable

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code netw-unr
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code net
t ICMP_20 "Run ICMP mode with type Destination Unreachable and Code Host Unreachable" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code host-unreachable

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code host-unr
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code host
t ICMP_21 "Run ICMP mode with type Destination Unreachable and Code Protocol unreachable" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code protocol-unreachable

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code prot-unr
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code proto
t ICMP_22 "Run ICMP mode with type Destination Unreachable and Code " \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code port-unreachable

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code port-unr
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code port
t ICMP_23 "Run ICMP mode with type Destination Unreachable and Code Needs Fragmentation" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code needs-fragmentation

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code need-fra
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code frag
t ICMP_24 "Run ICMP mode with type Destination Unreachable and Code Source Route Failed" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code source-route-failed

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code sour-rou
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code routefail
t ICMP_25 "Run ICMP mode with type Destination Unreachable and Code network-unknown" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code network-unknown

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code netw-unk
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code net?
t ICMP_26 "Run ICMP mode with type Destination Unreachable and Code host-unknown" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code host-unknown

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code host-unk
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code host?
t ICMP_27 "Run ICMP mode with type Destination Unreachable and Code host-isolated" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code host-isolated

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code host-iso
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code isolated
t ICMP_28 "Run ICMP mode with type Destination Unreachable and Code network-prohibited" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code network-prohibited

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code netw-pro
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code !net
t ICMP_29 "Run ICMP mode with type Destination Unreachable and Code host-prohibited" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code host-prohibited

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code host-pro
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code !host
t ICMP_30 "Run ICMP mode with type Destination Unreachable and Code network-tos" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code network-tos

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code unreachable-network-tos
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code netw-tos
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code tosnet
t ICMP_31 "Run ICMP mode with type Destination Unreachable and Code host-tos" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code host-tos

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code unreachable-host-tos
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code toshost
t ICMP_2 "Run ICMP mode with type Destination Unreachable and Code communication-prohibited" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code communication-prohibited

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code comm-pro
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code !comm
t ICMP_32 "Run ICMP mode with type Destination Unreachable and Code host-precedence-violation" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code host-precedence-violation

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code precedence-violation
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code prec-vio
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code violation
t ICMP_33 "Run ICMP mode with type Destination Unreachable and Code precedence-cutoff" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code precedence-cutoff

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code prec-cut
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type destination-unreachable --icmp-code cutoff
t ICMP_34 "Run ICMP mode with type Redirect and Code redirect-network" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type redirect --icmp-code redirect-network

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type redirect --icmp-code redi-net
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type redirect --icmp-code net
t ICMP_35 "Run ICMP mode with type Redirect and Code redirect-host" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type redirect --icmp-code redirect-host

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type redirect --icmp-code redi-host
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type redirect --icmp-code host
t ICMP_36 "Run ICMP mode with type Redirect and Code redirect-network-tos" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type redirect --icmp-code redirect-network-tos

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type redirect --icmp-code redi-ntos
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type redirect --icmp-code redir-ntos
t ICMP_37 "Run ICMP mode with type Redirect and Code redirect-host-tos" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type redirect --icmp-code redirect-host-tos

    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type redirect --icmp-code redi-htos
    #sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type redirect --icmp-code redir-htos
t ICMP_38 "Run ICMP mode with type Router Advert and Code normal-advertisement" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type router-advertisement --icmp-code normal-advertisement

t ICMP_39 "Run ICMP mode with type Router Advert and Code not-route-common-traffic" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type router-advertisement --icmp-code not-route-common-traffic

t ICMP_40 "Run ICMP mode with type Time Exceeded and Code  ttl-exceeded-in-transit" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type time-exceeded --icmp-code ttl-exceeded-in-transit

t ICMP_41 "Run ICMP mode with type Time Exceeded and Code fragment-reassembly-time-exceeded" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type time-exceeded --icmp-code fragment-reassembly-time-exceeded

t ICMP_42 "Run ICMP mode with type Parameter Problem and Code pointer-indicates-error" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type parameter-problem --icmp-code pointer-indicates-error

t ICMP_43 "Run ICMP mode with type Parameter Problem and Code missing-required-option" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type parameter-problem --icmp-code missing-required-option

t ICMP_44 "Run ICMP mode with type Parameter Problem and Code bad-length" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type parameter-problem --icmp-code bad-length

t ICMP_45 "Run ICMP mode supplying type as an integer" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type 8

t ICMP_46 "Run ICMP mode supplying type as a bogus integer. Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type 100000

t ICMP_47 "Run ICMP mode supplying non-existing type. Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type bogustype

t ICMP_48 "Run ICMP mode supplying a numeric type, NON-RFC compliant (<18). Expected: warning message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type 55

t ICMP_49 "Run ICMP mode supplying a numeric code." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-code 5

t ICMP_50 "Run ICMP mode supplying a bogus code." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-code boguscode

t ICMP_51 "Run ICMP mode supplying a number code, NON-RFC compliant." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-code 99

t ICMP_52 "Set ICMP Identifier. (Don't get confused with output for the IP id value)" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-code 9 --icmp-id 2

t ICMP_53 "Set bogus Identifier. Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-code 9 --icmp-id bogusid

t ICMP_54 "Set negative Identifier. Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-code 9 --icmp-id -99

t ICMP_55 "Set out of bounds Identifier (id>(2^16)-1). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-code 9 --icmp-id 65536

t ICMP_56 "Set ICMP Sequence number." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-code 9 --icmp-seq 22

t ICMP_57 "Set bogus ICMP sequence number. Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-code 9 --icmp-seq bogusseq

t ICMP_58 "Set negative ICMP sequence number. Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-code 9 --icmp-seq -99

t ICMP_59 "Set out of bounds ICMP sequence number (seq>(2^16)-1). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-code 9 --icmp-seq 65536

t ICMP_60 "Send ICMP Redirect with redirect IP=1.2.3.4." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type redirect --icmp-redirect-addr 1.2.3.4

t ICMP_61 "Send ICMP Redirect with redirect IP=google.com. Expected: google.com gets resolved." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type redirect --icmp-redirect-addr google.com

t ICMP_62 "Send ICMP Redirect passing a redirect IP hostname that does not resolve. Expected: error" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type redirect --icmp-redirect-addr bogushostspec

t ICMP_63 "Use --icmp-redirect-addr but don't send ICMP redirect but another type. Expected: parameter ignored" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-redirect-addr 1.2.3.4

t ICMP_64 "Use --icmp-redirect-addr but don't specify ICMP type. Expected: parameter ignored and default ICMP mode set" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-redirect-addr 1.2.3.4

t ICMP_65 "Send ICMP Parameter problem with parameter pointer=0" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type pp --icmp-param-pointer 0

t ICMP_66 "Send ICMP Parameter problem with nonzero parameter pointer" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type pp --icmp-param-pointer 128

t ICMP_67 "Send ICMP Parameter problem with bogus parameter pointer. Expected: error msg" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type pp --icmp-param-pointer boguspp

t ICMP_68 "Send ICMP Parameter problem with negative parameter pointer. Expected: error msg" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type pp --icmp-param-pointer -99

t ICMP_69 "Send ICMP Parameter problem with out-of-bounds parameter pointer (pp>255). Expected: error msg" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type pp --icmp-param-pointer 256

t ICMP_70 "Specify --icmp-param-pointer but use an ICMP Type != ParameterProblem. Expected: parameter ignored" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-param-pointer 22

t ICMP_71 "Specify --icmp-param-pointer but do not specify any ICMP Type. Expected: parameter ignored and default ICMP mode set" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-param-pointer 15

t ICMP_72 "Send ICMP Router Advertisement with advert lifetime=0" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-lifetime 0

t ICMP_73 "Send ICMP Router Advertisement with a nonzero advert lifetime" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-lifetime 37556

t ICMP_74 "Send ICMP Router Advertisement with a bougs advert lifetime. Expected: error msg" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-lifetime bogusAL

t ICMP_75 "Send ICMP Router Advertisement with a negative advert lifetime. Expected: error msg" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-lifetime -56

t ICMP_76 "Send ICMP Router Advertisement with an out-of-bounds (al>65535) advert lifetime. Expected: error msg" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-lifetime 65536

t ICMP_77 "Specify --icmp-advert-lifetime but use an ICMP Type != Router Advertisement. Expected: parameter ignored" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-advert-lifetime 22

t ICMP_78 "Specify --icmp-advert-lifetime but do not specify any ICMP Type. Expected: parameter ignored and default ICMP mode set" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-advert-lifetime 24

t ICMP_79 "Send ICMP Router Advertisement with zeroed advert entry" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-entry 0.0.0.0,0

t ICMP_80 "Send ICMP Router Advertisement with a normal preference and a zero IP" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-entry 0.0.0.0,16777215

t ICMP_81 "Send ICMP Router Advertisement with a normal advert entry" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-entry 1.2.3.4,16777215

t ICMP_82 "Send ICMP Router Advertisement with an advert entry specified as a hostname" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-entry google.com,16777215

t ICMP_83 "Send ICMP Router Advertisement with a few advert entries" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-entry 1.2.3.4,11111 --icmp-advert-entry 11.22.33.44,22222 --icmp-advert-entry 55.66.77.88,333333

t ICMP_84 "Send ICMP Router Advertisement with bogus entry #1 (missing preference). Expected: error msg" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-entry 1.2.3.4,

t ICMP_85 "Send ICMP Router Advertisement with bogus entry #2 (IP). Expected: error msg" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-entry ,10

t ICMP_86 "Send ICMP Router Advertisement with bogus entry #3 (missing parameter). Expected: error msg" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-entry 

t ICMP_87 "Send ICMP Router Advertisement with bogus entry #4 (unresolvable hostname). Expected: error msg" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-entry asdasdasdasdasd,222

t ICMP_88 "Send ICMP Router Advertisement with bogus entry #5 (bad preference). Expected: error msg" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-entry 1.2.3.4,boguspref

t ICMP_89 "Send ICMP Router Advertisement with bogus entry #6 (negative preference). Expected: error msg" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-entry 1.2.3.4,-222

#This works and it should't. "5" should not be resolved to 0.0.0.5 but detected as a bad IP.
t ICMP_90 "Send ICMP Router Advertisement with bogus entry #7 (bad IP format). Expected: error msg" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-entry 5,222

t ICMP_91 "Send ICMP Router Advertisement with bogus entry #8 (out-of-bounds IP). Expected: error msg" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-entry 256.257.258.259,222

t ICMP_92 "Send ICMP Router Advertisement with bogus entry #9 (out-of-bounds preference). Expected: error msg" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-entry 1.2.3.4,999999999999999

t ICMP_93 "Send ICMP Router Advertisement with a duplicated adevert entry. Expected: normal operation" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type ra --icmp-advert-entry 1.2.3.4,555 --icmp-advert-entry 1.2.3.4,555

t ICMP_94 "Specify --icmp-advert-entry but use an ICMP type!= Router Advertisement. Expected: parameter ignored" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-advert-entry 1.2.3.4,555

t ICMP_95 "Specify --icmp-advert-entry but do not specify ICMP type. Expected: parameter ignored and default ICMP mode set" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-advert-entry 1.2.3.4,555

# Parameter --icmp-orig-time
t ICMP_96 "Send ICMP Timestamp Request with zeroed originate timestamp" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-orig-time 0

t ICMP_97 "Send ICMP Timestamp Request with a normal originate timestamp" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-orig-time 57509000

t ICMP_98 "Send ICMP Timestamp Request with current originate timestamp" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-orig-time now

t ICMP_99 "Send ICMP Timestamp Request with current originate timestamp + 1 minute" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-orig-time now+1m

t ICMP_100 "Send ICMP Timestamp Request with current originate timestamp + 2 hours" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-orig-time now+2h

t ICMP_101 "Send ICMP Timestamp Request with current originate timestamp minus 200 milliseconds" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-orig-time now-200ms

t ICMP_102 "Send ICMP Timestamp Request with explicit positive originate timestamp" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-orig-time +10

t ICMP_103 "Send ICMP Timestamp Request with negative originate timestamp. Expected: It should be ok to specify negative values" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-orig-time -10

t ICMP_104 "Send ICMP Timestamp Request with bogus originate timestamp #1 (no number). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-orig-time bogusts

t ICMP_105 "Send ICMP Timestamp Request with bogus originate timestamp #2 (now+bogusspec). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-orig-time now+bogus

t ICMP_106 "Send ICMP Timestamp Request with bogus originate timestamp #3 (now+[nothing]). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-orig-time now+

t ICMP_107 "Send ICMP Timestamp Request with bogus originate timestamp #4 (wrong order 1000+now). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-orig-time 1000+now

t ICMP_108 "Send ICMP Timestamp Request with originate timestamp but specify ICMP Type!=Timestamp. Expected: parameter ignored" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-orig-time now

t ICMP_109 "Send ICMP Timestamp Request with originate timestamp but do not specify ICMP type. Expected: parameter ignored and default ICMP mode set" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-orig-time now

# Parameter --icmp-recv-time
t ICMP_110 "Send ICMP Timestamp Request with zeroed receive timestamp" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-recv-time 0

t ICMP_111 "Send ICMP Timestamp Request with a normal receive timestamp" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-recv-time 57509000

t ICMP_112 "Send ICMP Timestamp Request with current receive timestamp" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-recv-time now

t ICMP_113 "Send ICMP Timestamp Request with current receive timestamp + 1 minute" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-recv-time now+1m

t ICMP_114 "Send ICMP Timestamp Request with current receive timestamp + 2 hours" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-recv-time now+2h

t ICMP_115 "Send ICMP Timestamp Request with current receive timestamp minus 200 milliseconds" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-recv-time now-200ms

t ICMP_116 "Send ICMP Timestamp Request with explicit positive receive timestamp" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-recv-time +10

t ICMP_117 "Send ICMP Timestamp Request with negative receive timestamp. Expected: It should be ok to specify negative values" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-recv-time -10

t ICMP_118 "Send ICMP Timestamp Request with bogus receive timestamp #1 (no number). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-recv-time bogusts

t ICMP_119 "Send ICMP Timestamp Request with bogus receive timestamp #2 (now+bogusspec). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-recv-time now+bogus

t ICMP_120 "Send ICMP Timestamp Request with bogus receive timestamp #3 (now+[nothing]). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-recv-time now+

t ICMP_121 "Send ICMP Timestamp Request with bogus receive timestamp #4 (wrong order 1000+now). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-recv-time 1000+now

t ICMP_122 "Send ICMP Timestamp Request with receive timestamp but specify ICMP Type!=Timestamp. Expected: parameter ignored" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-recv-time now

t ICMP_123 "Send ICMP Timestamp Request with receive timestamp but do not specify ICMP type. Expected: parameter ignored and default ICMP mode set" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-recv-time now

# Parameter --icmp-trans-time
t ICMP_124 "Send ICMP Timestamp Request with zeroed transmit timestamp" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-trans-time 0

t ICMP_125 "Send ICMP Timestamp Request with a normal transmit timestamp" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-trans-time 57509000

t ICMP_126 "Send ICMP Timestamp Request with current transmit timestamp" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-trans-time now

t ICMP_127 "Send ICMP Timestamp Request with current transmit timestamp + 1 minute" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-trans-time now+1m

t ICMP_128 "Send ICMP Timestamp Request with current transmit timestamp + 2 hours" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-trans-time now+2h

t ICMP_129 "Send ICMP Timestamp Request with current transmit timestamp minus 200 milliseconds" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-trans-time now-200ms

t ICMP_130 "Send ICMP Timestamp Request with explicit positive transmit timestamp" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-trans-time +10

t ICMP_131 "Send ICMP Timestamp Request with negative transmit timestamp. Expected: It should be ok to specify negative values" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-trans-time -10

t ICMP_132 "Send ICMP Timestamp Request with bogus transmit timestamp #1 (no number). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-trans-time bogusts

t ICMP_133 "Send ICMP Timestamp Request with bogus transmit timestamp #2 (now+bogusspec). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-trans-time now+bogus

t ICMP_134 "Send ICMP Timestamp Request with bogus transmit timestamp #3 (now+[nothing]). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-trans-time now+

t ICMP_135 "Send ICMP Timestamp Request with bogus transmit timestamp #4 (wrong order 1000+now). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-trans-time 1000+now

t ICMP_136 "Send ICMP Timestamp Request with transmit timestamp but specify ICMP Type!=Timestamp. Expected: parameter ignored" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --icmp-trans-time now

t ICMP_137 "Send ICMP Timestamp Request with transmit timestamp but do not specify ICMP type. Expected: parameter ignored and default ICMP mode set" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-trans-time now

# --icmp-orig-time, --icmp-recv-time and --icmp-trans-time together
t ICMP_138 "Send ICMP Timestamp Request with all timestamps" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp --icmp-orig-time now-2s --icmp-trans-time now-1s --icmp-recv-time now

t ICMP_139 "Test it also works with replies." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type timestamp-reply --icmp-orig-time now-2s --icmp-trans-time now-1s --icmp-recv-time now



#### ARP/RARP MODE ####

t ARP_0 "Test ARP mode with default values. Expected: <<ARP Who has?>> for target host" \
sudo nping --arp $TARGETS $GLOBALOPTS

t ARP_1 "Send ARP Requests" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request

t ARP_2 "Send ARP Replies" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-reply

t ARP_3 "Send RARP Requests" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type rarp-request

t ARP_4 "Send RARP Replies" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type rarp-reply

t ARP_5 "Send DRARP Requests" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type drarp-request

t ARP_6 "Send DRARP Replies" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type drarp-reply

t ARP_7 "Send DRARP Error messages" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type drarp-error

t ARP_8 "Send INARP Requests" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type inarp-request

t ARP_9 "Send INARP Replies" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type inarp-reply

t ARP_10 "Send ARP NAKs" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-nak

t ARP_10b "Supply bogus ARP type" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type bogusarptype

t ARP_10c "Supply NULL ARP type" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type ""

t ARP_11 "Test sender MAC specification #1 (standard notation)" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-sender-mac AA:BB:CC:DD:EE:FF

t ARP_12 "Test sender MAC specification #2 (using hyphens as octet separators)" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-sender-mac AA-BB-CC-DD-EE-FF

t ARP_13 "Test sender MAC specification, suplying a bogus MAC #1 (too short MAC)" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-sender-mac AA:BB:CC:DD:EE

t ARP_14 "Test sender MAC specification, suplying a bogus MAC #2 (too long MAC)" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-sender-mac AA:BB:CC:DD:EE:FF:GG

t ARP_15 "Test sender MAC specification, suplying a bogus MAC #3 (empty MAC)" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-sender-mac ""

t ARP_16 "Test sender MAC specification, suplying a bogus MAC #4 (MAC with a colon at the end)" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-sender-mac AA:BB:CC:DD:EE:FF:

t ARP_17 "Test sender MAC specification, suplying a bogus MAC #4 (MAC with a colon at the beginning)" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-sender-mac :AA:BB:CC:DD:EE:FF

t ARP_18 "Test target MAC specification #1 (standard notation)" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-target-mac AA:BB:CC:DD:EE:FF

t ARP_19 "Test target MAC specification #2 (using hyphens as octet separators)" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-target-mac AA-BB-CC-DD-EE-FF

t ARP_20 "Test target MAC specification, suplying a bogus MAC #1 (too short MAC)" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-target-mac AA:BB:CC:DD:EE

t ARP_21 "Test target MAC specification, suplying a bogus MAC #2 (too long MAC)" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-target-mac AA:BB:CC:DD:EE:FF:GG

t ARP_22 "Test target MAC specification, suplying a bogus MAC #3 (empty MAC)" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-target-mac ""

t ARP_23 "Test target MAC specification, suplying a bogus MAC #4 (MAC with a colon at the end)" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-target-mac AA:BB:CC:DD:EE:FF:

t ARP_24 "Test target MAC specification, suplying a bogus MAC #4 (MAC with a colon at the beginning)" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-target-mac :AA:BB:CC:DD:EE:FF

t ARP_25 "Test sender IP. Supply IP address in standard decimal dot notation" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-sender-ip 1.2.3.4

t ARP_26 "Test sender IP. Supply IP address as a resolvable hostname" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-sender-ip google.com

t ARP_27 "Test sender IP, supplying an unresolvable hostname. Expected: error message" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-sender-ip bogussenderip

t ARP_28 "Test sender IP, supplying a null IP. Expected: error message" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-sender-ip ""

t ARP_29 "Test target IP. Supply IP address in standard decimal dot notation" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-target-ip 1.2.3.4

t ARP_30 "Test target IP. Supply IP address as a resolvable hostname" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-target-ip google.com

t ARP_31 "Test target IP, supplying an unresolvable hostname. Expected: error message" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-target-ip bogustargetip

t ARP_32 "Test target IP, supplying a null IP. Expected: error message" \
sudo nping --arp $TARGETS $GLOBALOPTS --arp-type arp-request --arp-target-ip ""


#### IPV4 OPTIONS ####

t IP_1 "IP source IP." \
sudo nping --tcp -S 5.5.5.5 $TARGETS $GLOBALOPTS

t IP_2 "IP dest IP." \
sudo nping --tcp --dest-ip="$TARGETS" $GLOBALOPTS

t IP_3 "IP dest IP with target specification." \
sudo nping --tcp --dest-ip="5.5.5.5" $TARGETS $GLOBALOPTS

t IP_4 "IP tos decimal." \
sudo nping --tcp --tos 10 $TARGETS $GLOBALOPTS

t IP_5 "IP tos hex." \
sudo nping --tcp --tos 0x10 $TARGETS $GLOBALOPTS

t IP_6 "IP tos negative." \
sudo nping --tcp --tos -5 $TARGETS $GLOBALOPTS

t IP_7 "IP tos too big." \
sudo nping --tcp --tos 256 $TARGETS $GLOBALOPTS

t IP_8 "IP tos rand." \
sudo nping --tcp --tos rand $TARGETS $GLOBALOPTS

t IP_9 "IP id decimal." \
sudo nping --tcp --id 1234 $TARGETS $GLOBALOPTS

t IP_10 "IP id hex." \
sudo nping --tcp --id 0x1234 $TARGETS $GLOBALOPTS

t IP_11 "IP id negative." \
sudo nping --tcp --id -5 $TARGETS $GLOBALOPTS

t IP_12 "IP id too big." \
sudo nping --tcp --id 70000 $TARGETS $GLOBALOPTS

t IP_13 "IP id rand." \
sudo nping --tcp --id rand $TARGETS $GLOBALOPTS

t IP_14 "IP df." \
sudo nping --tcp --df $TARGETS $GLOBALOPTS

t IP_15 "IP mf." \
sudo nping --tcp --mf $TARGETS $GLOBALOPTS

t IP_16 "IP df mf." \
sudo nping --tcp --df --mf $TARGETS $GLOBALOPTS

t IP_17 "IP ttl decimal." \
sudo nping --tcp --ttl 10 $TARGETS $GLOBALOPTS

t IP_18 "IP ttl hex." \
sudo nping --tcp --ttl 0x10 $TARGETS $GLOBALOPTS

t IP_19 "IP ttl negative." \
sudo nping --tcp --ttl -5 $TARGETS $GLOBALOPTS

t IP_20 "IP ttl too big." \
sudo nping --tcp --ttl 256 $TARGETS $GLOBALOPTS

t IP_21 "IP ttl rand." \
sudo nping --tcp --ttl rand $TARGETS $GLOBALOPTS

t IP_22 "IP badsum-ip." \
sudo nping --tcp --badsum-ip $TARGETS $GLOBALOPTS

for mtu in 0 20 600 1500 65536 70000; do
  t IP_mtu$mtu "IP mtu $mtu." \
  sudo nping --tcp --mtu $mtu $TARGETS $GLOBALOPTS
done

t IP_23 "IP options null." \
sudo nping --tcp --ip-options "" $TARGETS $GLOBALOPTS

t IP_24 "IP options R." \
sudo nping --tcp --ip-options "R" $TARGETS $GLOBALOPTS

t IP_25 "IP options R with trailing data." \
sudo nping --tcp --ip-options "R bogus" $TARGETS $GLOBALOPTS

t IP_26 "IP options T." \
sudo nping --tcp --ip-options "T" $TARGETS $GLOBALOPTS

t IP_27 "IP options T with trailing data." \
sudo nping --tcp --ip-options "T bogus" $TARGETS $GLOBALOPTS

t IP_28 "IP options U." \
sudo nping --tcp --ip-options "U" $TARGETS $GLOBALOPTS

t IP_29 "IP options U with trailing data." \
sudo nping --tcp --ip-options "U bogus" $TARGETS $GLOBALOPTS

t IP_30 "IP options S no hops." \
sudo nping --tcp --ip-options "S" $TARGETS $GLOBALOPTS

t IP_31 "IP options S some hops." \
sudo nping --tcp --ip-options "S 1.1.1.1 2.2.2.2" $TARGETS $GLOBALOPTS

t IP_32 "IP options S too many hops." \
sudo nping --tcp --ip-options "S 1.1.1.1 2.2.2.2 3.3.3.3 4.4.4.4 5.5.5.5 6.6.6.6 7.7.7.7 8.8.8.8 9.9.9.9" $TARGETS $GLOBALOPTS

t IP_33 "IP options L no hops." \
sudo nping --tcp --ip-options "L" $TARGETS $GLOBALOPTS

t IP_34 "IP options L some hops." \
sudo nping --tcp --ip-options "L 1.1.1.1 2.2.2.2" $TARGETS $GLOBALOPTS

t IP_35 "IP options L too many hops." \
sudo nping --tcp --ip-options "L 1.1.1.1 2.2.2.2 3.3.3.3 4.4.4.4 5.5.5.5 6.6.6.6 7.7.7.7 8.8.8.8 9.9.9.9" $TARGETS $GLOBALOPTS

t IP_36 "IP options RTUS." \
sudo nping --tcp --ip-options "RTUS 1.1.1.1 2.2.2.2" $TARGETS $GLOBALOPTS

t IP_37 "IP options hex." \
sudo nping --tcp --ip-options "\xff" $TARGETS $GLOBALOPTS

t IP_38 "IP options decimal." \
sudo nping --tcp --ip-options "\255" $TARGETS $GLOBALOPTS

t IP_39 "IP options repetition." \
sudo nping --tcp --ip-options "\x12*8" $TARGETS $GLOBALOPTS


#### IPV6 OPTIONS ####

t IPV6_1 "IPv6 source IP." \
sudo nping -6 --tcp -S 55::55 $TARGETS $GLOBALOPTS

t IPV6_2 "IPv6 dest IP." \
sudo nping -6 --tcp --dest-ip="$TARGETS" $GLOBALOPTS

t IPV6_3 "IPv6 dest IP with target specification." \
sudo nping -6 --tcp --dest-ip="55::55" $TARGETS $GLOBALOPTS

t IPV6_4 "IPv6 flow decimal." \
sudo nping -6 --tcp --flow 10 $TARGETS $GLOBALOPTS

t IPV6_5 "IPv6 flow hex." \
sudo nping -6 --tcp --flow 0x10 $TARGETS $GLOBALOPTS

t IPV6_6 "IPv6 flow negative." \
sudo nping -6 --tcp --flow -5 $TARGETS $GLOBALOPTS

t IPV6_7 "IPv6 flow > 2**20." \
sudo nping -6 --tcp --flow 2000000 $TARGETS $GLOBALOPTS

t IPV6_8 "IPv6 flow > 2**32." \
sudo nping -6 --tcp --flow 10000000000 $TARGETS $GLOBALOPTS

t IPV6_9 "IPv6 flow rand." \
sudo nping -6 --tcp --flow rand $TARGETS $GLOBALOPTS

t IPV6_10 "IPv6 hop-limit decimal." \
sudo nping -6 --tcp --hop-limit 10 $TARGETS $GLOBALOPTS

t IPV6_11 "IPv6 hop-limit hex." \
sudo nping -6 --tcp --hop-limit 0x10 $TARGETS $GLOBALOPTS

t IPV6_12 "IPv6 hop-limit negative." \
sudo nping -6 --tcp --hop-limit -5 $TARGETS $GLOBALOPTS

t IPV6_13 "IPv6 hop-limit too big." \
sudo nping -6 --tcp --hop-limit 256 $TARGETS $GLOBALOPTS

t IPV6_14 "IPv6 hop-limit rand." \
sudo nping -6 --tcp --hop-limit rand $TARGETS $GLOBALOPTS

t IPV6_15 "IPv6 traffic-class decimal." \
sudo nping -6 --tcp --traffic-class 10 $TARGETS $GLOBALOPTS

t IPV6_16 "IPv6 traffic-class hex." \
sudo nping -6 --tcp --traffic-class 0x10 $TARGETS $GLOBALOPTS

t IPV6_17 "IPv6 traffic-class negative." \
sudo nping -6 --tcp --traffic-class -5 $TARGETS $GLOBALOPTS

t IPV6_18 "IPv6 traffic-class too big." \
sudo nping -6 --tcp --traffic-class 256 $TARGETS $GLOBALOPTS

t IPV6_19 "IPv6 traffic-class rand." \
sudo nping -6 --tcp --traffic-class rand $TARGETS $GLOBALOPTS


#### PAYLOAD RELATED OPTIONS ####

t PAYLOAD_1 "Test raw hex payload specification. Data starts with 0x." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data 0xAABBCCDDEEFF

t PAYLOAD_2 "Test raw hex payload specification. Data does not start with 0x." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data AABBCCDDEEFF

t PAYLOAD_3 "Test raw hex payload specification. Data specified with the \xNN format." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data "\xAA\xBB\xCC\xDD\xEE\xFF"

t PAYLOAD_4 "Test raw hex payload specification, specifying bogus hex data #1 (uneven hex chars) Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data 0xAAB

t PAYLOAD_5 "Test raw hex payload specification, specifying bogus hex data #2 (uneven hex chars without the 0x) Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data AAB

t PAYLOAD_6 "Test raw hex payload specification, specifying bogus hex data #3 (uneven hex chars  with the \xNN format.) Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data "\xAA\xB"

t PAYLOAD_7 "Test raw hex payload specification, specifying bogus hex data #4 (uneven hex chars  with the \xNN format.) Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data "\xAA\xB"

t PAYLOAD_8 "Test raw hex payload specification, specifying bogus hex data #5 (non hex digits) Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data 0xFG

t PAYLOAD_9 "Test raw hex payload specification, specifying bogus hex data #6 (non hex digits) Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data FG

t PAYLOAD_10 "Test raw hex payload specification, specifying bogus hex data #7 (no hex digits, just 0x) Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data 0x

t PAYLOAD_11 "Test raw hex payload specification, specifying bogus hex data #8 (no hex digits, just "\x") Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data "\x"

t PAYLOAD_12 "Test raw hex payload specification, specifying bogus hex data #9 (just pass empty quotes) Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data ""

t PAYLOAD_13 "Test string payload specification. Supply a single character." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data-string A

t PAYLOAD_14 "Test string payload specification. Supply sentence" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data-string "Let me tell you about Sally Brown..."

t PAYLOAD_15 "Test string payload specification. Supply hex data. Expected: treat that as a regular ASCII string, not as hex data" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data-string 0xAABBCCDD

t PAYLOAD_16 "Test string payload specification, specifying empty string" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data-string ""

t PAYLOAD_17a "Test random data payload specification. Include 0 bytes." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data-len 0

t PAYLOAD_17b "Test random data payload specification. Include 1 byte." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data-len 1

t PAYLOAD_18 "Test random data payload specification. Include 100 bytes." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data-len 100

t PAYLOAD_19 "Test random data payload specification. Include maximum recomended payload bytes." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data-len 1400

t PAYLOAD_20 "Test random data payload specification. Include more than maximum recomended payload bytes. Expected: warning message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data-len 1401

t PAYLOAD_21 "Test random data payload specification. Include maximum allowed payload bytes." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data-len 65400

t PAYLOAD_22 "Test random data payload specification. Include more tan maximum allowed payload bytes. Expected error message." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data-len 65401

t PAYLOAD_23 "Test random data payload specification. Include a lot more tan maximum allowed payload bytes. Expected error message." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data-len 999999999999999999

t PAYLOAD_24 "Test random data payload specification, specifying bogus data (negative number of bytes)." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data-len -1

# The following tests are not passed because --data-file is currently unimplemented

# Generate an empty file
rm -f NPINGEMPTYFILE.tmp
touch NPINGEMPTYFILE.tmp
t PAYLOAD_25 "Test payload file specification, specifying an empty file. Expected: Packets with a 0-byte payload." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data-file NPINGEMPTYFILE.tmp
# And delete it after the test
rm -f NPINGEMPTYFILE.tmp

# Generate regular empty file
echo "London's burning dial 99999..." > NPINGREGULARFILE.tmp
t PAYLOAD_26 "Test payload file specification, specifying normal file with a normal string. Expected: Packets with the string included." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data-file NPINGREGULARFILE.tmp
# And delete it after the test
rm -f NPINGREGULARFILE.tmp

t PAYLOAD_27 "Test payload file specification, specifying a nonexisting or not-readable file. Expected: error message." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data-file FILE_THAT_DOES_NOT_EXIST.tmp

t PAYLOAD_28 "Test payload file specification, specifying a null filename. Expected: error message." \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --data-file ""

# This doesn't give an error, it just ignores the payload spec.
t PAYLOAD_29 "Test payload specification in TCP connect mode. Expected: warning message." \
nping --tcp-connect $TARGETS $GLOBALOPTS --data-string "Test Payload"


#### ECHO MODE ####

# Client
t ECHO_1 "Test client connection to echo.nmap.org." \
sudo nping --echo-client "public" echo.nmap.org -c2

t ECHO_2 "Test client connection to a bogus server" \
sudo nping --echo-client "public" bogus.bogus

t ECHO_3 "Test client connection to a server that has no NEP service running" \
sudo nping --echo-client "public" google.com

t ECHO_4 "Test client connection to echo.nmap.org using the explicit port number 9929" \
sudo nping --echo-client "public" echo.nmap.org --echo-port 9929 -c2

t ECHO_5 "Test client connection to echo.nmap.org but using a different port" \
sudo nping --echo-client "public" echo.nmap.org --echo-port 34554

t ECHO_6 "Test client connection to echo.nmap.org but using an invalid port number #1" \
sudo nping --echo-client "public" echo.nmap.org --echo-port -1

t ECHO_7 "Test client connection to echo.nmap.org but using an invalid port number #2" \
sudo nping --echo-client "public" echo.nmap.org --echo-port BOGUSPORT

t ECHO_8 "Test client connection to echo.nmap.org but using an invalid port number #3" \
sudo nping --echo-client "public" echo.nmap.org --echo-port 65536

t ECHO_9 "Test client connection to echo.nmap.org but using an invalid port number #4" \
sudo nping --echo-client "public" echo.nmap.org --echo-port 0

t ECHO_10 "Test client connection to echo.nmap.org. TCP mode" \
sudo nping --echo-client "public" echo.nmap.org --tcp -c2

t ECHO_11 "Test client connection to echo.nmap.org. UDP mode" \
sudo nping --echo-client "public" echo.nmap.org --udp -c2

t ECHO_12 "Test client connection to echo.nmap.org. ICMP mode" \
sudo nping --echo-client "public" echo.nmap.org --icmp -c2

t ECHO_13 "Test client connection to echo.nmap.org. TCP connect mode. Expected: Failure" \
sudo nping --echo-client "public" echo.nmap.org --tcp-connect

t ECHO_14 "Test client connection to echo.nmap.org. ARP mode. Expected: Failure" \
sudo nping --echo-client "public" echo.nmap.org --arp

t ECHO_15 "Test client connection to echo.nmap.org. RARP mode. Expected: Failure" \
sudo nping --echo-client "public" echo.nmap.org --rarp

t ECHO_16 "Test client connection to echo.nmap.org, using the wrong password." \
sudo nping --echo-client "BOGUS" echo.nmap.org

t ECHO_17 "Test client connection to echo.nmap.org, using --no-crypto. Expected: Failure" \
sudo nping --echo-client "a" echo.nmap.org --no-crypto

t ECHO_18 "Test client connection to echo.nmap.org, NOT running as root. Expected: Failure" \
nping --echo-client "a" echo.nmap.org

t ECHO_19 "Test client connection to echo.nmap.org. No passphrase supplied." \
nping echo.nmap.org --echo-client

t ECHO_20 "Test client connection to echo.nmap.org. No target host supplied." \
nping --echo-client "public"

# Server
t ECHO_21 "Test. Run the server normally" \
sudo nping --echo-server "public"

t ECHO_22 "Test. Run the server, but NOT as root. Expected: Failure" \
nping --echo-server "public"

t ECHO_23 "Test. Run the server with --no-crypto" \
sudo nping --echo-server "" --no-crypto

t ECHO_24 "Test. Run the server specifying the interface to use for capture ($EXISTING_NET_IFACE)" \
sudo nping --echo-server "public" -e $EXISTING_NET_IFACE

t ECHO_25 "Test. Run the server specifying an interface that does not exist." \
sudo nping --echo-server "public" -e BOGUS_INTERFACE

t ECHO_26 "Test. Run the server with --once. You should run a client in parallel (sudo nping --echo-client public --echo-port 33445 localhost -c1)" \
sudo nping --once --echo-server "public" --echo-port 33445 -e lo &

t ECHO_27 "Test. Run the server with --no-crypto.  You should run a client in parallel (sudo nping --echo-client "" --no-crypto --echo-port 33446 localhost -c1)" \
sudo nping --once --echo-server "" --no-crypto --echo-port 33446 -e lo &


#### TIMING AND PERFORMANCE OPTIONS ####

t TIMING_1 "Test inter packet delay. Specify 1sec" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --delay 1s -c 2

t TIMING_2 "Test inter packet delay. Specify 10secs" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --delay 10s -c 2

t TIMING_3 "Test inter packet delay. Specify 0.1 (100ms) " \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --delay 100ms -c 2

t TIMING_4 "Test inter packet delay. Specify 0.5ms" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --delay 100ms -c 2

t TIMING_5 "Test inter packet delay specifying a bogus interval #1 (negative value). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --delay -10 -c2

t TIMING_6 "Test inter packet delay specifying a bogus interval #2 (empty value). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --delay "" -c2

t TIMING_7 "Test inter packet delay specifying a bogus interval #3 (no digits value). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --delay bogusdelay -c2

t TIMING_8 "Test inter packet delay specifying a bogus interval #4 (bad time specifier). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --delay 10xy -c2

t TIMING_9 "Test packet transmission rate. 1 packet per second " \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --rate 1

t TIMING_10 "Test packet transmission rate. 5 packets per second " \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --rate 5

t TIMING_11 "Test packet transmission rate. 99 packets per second " \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --rate 99

t TIMING_12 "Test packet transmission rate. 10,000 packets per second " \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --rate 10000

t TIMING_13 "Test packet transmission rate, specifying a bougus rate #1 (0 pps). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --rate 0

t TIMING_14 "Test packet transmission rate, specifying a bougus rate #2 (negative rate). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --rate -1

t TIMING_15 "Test packet transmission rate, specifying a bougus rate #3 (non numerical rate). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --rate bogusrate

t TIMING_16 "Test packet transmission rate, specifying a bougus rate #4 (very large rate). Expected: error message" \
sudo nping --icmp $TARGETS $GLOBALOPTS --icmp-type echo --rate 99999999999999999999999


#### MISCELLANEOUS OPTIONS ####

t MISC_1 "Test help display option (-h)" \
nping -h

t MISC_2 "Test help display option (--help)" \
nping --help

t MISC_3 "Test version display option (-V)" \
nping -V

t MISC_4 "Test version display option (--version)" \
nping --version

t MISC_5 "Test round number specification. Just send one packet to each target " \
sudo nping --tcp $TARGETS $GLOBALOPTS --flags psh,fin,syn -c 1

t MISC_6 "Test round number specification. Send two packets to each target " \
sudo nping --tcp $TARGETS $GLOBALOPTS --flags psh,fin,syn -c 2

t MISC_7 "Test round number specification. Send infinite packets [Press CTRL-C to quit]" \
sudo nping --tcp $TARGETS $GLOBALOPTS --flags psh,fin,syn -c 0

t MISC_8 "Test round number specification, specifying a bogus number #1 (negative value) " \
sudo nping --tcp $TARGETS $GLOBALOPTS --flags psh,fin,syn -c -1

t MISC_9 "Test round number specification, specifying a bogus number #2 (non-numeric value) " \
sudo nping --tcp $TARGETS $GLOBALOPTS --flags psh,fin,syn -c boguscount

t MISC_10 "Test network interface specification. Supply an interface that exists ($EXISTING_NET_IFACE) " \
sudo nping --tcp $TARGETS $GLOBALOPTS --flags psh,fin,syn -e $EXISTING_NET_IFACE

t MISC_11 "Test network interface specification. Supply an interface that does not exist. Expected: error message." \
sudo nping --tcp $TARGETS $GLOBALOPTS --flags psh,fin,syn -e bogusinterface

t MISC_12 "Test network interface specification,  specifying a bogus interface name (null). Expected: error message" \
sudo nping --tcp $TARGETS $GLOBALOPTS --flags psh,fin,syn -e ""

t MISC_13 "Test --hide-sent option. Expected: sent packets not shown." \
sudo nping --tcp $TARGETS $GLOBALOPTS --flags psh,fin,syn --hide-sent

t MISC_14 "Test --no-capture option. Expected: no replies captured. This is run against localhost (overriding global TARGETS) to make sure we get TCP RST packets but we don't capure them." \
sudo nping --tcp localhost $GLOBALOPTS --flags psh,fin,syn --no-capture

t MISC_15 "Force unprivileged execution. Expected: Error message complaining about TCP more requiring privileges" \
sudo nping --tcp $TARGETS $GLOBALOPTS --flags psh,fin,syn --unprivileged

t MISC_16 "Force unprivileged execution. Expected: Operation in TCP-Connect mode" \
sudo nping $TARGETS $GLOBALOPTS --unprivileged

t MISC_17 "Force privileged execution (being non-root). Expected: Error caused by a failed system call." \
nping $TARGETS $GLOBALOPTS --privileged

t MISC_18 "Force privileged execution (being root). Expected: Normal operation." \
sudo nping $TARGETS $GLOBALOPTS --privileged

# This works on normal connection but fails when working through a VPN
t MISC_19 "Test --send-eth. Expected: Normal operation, sending packet at ethernet level." \
sudo nping $TARGETS $GLOBALOPTS --send-eth

t MISC_20 "Test --send-ip. Expected: Normal operation in Linux, etc. Possible failure on windows." \
sudo nping $TARGETS $GLOBALOPTS --send-ip

t MISC_21 "Test custom BPF filter specification. Capture all IP traffic. [You need to browse the web or generate another traffic in parallel]. Expected: ICMP traffic and any other IP traffic shown" \
sudo nping $TARGETS $GLOBALOPTS --bpf-filter "ip" -c 30

t MISC_21 "Test custom BPF filter specification. Capture only TCP. Expected: no ICMP replies shown." \
sudo nping $TARGETS $GLOBALOPTS --bpf-filter "tcp"

t MISC_22 "Test custom BPF filter specification, specifying a bogus BPF filter spec #1 (null spec). Expected: capture all traffic" \
sudo nping $TARGETS $GLOBALOPTS --bpf-filter ""

t MISC_23 "Test custom BPF filter specification, specifying a bogus BPF filter spec #2 (incorrect spec). Expected: error message." \
sudo nping $TARGETS $GLOBALOPTS --bpf-filter "bogus_spec"





#####################
#   PRINT RESULTS   # 
#####################
END_TIME=`date +"%s"`
ELAPSED_TIME=`expr $END_TIME - $START_TIME`
echo "[+] ============== RESULTS =============="
echo "[+] Total tests run      : $TOTAL_TESTS_RUN"
echo "[+] Total tests PASSED   : $TOTAL_TESTS_PASSED"
echo "[+] Total tests FAILED   : $TOTAL_TESTS_FAILED"
echo "[+] List of PASSED Tests : $PASSED_TESTS"
echo "[+] List of FAILED Tests : $FAILED_TESTS"
echo "[+] Time elapsed         : $ELAPSED_TIME seconds"
exit
