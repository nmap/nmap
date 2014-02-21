#!/usr/bin/env python
################################################################################
#                                                                              #
#                       IPv6 OS detection test suite                           #
#                                                                              #
#                                                                              #
#                          Luis MartinGarcia                                   #
#                        {luis.mgarc@gmail.com}                                #
#                                                                              #
################################################################################
import getopt
import sys
from scapy.all import *
import warnings
import time
import signal
from struct import *
from socket import *

#############################
# DEFAULT HEADER PARAMETERS #
#############################

# IP version 6
IPv6_DEFAULT_HOP_LIMIT=128
IPv6_DEFAULT_TRAFFIC_CLASS=0
IPv6_DEFAULT_FLOW_LABEL=0x12345

# ICMP version 6
ICMPv6_DEFAULT_TYPE=128 # Cannot be changed
ICMPv6_DEFAULT_CODE=0
ICMPv6_DEFAULT_IDENTIFIER=0xABCD
ICMPv6_DEFAULT_SEQUENCE=0x0123

# IP version 4
IPv4_DEFAULT_TTL=128
IPv4_DEFAULT_TOS=0
IPv4_DEFAULT_ID=0xABCD
IPv4_DEFAULT_FRAGOFF=0
IPv4_DEFAULT_FLAGS=0

# ICMP version 4
ICMPv4_DEFAULT_TYPE=8 # Echo request
ICMPv4_DEFAULT_CODE=0
ICMPv4_DEFAULT_IDENTIFIER=0xDDEE
ICMPv4_DEFAULT_SEQUENCE=0x9876

# TCP
TCP_DEFAULT_SPORT=20
TCP_DEFAULT_DPORT=80
TCP_DEFAULT_SEQ=0x12345678
TCP_DEFAULT_ACK=0x00
TCP_DEFAULT_WIN=4096
TCP_DEFAULT_FLAGS='S'
TCP_DEFAULT_URG=0x00

#UDP
UDP_DEFAULT_SPORT=53
UDP_DEFAULT_DPORT=53
UDP_PORT_53_PAYLOAD="\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00"

# Payloads
ASCII_PAYLOAD_16="0123456789ABCDEF"
ASCII_PAYLOAD_32="0123456789ABCDEF"*2
ASCII_PAYLOAD_64="0123456789ABCDEF"*4
ASCII_PAYLOAD_128="0123456789ABCDEF"*8
ASCII_PAYLOAD_256="0123456789ABCDEF"*16
ASCII_PAYLOAD_512="0123456789ABCDEF"*32
ASCII_PAYLOAD_1024="0123456789ABCDEF"*64
ASCII_PAYLOAD_2048="0123456789ABCDEF"*128

# Miscellaneous
DEFAULT_OPEN_PORT_IN_TARGET=80
DEFAULT_CLOSED_PORT_IN_TARGET=9999
NUM_SEQ_SAMPLES=6
DEFAULT_INTERPACKET_DELAY=0
DEFAULT_CAPTURE_TIMEOUT=2

####################
# GLOBAL VARIABLES #
####################
# Target host
target_host6_g=None
target_host4_g=None

# Simple list of test numbers (0, 1, 2, ... , N)
test6_ids=list()
test4_ids=list()

# List of test textual descriptions
test6_descriptions=list()
test4_descriptions=list()

# List of test probes
test6_packets=list()
test4_packets=list()

# List of test results
test6_replies=list()
test4_replies=list()

# Final result vector
result_vector6=list()
result_vector4=list()

# Offsets for the TCP source port of some probes (current Nmap OS detection probes)
source_port_g=48621

# Open and closed ports
open_port_g=None
closed_port_g=None

# Some fixed values for TCP Seq and TCP Ack
tcpSeqBase=0x5f2ecb23
tcpAck=0xbc2efd0a

# ICMP Sequence Number
icmp_seq_g=0

# Test range
first_test_g=0
last_test_g=99999

# Send & receive parameters
capture_timeout_g=DEFAULT_CAPTURE_TIMEOUT
packet_retries_g=2
interface_g=None
inter_test_delay_g=1   # Time between each test (in seconds)
inter_packet_delay_g=DEFAULT_INTERPACKET_DELAY   # Time between each packet (for tests that consist of more than one)
target_mac_addr_g=None
source_ipv6_addr_g=None
source_ipv4_addr_g=None
send_eth_g=None

# Misc
debug_g=False
start_time_g=None
output_data=[]
output_file_name_g="nmap6fp"+str(random.random())[2:-4]+".6fp"
result_report_email_g="david+luis@nmap.org"
target_os_details_g=None
do_connectivity_test_g=True
interactive_mode_g=False

#################################
# DEFAULT PACKET "CONSTRUCTORS" #
#################################

# Generic IPv6 datagram
def build_default_ipv6(target):
    pkt=IPv6()
    pkt.hlim=IPv6_DEFAULT_HOP_LIMIT
    pkt.tc=IPv6_DEFAULT_TRAFFIC_CLASS
    pkt.fl=IPv6_DEFAULT_FLOW_LABEL
    pkt.dst=target
    if source_ipv6_addr_g != None :
        pkt.src=source_ipv6_addr_g
    return pkt

# Generic ICMPv6 Echo Request
def build_default_icmpv6():
    pkt=ICMPv6EchoRequest()
    pkt.code=ICMPv6_DEFAULT_CODE
    pkt.id=ICMPv6_DEFAULT_IDENTIFIER
    pkt.seq=ICMPv6_DEFAULT_SEQUENCE
    return pkt

# Generic IPv4 datagram
def build_default_ipv4(target):
    pkt=IP()
    pkt.tos=IPv4_DEFAULT_TOS
    pkt.id=IPv4_DEFAULT_ID
    pkt.flags=IPv4_DEFAULT_FLAGS
    pkt.frag=IPv4_DEFAULT_FRAGOFF
    pkt.ttl=IPv4_DEFAULT_TTL
    pkt.dst=target
    if source_ipv4_addr_g != None :
        pkt.src=source_ipv4_addr_g
    return pkt

# Generic ICMPv4 Echo Request
def build_default_icmpv4():
    pkt=ICMP()
    pkt.type=ICMPv4_DEFAULT_TYPE
    pkt.code=ICMPv4_DEFAULT_CODE
    pkt.id=ICMPv4_DEFAULT_IDENTIFIER
    pkt.seq=ICMPv4_DEFAULT_SEQUENCE
    return pkt

# Generic TCP Syn packet
def build_default_tcp():
    pkt=TCP()
    pkt.sport=TCP_DEFAULT_SPORT
    pkt.dport=TCP_DEFAULT_DPORT
    pkt.seq=TCP_DEFAULT_SEQ
    pkt.ack=TCP_DEFAULT_ACK
    pkt.dataofs= None
    pkt.reserved= 0
    pkt.flags=TCP_DEFAULT_FLAGS
    pkt.window=TCP_DEFAULT_WIN
    pkt.urgptr=TCP_DEFAULT_URG
    return pkt

# Generic UDP packet.
def build_default_udp():
    pkt=UDP()
    pkt.sport=UDP_DEFAULT_SPORT
    pkt.dport=UDP_DEFAULT_DPORT
    return pkt

# Returns an unused source port number
def get_source_port_number():
    global source_port_g
    source_port_g=source_port_g+1
    return source_port_g-1

# Returns an unused ICMP sequence number
def get_icmp_seq_number():
    global icmp_seq_g
    icmp_seq_g=icmp_seq_g+1
    return icmp_seq_g-1

#############################
# STANDARD OUTPUT FUNCTIONS #
#############################

def print_start_separator():
    print "---------------------------------- BEGIN TEST ----------------------------------"

def print_end_separator():
    print "---------------------------------- END OF TEST ---------------------------------"

def print_sent_packet(test_packet):
    if type(test_packet)==list :
          for i in range(0, len(test_packet)) :
            print "[+] Test Packet #" + str(i) + ":"
            test_packet[i].show2()
            hexdump(test_packet[i])
    else :
        print "[+] Test Packet:"
        test_packet.show2()
        hexdump(test_packet)

def store_line(line2print):
    output_data.append("#PARSE# "+line2print)

def print_and_store_line(line2print):
    print "[#] " + line2print
    store_line(line2print)

def print_received_packet(packet):
    try:
        packet.show(label_lvl="    ")
        hexdump(packet)
    except:
        return
    return



def print_parseable_test_result(test_number, responses, ip_version):
    if ip_version==4 :
        tag="result4"
    elif ip_version==6 :
        tag="result6"

    # If we received responses, print each of them
    if responses!=None and len(responses)>0 :
        
        rs=-1
        for response in responses:
            rs=rs+1


            # Determine how many layers are present in the packet
            pkt=response
            layers=0
            while type(pkt)!=scapy.packet.NoPayload :
                pkt=pkt.payload
                layers=layers+1

            # Try to obtain the packet's hexdump (scapy is buggy and fails to do
            # this in certain cases). What we do here is: try to display the whole
            # packet. If it fails, remove the layer on the top and try again. Repeat
            # until we run out of layers or the operation succeeds.
            pktstr=''
            removed=0
            for i in range(0, layers) :
                try:
                    pktstr=hexstr(str(response), onlyhex=1)
                    break
                except :
                    response[layers-i-2].remove_payload()
                    print "Error displaying packet. Removing layer "+str(layers-i)
                    removed=removed+1

            # Print result status (Truncated, Full or Empty) along with the total number of layers and the number of layers that were chopped.
            if removed>0 :
                print_and_store_line("rstatus={"+str(test_number)+", Truncated, "+str(layers)+", "+str(removed)+"}")
            else :
                print_and_store_line("rstatus={"+str(test_number)+", Full, "+str(layers)+ ", 0}")

            # Print the actual packet contents
            print_and_store_line( tag+ "={" + str(test_number) + ", " + str(rs) + ", " + pktstr + "}" )
    # Otherwise, print and empty response tag
    else:
        print_and_store_line("status={"+str(test_number)+", Empty, 0, 0}")
        print_and_store_line( tag + "={" + str(test_number)+ ", 0,}")

def print_parseable_sent_packet(test_number, test_packet, ip_version):
    if ip_version==4 :
        tag="sent4"
    elif ip_version==6 :
        tag="sent6"

    if type(test_packet)==list :
          for i in range(0, len(test_packet)) :
            print_and_store_line(tag + "={"+str(test_number)+", " + str(i) +", " + hexstr(str(test_packet[i]), onlyhex=1) + "}")
    else :
        print_and_store_line(tag + "={"+str(test_number)+", " + "0" +", " + hexstr(str(test_packet), onlyhex=1) + "}")

def print_parseable_time_dependent_test_result(test_number, response, ip_version):
    if ip_version==4 :
        tag="timed4_result"
    else :
        tag="timed6_result"
    if response != None :
        print_and_store_line(tag+"={"+str(test_number)+","+hexstr(str(response), onlyhex=1)+"}")
    else:
        print_and_store_line(tag+"={"+str(test_number)+",}")

def print_test_id(test_id, ip_version):
    if ip_version==4 :
        print_and_store_line("test4_id=" + str(test_id))
    else :
        print_and_store_line("test6_id=" + str(test_id))

def print_test_number(test_num):
    print_and_store_line("test_no=" + str(test_num))

def print_test_description(test_desc):
    print "[+] Test Description: " + str(test_desc)

def print_welcome_banner():
    print "================================================================="
    print "==            NMAP IPv6 OS DETECTION RESEARCH TOOL             =="
    print "================================================================="
    print " You are running ipv6fp, an internal research tool for the Nmap  "
    print " Security Scanner. This program will send about 150 IPv6 network "
    print " probes to a target system and collect any responses received.   "
    print " The results will let us build a new IPv6 stack fingerprinting   "
    print " engine in Nmap.                                                 "
    print "                                                                 "
    print " We'd like to thank you in advance for running this tool. After  "
    print " the execution has finished, a file with the following name      "
    print " will be created in the working directory:                       "
    print "                                                                 "
    print output_file_name_g.center(65)
    print "                                                                 "
    print " Please send it to the following address: " + result_report_email_g
    print "                                                                 "
    print "================================================================="

def print_debug_info():
    print "== IPv6 Routing information ====================================="
    print conf.route6
    print "== IPv4 Routing information ====================================="
    print conf.route
    print "== Other Details ================================================"
    print "[+] IPv4 Interface:      " + conf.iface
    print "[+] IPv6 Interface:      " + conf.iface6
    print "[+] User interface:      " + interface_g
    print "[+] IPv6 enabled:        " + str(conf.ipv6_enabled)
    print "[+] Python version:      " + sys.version.replace('\n', '')
    print "[+] Scapy version:       " + conf.version
    print "[+] Run as root:         " + str(os.geteuid()==0)

    if target_os_details_g!=None:
        print "[+] OS Type:             " + target_os_details_g[0]
        print "[+] OS Sub-type:         " + target_os_details_g[1]
        print "[+] OS Version:          " + target_os_details_g[2]

    if target_host6_g!=None :
        print "[+] Dst IPv6 Address:    " + str(target_host6_g)

    if target_host4_g!=None :
        print "[+] Dst IPv4 Address:    " + str(target_host4_g)

    if source_ipv6_addr_g!=None :
        print "[+] Src IPv6 Address:    " + str(source_ipv6_addr_g)

    if source_ipv4_addr_g!=None :
        print "[+] Src IPv4 Address:    " + str(source_ipv4_addr_g)

    if target_mac_addr_g!=None:
        print "[+] Gateway MAC:         " + str(target_mac_addr_g)

    print "[+] Send eth:            " + str(send_eth_g)
    print "[+] Open Port:           " + str(open_port_g)
    print "[+] Open Port:           " + str(closed_port_g)
    print "[+] Timeout:             " + str(capture_timeout_g)
    print "[+] Retries:             " + str(packet_retries_g)
    print "[+] Inter-test delay:    " + str(inter_test_delay_g)
    print "[+] Inter-packet delay:  " + str(inter_packet_delay_g)
    print "[+] Debug:               " + str(debug_g)
    print "================================================================="

def print_test_results():
    print "================================================================="
    print "==             NMAP IPv6 OS DETECTION TEST RESULTS             =="
    print "================================================================="
    if target_host4_g!=None :
        for i in range(0, len(test4_replies)) :
            sys.stdout.write("IPv4 TEST #")
            sys.stdout.write(str(test4_ids[i]))
            sys.stdout.write("=")
            if test4_replies[i]!=None :
                print "Response received"
            else :
                print "No response"
    if target_host6_g!=None :
        j=0
        for i in range(first_test_g, min( len(test6_replies), last_test_g+1) ) :
            sys.stdout.write("IPv6 TEST #")
            sys.stdout.write(str(test6_ids[i]))
            sys.stdout.write("=")
            if test6_replies[j]!=None :
                print "Response received"
            else :
                print "No response"
            j=j+1
    print "================================================================="
    print "==                     SUMMARY OF RESULTS                      =="
    print "================================================================="
    print_and_store_line("currtime={" + str(time.time()) +", " + time.ctime()+"}" )
    if target_os_details_g!=None:
        print_and_store_line("ostype="+target_os_details_g[0])
        print_and_store_line("ossubtype="+target_os_details_g[1])
        print_and_store_line("osversion="+target_os_details_g[2])
    if target_host6_g!=None :
        print_and_store_line("hostaddr6="+str(target_host6_g))
    if target_host4_g!=None :
        print_and_store_line("hostaddr4="+str(target_host4_g))
    print_and_store_line("timeout="+str(capture_timeout_g))
    print_and_store_line("retries="+str(packet_retries_g))
    print_and_store_line("interface="+interface_g)
    print_and_store_line("delay="+str(inter_test_delay_g))
    print_and_store_line("debug="+str(debug_g))
    if len(result_vector6) > 0 :
        print_and_store_line("rvector6=" + str(result_vector6))
    if len(result_vector4) > 0 :
        print_and_store_line("rvector4=" + str(result_vector4))
    print "                                                                 "
    print " Thank you for running this tool. A file with the following name "
    print " has been created in the working directory:                      "
    print "                                                                 "
    print output_file_name_g.center(65)
    print "                                                                 "
    if target_os_details_g!=None:
        print " Please send it to the following address: " + result_report_email_g
    else :
        print " Please edit the file to provide details about the target's      "
        print " operating system type and version. Read the instructions at the "
        print " top.                                                            "
        print "                                                                 "
        print " Once you're done, please send the file to the following address:"
        print "                                                                 "
        print result_report_email_g.center(65)
    print "                                                                 "
    print "================================================================="

def get_results_file_header():
    text= [ '================================================================================',
            '==                   NMAP IPv6 OS DETECTION RESEARCH TOOL                     ==',
            '==                ------------------------------------------                  ==',
            '==                                                                            ==',
            '==                            ==RESULTS FILE==                                ==',
            '==                                                                            ==',
            '================================================================================',
           ]
    return text

def get_results_file_osrequest():
    text= [ '==  IMPORTANT! Please provide some information about the target OS: OS type,  ==',
            '==  OS sub-type and OS version.                                               ==',
            '==                                                                            ==',
            '==  Please chose an OS type and subtype from the following table, and replace ==',
            '==  the XXXXXXX value in the "ostype=" and "ossubtype=" labels below (do NOT  ==',
            '==  include the quote marks).                                                 ==',
            '==                                                                            ==',
            '==  +---------+------------------------------------------------------------+  ==',
            '==  | OS TYPE | OS SUB-TYPE                                                |  ==',
            '==  +---------+------------------------------------------------------------+  ==',
            '==  | Linux   | "CentOs", "Debian", "Fedora", "Gentoo", "Mandriva",        |  ==',
            '==  |         | "Mint", "Redhat", "Slackware", "Suse", "Ubuntu", "Other"   |  ==',
            '==  +---------+------------------------------------------------------------+  ==',
            '==  | BSD     | "DragonFlyBSD", "FreeBSD", "NetBSD", "OpenBSD",            |  ==',
            '==  |         | "PC-BSD", "Other"                                          |  ==',
            '==  +---------+------------------------------------------------------------+  ==',
            '==  | Windows | "XP", "Vista", "7", "2003 Server", "2008 Server", "Other"  |  ==',
            '==  +---------+------------------------------------------------------------+  ==',
            '==  | MacOS X | "Puma", "Jaguar", "Panther", "Tiger", "Leopard",           |  ==',
            '==  |         | "Snow Leopard", "Lion", "Other"                            |  ==',
            '==  +---------+------------------------------------------------------------+  ==',
            '==  | Solaris | "Sun Solaris", "OpenSolaris", "OpenIndiana", "SchilliX",   |  ==',
            '==  |         | "Other"                                                    |  ==',
            '==  +---------+------------------------------------------------------------+  ==',
            '==  | Other   | "Router", "Firewall", "Switch", "Proxy", "Other"           |  ==',
            '==  +---------+------------------------------------------------------------+  ==',
            '==                                                                            ==',
            '== INSERT THE OS DETAILS HERE:                                                ==',
            '#PARSE# ostype=XXXXXXX',
            '#PARSE# ossubtype=XXXXXXX',
            '#PARSE# osversion=XXXXXXX',
            '#PARSE# os_additional_comments=',
            '==                                                                            ==',
            '== The OS version can be a distro version (e.g., "10.04", "Core 4"), a        ==',
            '== service pack id (e.g., "SP2"), a firmware version (e.g., "12.2SG"), or a   ==',
            '== kernel version (e.g., 2.6.28).                                             ==',
            "== If you'd like to provide additional information, like the output of        ==",
            '== "uname -a", details about your network configuration, etc, please add them ==',
            '== after the "os_additional_comments=" tag above.                             =='
            '\r\n\r\n\r\n',
    ]
    return text

def print_time_elapsed():
    print_and_store_line("elapsed=" + str(get_time_elapsed()))

def print_usage(f = sys.stdout):
    print >> f, """\
Usage: %(progname)s {Target} [Options]

  OPTIONS:
   -h, --help           Show this help.
       --ot=PORT        Use PORT as open TCP port (default %(ot)s).
       --ct=PORT        Use PORT as closed TCP port (default %(ct)s).
       --noports        Use default open/closed port numbers.
       --from=N         Start from test #N
       --to=N           Stop execution after test #N
       --test=N         Run only test #N
       --interface=DEV  Use the DEV network interface.
       --delay=N        Wait N seconds between each test.
       --retries=N      Retransmit unanswered packets N times.
       --send-eth       Transmit packets at the ethernet level.
       --send-ip        Transmit packets at the IP level.
       --debug          Print debugging information.
       --addr4=ADDR     Specify the target's IPv4 address.
       --interactive    Ask parameter values interactively.
""" % { "progname": sys.argv[0], "ot": DEFAULT_OPEN_PORT_IN_TARGET,
        "ct": DEFAULT_CLOSED_PORT_IN_TARGET }

def print_debug(debug_msg):
    if( debug_g==True and debug_msg!=None):
        print debug_msg


########################
# PACKET I/O FUNCTIONS #
########################

def filter_ip_responses(packet_set, src, dst, ip_version):
    result=[]

    # Determine matching type
    if ip_version==6 :
        match_type=scapy.layers.inet6.IPv6
    else :
        match_type=scapy.layers.inet.IP

    for packet in packet_set :
        if type(packet)==match_type :
            if packet.dst==src and packet.src==dst :
                result.append(packet)
    return result

def filter_ipv6_responses(packet_set, src, dst):
    return filter_ip_responses(packet_set=packet_set, src=src, dst=dst, ip_version=6)

def filter_ipv4_responses(packet_set, src, dst):
    return filter_ip_responses(packet_set=packet_set, src=src, dst=dst, ip_version=4)

def filter_responses(sent, received):
    aux=[]
    final_results=[]
    if sent==None or received==None :
        return None

    # If we only have one sent packet, turn it into a list
    if type(sent)!=list :
        sent=[sent]

    # Use a copy of the supplied "sent" list so we do not modify the original
    # data, but just a copy
    backup=[]
    for pkt in sent :
        if type(pkt)==list :
            backup2=[]
            for pkt2 in pkt :
                backup2.append(pkt2.copy())
            backup.append(backup2)
        else :
            backup.append(pkt.copy())
    sent=backup

    # Remove any layer 2 headers that are present in the packets
    for i in range(0, len(sent)) :
        if str(type(sent[i])).find("scapy.layers.l2.")!=-1 :
            sent[i]=sent[i].payload
    for response in received:
        # Remove layer 2 headers
        while(True) :
            if str(type(response)).find("scapy.layers.l2.")!=-1 :
                response=response.payload
            else :
                break
        # Only keep packets that are IPv4 or IPv6
        if type(response)==scapy.layers.inet6.IPv6 or type(response)==scapy.layers.inet.IP :
            aux.append(response)
    received=aux


    # Try to find a response for every packet in the sent set
    for sent_probe in sent :

        match=False

        # Select those packets that originate from the target and are destined to us
        if type(sent_probe)==scapy.layers.inet6.IPv6 :
            response_set=filter_ipv6_responses(received, src=sent_probe.src, dst=sent_probe.dst)
        elif type(sent_probe)==scapy.layers.inet.IP :
            response_set=filter_ipv4_responses(received, src=sent_probe.src, dst=sent_probe.dst)
        else :
            response_set=[]

        for i in range(0, len(response_set)) :

            # Transmission Control Protocol
            if TCP in sent_probe:
                if TCP in response_set[i] :
                    if sent_probe[TCP].dport == response_set[i][TCP].sport :
                        if sent_probe[TCP].sport == response_set[i][TCP].dport :
                            print_debug("TCP MATCH")
                            final_results.append( [sent_probe, response_set[i]] )
                            match=response_set[i]
                            break
            # User Datagram Protocol
            if UDP in sent_probe :
                if UDP in response_set[i] :
                    if sent_probe[UDP].dport == response_set[i][UDP].sport :
                        if sent_probe[UDP].sport == response_set[i][UDP].dport :
                            print_debug("UDP MATCH")
                            final_results.append( [sent_probe, response_set[i]] )
                            match=response_set[i]
                            break
            # ICMPv6 Echo Requests
            if ICMPv6EchoRequest in sent_probe :
                if ICMPv6EchoReply in response_set[i] :
                    if sent_probe[ICMPv6EchoRequest].id == response_set[i][ICMPv6EchoReply].id :
                        if sent_probe[ICMPv6EchoRequest].seq == response_set[i][ICMPv6EchoReply].seq :
                            print_debug("EchoRequest MATCH")
                            final_results.append( [sent_probe, response_set[i]] )
                            match=response_set[i]
                            break
            # ICMPv6 Home Agent Address Discovery Requests
            if ICMPv6HAADRequest in sent_probe :
                if ICMPv6HAADReply in response_set[i] :
                    if sent_probe[ICMPv6HAADRequest].id == response_set[i][ICMPv6HAADReply].id :
                        print_debug("ICMPv6HAADRequest MATCH")
                        final_results.append( [sent_probe, response_set[i]] )
                        match=response_set[i]
                        break
            # ICMPv6 Multicast Listener Discovery Queries
            if ICMPv6MLQuery in sent_probe :
                if ICMPv6MLReport in response_set[i] or ICMPv6MLDone in response_set[i]:
                    print_debug("MLD Query MATCH")
                    final_results.append( [sent_probe, response_set[i]] )
                    match=response_set[i]
                    break
            # ICMPv6 Mobile Prefix Solicitations
            if ICMPv6MPSol in sent_probe :
                if ICMPv6MPAdv in response_set[i] :
                    if sent_probe[ICMPv6MPSol].id == response_set[i][ICMPv6MPAdv].id :
                        print_debug("ICMPv6MPSol MATCH")
                        final_results.append( [sent_probe, response_set[i]] )
                        match=response_set[i]
                        break
            # ICMPv6 Multicast Router Discovery Solicitations
            if ICMPv6MRD_Solicitation in sent_probe :
                if ICMPv6MRD_Advertisement in response_set[i] or ICMPv6MRD_Termination in response_set[i]:
                    print_debug("ICMPv6MRD_Solicitation MATCH")
                    final_results.append( [sent_probe, response_set[i]] )
                    match=response_set[i]
                    break
            # ICMPv6 Inverse Neighbor Discovery Solicitations
            if ICMPv6ND_INDSol in sent_probe :
                if ICMPv6ND_INDAdv in response_set[i]:
                    print_debug("ICMPv6ND_INDSol MATCH")
                    final_results.append( [sent_probe, response_set[i]] )
                    match=response_set[i]
                    break
            # ICMPv6 Neighbor Discovery Solicitations
            if ICMPv6ND_NS in sent_probe :
                if ICMPv6ND_NA in response_set[i]:
                    print_debug("ICMPv6ND_NS MATCH")
                    final_results.append( [sent_probe, response_set[i]] )
                    match=response_set[i]
                    break
            # ICMPv6 Router Solicitations
            if ICMPv6ND_RS in sent_probe :
                if ICMPv6ND_RA in response_set[i]:
                    print_debug("ICMPv6ND_RS MATCH")
                    final_results.append( [sent_probe, response_set[i]] )
                    match=response_set[i]
                    break
            # ICMPv6 Node Information Queries
            if ICMPv6NIQueryIPv4 in sent_probe or ICMPv6NIQueryIPv6 in sent_probe \
                or ICMPv6NIQueryNOOP in sent_probe or ICMPv6NIQueryName in sent_probe:
                    # Store which of the tests was true so we can access the layer later
                    if ICMPv6NIQueryIPv4 in sent_probe :
                        mytype=ICMPv6NIQueryIPv4
                    elif ICMPv6NIQueryIPv6 in sent_probe :
                        mytype=ICMPv6NIQueryIPv6
                    elif ICMPv6NIQueryNOOP in sent_probe :
                        mytype=ICMPv6NIQueryNOOP
                    else :
                        mytype=ICMPv6NIQueryName

                    # Check if the response is some kind of Node Information reply
                    if ICMPv6NIReplyIPv4  in response_set[i] or ICMPv6NIReplyIPv6 in response_set[i] \
                        or ICMPv6NIReplyNOOP in response_set[i] or ICMPv6NIReplyName in response_set[i] \
                        or ICMPv6NIReplyRefuse in response_set[i] or ICMPv6NIReplyUnknown in response_set[i] :

                        # Store which of the tests was true so we can access the layer later
                        if ICMPv6NIReplyIPv4  in response_set[i] :
                            mytype2=ICMPv6NIReplyIPv4
                        elif ICMPv6NIReplyIPv6 in response_set[i] :
                            mytype2=ICMPv6NIReplyIPv6
                        elif ICMPv6NIReplyNOOP in response_set[i] :
                            mytype2=ICMPv6NIReplyNOOP
                        elif ICMPv6NIReplyName in response_set[i] :
                            mytype2=ICMPv6NIReplyName
                        elif ICMPv6NIReplyRefuse in response_set[i] :
                            mytype2=ICMPv6NIReplyRefuse
                        else :
                            mytype2=ICMPv6NIReplyUnknown

                        # Check that the nonces are equal
                        if sent_probe[mytype].nonce == response_set[i][mytype2].nonce :
                            print_debug("ICMPv6NIQuery MATCH")
                            final_results.append( [sent_probe, response_set[i]] )
                            match=response_set[i]
                            break
            # ICMPv4
            if ICMP in sent_probe :
                if ICMP in response_set[i] :

                    # Sent is EchoRequest, Recv is EchoReply
                    if sent_probe[ICMP].type==8 and response_set[i][ICMP].type==0:
                        if sent_probe[ICMP].id == response_set[i][ICMP].id :
                            if sent_probe[ICMP].seq == response_set[i][ICMP].seq :
                                print_debug("ICMPv4 EchoRequest MATCH")
                                final_results.append( [sent_probe, response_set[i]] )
                                match=response_set[i]
                                break
                    # Sent is TimestampRequest, Recv is TimestampReply
                    if sent_probe[ICMP].type==13 and response_set[i][ICMP].type==14:
                        if sent_probe[ICMP].id == response_set[i][ICMP].id :
                            if sent_probe[ICMP].seq == response_set[i][ICMP].seq :
                                print_debug("ICMPv4 TimestampRequest MATCH")
                                final_results.append( [sent_probe, response_set[i]] )
                                match=response_set[i]
                                break
                    # Sent is InformationRequest, Recv is InformationReply
                    if sent_probe[ICMP].type==15 and response_set[i][ICMP].type==16:
                        if sent_probe[ICMP].id == response_set[i][ICMP].id :
                            if sent_probe[ICMP].seq == response_set[i][ICMP].seq :
                                print_debug("ICMPv4 InformationRequest MATCH")
                                final_results.append( [sent_probe, response_set[i]] )
                                match=response_set[i]
                                break
                    # Sent is AddressMaskRequest, Recv is InformationReply
                    if sent_probe[ICMP].type==17 and response_set[i][ICMP].type==18:
                        if sent_probe[ICMP].id == response_set[i][ICMP].id :
                            if sent_probe[ICMP].seq == response_set[i][ICMP].seq :
                                print_debug("ICMPv4 MaskRequest MATCH")
                                final_results.append( [sent_probe, response_set[i]] )
                                match=response_set[i]
                                break
                    # Sent is DomainNameRequest, Recv is InformationReply
                    if sent_probe[ICMP].type==37 and response_set[i][ICMP].type==38:
                        if sent_probe[ICMP].id == response_set[i][ICMP].id :
                            if sent_probe[ICMP].seq == response_set[i][ICMP].seq :
                                print_debug("ICMPv4 DomainNameRequest MATCH")
                                final_results.append( [sent_probe, response_set[i]] )
                                match=response_set[i]
                                break

        # Check if we matched a packet, in that case, remove the response from the
        # list of captured packets so we don't match it again in future loop
        # iterations
        if (match!=False) :
            for j in range(0, len(received)) :
                if received[j]==match :
                    received.pop(j)
                    break;
            continue

        # If we get here (we have not "break"ed the loop), it means that we
        # did not find any standard response. Now check for ICMP errors.
        # We do a very soft matching. We can probably make mistakes here if
        # we send many packets and we get many different responses, but this
        # is not a common case in ipv6fp.py, so we should be fine.
        for i in range(0, len(response_set)) :

            # ICMPv6 Parameter Problem
            if ICMPv6ParamProblem in response_set[i] :
                if IPerror6 in response_set[i] :
                    if response_set[i][IPerror6].src==sent_probe.src:
                        if response_set[i][IPerror6].dst==sent_probe.dst:
                            if response_set[i][IPerror6].nh==sent_probe.nh:
                                print_debug("ParameterProblem MATCH")
                                final_results.append( [sent_probe, response_set[i]] )
                                match=response_set[i]
                                break
            # ICMPv6 Destination Unreachable
            if ICMPv6DestUnreach in response_set[i] :
                if IPerror6 in response_set[i] :
                    if response_set[i][IPerror6].src==sent_probe.src:
                        if response_set[i][IPerror6].dst==sent_probe.dst:
                            if response_set[i][IPerror6].nh==sent_probe.nh:
                                print_debug("DestUnreach MATCH")
                                final_results.append( [sent_probe, response_set[i]] )
                                match=response_set[i]
                                break
            # ICMPv6 Time Exceeded
            if ICMPv6TimeExceeded in response_set[i] :
                if IPerror6 in response_set[i] :
                    if response_set[i][IPerror6].src==sent_probe.src:
                        if response_set[i][IPerror6].dst==sent_probe.dst:
                            if response_set[i][IPerror6].nh==sent_probe.nh:
                                print_debug("TimeExceeded MATCH")
                                final_results.append( [sent_probe, response_set[i]] )
                                match=response_set[i]
                                break
            # ICMPv6 Packet Too Big
            if ICMPv6PacketTooBig in response_set[i] :
                if IPerror6 in response_set[i] :
                    if response_set[i][IPerror6].src==sent_probe.src:
                        if response_set[i][IPerror6].dst==sent_probe.dst:
                            if response_set[i][IPerror6].nh==sent_probe.nh:
                                print_debug("PacketTooBig MATCH")
                                final_results.append( [sent_probe, response_set[i]] )
                                match=response_set[i]
                                break
            # ICMPv4
            if ICMP in response_set[i] :
                # If we get here it means that the response is an ICMP error
                # message. If it contains the original IP datagram, do the match
                # using the datagram's source and destination address
                if IPerror in response_set[i] :
                    if response_set[i][IPerror].src==sent_probe.src:
                        if response_set[i][IPerror].dst==sent_probe.dst:
                            if response_set[i][IPerror].proto==sent_probe.proto:
                                print_debug("ICMP Error MATCH")
                                final_results.append( [sent_probe, response_set[i]] )
                                match=response_set[i]
                                break
                # If it does not contain the original datagram, store it anyway,
                # providing we have a true error message.
                elif response_set[i][ICMP].type==3 or response_set[i][ICMP].type==4 \
                 or response_set[i][ICMP].type==5 or response_set[i][ICMP].type==11 \
                 or response_set[i][ICMP].type==12 or response_set[i][ICMP].type==40:
                    print_debug("Possible ICMP Error MATCH")
                    final_results.append( [sent_probe, response_set[i]] )
                    match=response_set[i]
                    break
            # ICMPv6 Redirects
            if ICMPv6ND_Redirect in response_set[i] :
                print_debug("Redirect MATCH")
                final_results.append( [sent_probe, response_set[i]] )
                match=response_set[i]
                break
            # Unknown ICMPv6 message types
            if ICMPv6Unknown in response_set[i] :
                print_debug("Unknown ICMP type MATCH")
                final_results.append( [sent_probe, response_set[i]] )
                match=response_set[i]
                break
            # Fragmented datagrams that contain ICMP messages (first fragment)
            if IPv6 in response_set[i] :
                if IPv6ExtHdrFragment in response_set[i] :
                    if ICMPv6EchoReply in response_set[i] :
                        print_debug("Some ICMP type MATCH (from frag packet #0)")
                        final_results.append( [sent_probe, response_set[i]] )
                        match=response_set[i]
                        break
            # Fragmented datagrams that contain ICMP messages (other fragments)
            if Raw in response_set[i]:
                if IPv6 in response_set[i] :
                    if IPv6ExtHdrFragment in response_set[i] :
                        if response_set[i][IPv6ExtHdrFragment].nh==58 :
                            print_debug("Some ICMP type MATCH (from frag packet #n)")
                            final_results.append( [sent_probe, response_set[i]] )
                            match=response_set[i]
                            break
            # Print debug info
            else :
                hdr=sent_probe
                print_debug("SENT:")
                while True :
                    print_debug(str(type(hdr)))
                    hdr=hdr.payload
                    if type(hdr)==scapy.packet.NoPayload :
                        break
                hdr=response_set[i]
                print_debug("CAPT:")
                while True :
                    print_debug(str(type(hdr)))
                    hdr=hdr.payload
                    if type(hdr)==scapy.packet.NoPayload :
                        break

        # Check if we matched a packet, in that case, remove the response from the
        # list of captured packets so we don't match it again in future loop
        # iterations
        if (match!=False) :
            for j in range(0, len(received)) :
                if received[j]==match :
                    received.pop(j)
                    break;
                    
    return final_results

def sndrcv_ng(pkt, timeout=1, iface=None, inter = 0, verbose=1, retry=0, multi=0) :
    print_debug("sndrcv_ng()")
    cap_pkts=[] # Responses are stored here

    if pkt==None or timeout <=0:
        return None

    # If we only have one packet to send, turn it into a list
    if type(pkt)!=list :
        pkt=[pkt]

    # Determine if we need to send at the ethernet level or not
    if type(pkt[0])==scapy.layers.l2.Ether :
        send_ether=True
    else :
        send_ether=False

    # Send and receive loop
    while retry >= 0:
        retry=retry-1

        # For into two processes, one for transmission, one for reception
        pid=1
        pid = os.fork()

        # Packet transmission child
        if pid == 0:
            print_debug("Transmission Child")
            sys.stdin.close()
            if send_ether==True :
                sendp(pkt, inter=inter, iface=iface, verbose=verbose)
            else :
                send(pkt, inter=inter, verbose=verbose)

        elif pid < 0:
            print "ERROR: unable to fork()"

        # Packet reception child
        else:
            print_debug("Reception Child")
            cap_pkts=sniff(timeout=timeout)
            print_debug("Captured " +str(len(cap_pkts)) + " packets")

            cap_pkts=filter_responses(pkt, cap_pkts)

            # If we received a response, avoid looping again
            if cap_pkts!=None and len(cap_pkts)>0 :
                retry=-1

            os.waitpid(pid,0)

        if pid == 0:
             os._exit(0)

    return cap_pkts


def send_and_receive(packet, verbosity=1):
    # Send packet and get response
    responses=sndrcv_ng(packet, iface=interface_g, retry=packet_retries_g, timeout=capture_timeout_g, multi=0, verbose=verbosity, inter=inter_packet_delay_g)

    if responses==None or len(responses)==0 :
        return []

    # If we got responses, strip the link layer before returning them
    for i in range(0, len(responses)) :
        responses[i][0]=strip_link_layer(responses[i][0])
        responses[i][1]=strip_link_layer(responses[i][1])

    return responses

def send_and_receive_multiple(packet, verbosity=1):
    # Send a list of packets and get the responses
    responses=sr(packet, retry=packet_retries_g, timeout=capture_timeout_g, multi=1, verbose=verbosity, inter=inter_packet_delay_g);
    return responses


def strip_link_layer(packet):
    while(True) :
        if str(type(packet)).find("scapy.layers.l2.")!=-1 :
            packet=packet.payload
        else :
            break
    return packet

def send_and_receive_eth(packet, verbosity=1):
    # Send packet(s) and get response(s)

    # Add an ethernet header to the packet(s)
    eth_hdr=Ether(dst=target_mac_addr_g)
    if type(packet)==list : # Test contains more than one packet
          for i in range(0, len(packet)) :
            packet[i]=eth_hdr/packet[i]
    else :
        packet=eth_hdr/packet

    responses=send_and_receive(packet, verbosity=verbosity)

    return responses

# Note that this function does NOT strip the ethernet header of the returned (answered, unanswered) set.
def send_and_receive_eth_multiple(packet, verbosity=1):
    # Send packet and get response

    # Add an ethernet header to the packet(s)
    eth_hdr=Ether(dst=target_mac_addr_g)
    if type(packet)==list : # Test contains more than one packet
          for i in range(0, len(packet)) :
            packet[i]=eth_hdr/packet[i]
    else :
        packet=eth_hdr/packet

    responses=srp(packet, iface=interface_g, retry=packet_retries_g, timeout=capture_timeout_g, multi=1, verbose=verbosity, inter=inter_packet_delay_g);
    return responses

#############################
# TEST MANAGEMENT FUNCTIONS #
#############################

# Runs the specified test. It returns a packet if a response was received and
# 'None' otherwise.
def run_test(test_number, test_id, test_description, test_packet, ip_version):
    # Print test details
    print_start_separator()
    print_test_number(test_number)
    print_test_id(test_id, ip_version)
    print_time_elapsed()
    print_test_description(test_description)
    print_parseable_sent_packet(test_number, test_packet, ip_version)
    print_sent_packet(test_packet)

    # Special case: localhost needs some adjustments
    if ip_version==4 and send_eth_g==False and (target_host4_g=='127.0.0.1' or target_host4_g=='localhost') :
        tmp=conf.L3socket
        conf.L3socket = L3RawSocket

    # Send the packet and listen for responses
    if send_eth_g == True:
        responses=send_and_receive_eth(test_packet)
    else:
        responses=send_and_receive(test_packet)

    # Restore original L3 socket
    if ip_version==4 and send_eth_g==False and (target_host4_g=='127.0.0.1' or target_host4_g=='localhost') :
        conf.L3socket=tmp

    # Check if we got a response. Print it if that's the case.
    received=[]
    if(len(responses)>0 ):
        print "[+] Response received:"
        for i in range(0, len(responses)) :
            print_received_packet(responses[i][1])
            received.append(responses[i][1])
    else :
        received=None
        print "[+] No response received:"

    print_parseable_test_result(test_number, received, ip_version)

    # Cleanup and return
    print_end_separator()
    return received

# Runs the specified test. It returns a packet if a response was received and
# 'None' otherwise.
def run_test_multiple(test_number_base, test_id, test_description, test_packet, ip_version):
    # Print test details
    print_start_separator()
    print_test_number(test_number_base)
    print_test_id(test_id, ip_version)
    print_test_description(test_description)
    myresponses=[]

    # Special case: localhost needs some adjustments
    if ip_version==4 and send_eth_g==False and (target_host4_g=='127.0.0.1' or target_host4_g=='localhost') :
        tmp=conf.L3socket
        conf.L3socket = L3RawSocket

    # Send the packet and listen for responses
    if send_eth_g == True:
        responses=send_and_receive_eth_multiple(test_packet)
    else:
        responses=send_and_receive_multiple(test_packet)

    # Restore original L3 socket
    if ip_version==4 and send_eth_g==False and (target_host4_g=='127.0.0.1' or target_host4_g=='localhost') :
        conf.L3socket=tmp

    # Print packets that did not get any response
    for i in range(0, len(responses[1])) :
        print_sent_packet(responses[1][i])
        print "[+] No response received:"

    # Print packets that did get responses
    for i in range(0, len(responses[0])) :
        if type(responses[0][i][0])==scapy.layers.l2.Ether :
            print_sent_packet(responses[0][i][0].payload)
        else :
            print_sent_packet(responses[0][i][0])
        print "[+] Response received:"

        if type(responses[0][i][1])==scapy.layers.l2.Ether :
            print_received_packet(responses[0][i][1].payload)
            myresponses.append(responses[0][i][1].payload)
            print_parseable_time_dependent_test_result(test_number_base+i, responses[0][i][1].payload, ip_version)
        else:
            print_received_packet(responses[0][i][1])
            myresponses.append(responses[0][i][1])
            print_parseable_time_dependent_test_result(test_number_base+i, responses[0][i][1], ip_version)

    # Cleanup and return
    print_end_separator()

    # Check if we got a response. Print it if that's the case.
    if len(myresponses)>0 :
       return myresponses
    else :
        return None


################
# TEST BATTERY #
################
#
# Acknowledgments: Some of the following tests have been inspired by the
# great "THC-IPv6" toolkit (v1.6) written by Van Hauser from the THC group,
# (mainly from the "implementation6" tool). {http://www.thc.org/thc-ipv6/}
#

def set_up_ipv6_tests(target):

    ####################################
    # CURRENT NMAP OS DETECTION PROBES #
    ####################################

    # TEST 0
    test6_ids.append("NMAP_OS_PROBE_TCP_0")
    test6_descriptions.append("TCP/SYN/OpenPort/NmapProbe0")
    ip_packet=build_default_ipv6(target)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase+0
    tcp_packet.ack=tcpAck
    tcp_packet.flags='S'
    tcp_packet.options=[('WScale', 10), ('NOP', None), ('MSS',1460), ('Timestamp', (0xFFFFFFFF,0L)), ('SAckOK', '')]
    tcp_packet.window=1
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 1
    test6_ids.append("NMAP_OS_PROBE_TCP_1")
    test6_descriptions.append("TCP/SYN/OpenPort/NmapProbe1")
    ip_packet=build_default_ipv6(target)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase+1
    tcp_packet.ack=tcpAck
    tcp_packet.flags='S'
    tcp_packet.options=[('MSS', 1400), ('WScale', 0), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF,0L)), ('EOL', '')]
    tcp_packet.window=63
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 2
    test6_ids.append("NMAP_OS_PROBE_TCP_2")
    test6_descriptions.append("TCP/SYN/OpenPort/NmapProbe2")
    ip_packet=build_default_ipv6(target)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase+2
    tcp_packet.ack=tcpAck
    tcp_packet.flags='S'
    tcp_packet.options=[('Timestamp', (0xFFFFFFFF,0L)), ('NOP', ''), ('NOP', ''), ('WScale', 5), ('NOP', ''), ('MSS', 640)]
    tcp_packet.window=4
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 3
    test6_ids.append("NMAP_OS_PROBE_TCP_3")
    test6_descriptions.append("TCP/SYN/OpenPort/NmapProbe3")
    ip_packet=build_default_ipv6(target)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase+3
    tcp_packet.ack=tcpAck
    tcp_packet.flags='S'
    tcp_packet.options=[('SAckOK', ''), ('Timestamp', (0xFFFFFFFF,0L)), ('WScale', 10),  ('EOL', '')]
    tcp_packet.window=4
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 4
    test6_ids.append("NMAP_OS_PROBE_TCP_4")
    test6_descriptions.append("TCP/SYN/OpenPort/NmapProbe4")
    ip_packet=build_default_ipv6(target)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase+4
    tcp_packet.ack=tcpAck
    tcp_packet.flags='S'
    tcp_packet.options=[('MSS', 536), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF,0L)), ('WScale', 10), ('EOL', '')]
    tcp_packet.window=16
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 5
    test6_ids.append("NMAP_OS_PROBE_TCP_5")
    test6_descriptions.append("TCP/SYN/OpenPort/NmapProbe5")
    ip_packet=build_default_ipv6(target)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase+5
    tcp_packet.ack=tcpAck
    tcp_packet.flags='S'
    tcp_packet.options=[('MSS', 265), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF,0L))]
    tcp_packet.window=512
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 6 ECN
    test6_ids.append("NMAP_OS_PROBE_TCP_6")
    test6_descriptions.append("TCP/CWR|ECN|SYN/OpenPort/NmapProbe6")
    ip_packet=build_default_ipv6(target)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase
    tcp_packet.ack=0
    tcp_packet.urgptr=0xF7F5
    tcp_packet.flags='CES'
    tcp_packet.options=[('WScale', 10), ('NOP', ''), ('MSS', 1460), ('SAckOK', ''), ('NOP', ''), ('NOP', '')]
    tcp_packet.window=3
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 7 (T2)
    test6_ids.append("NMAP_OS_PROBE_TCP_7")
    test6_descriptions.append("TCP/NullFlags/OpenPort/NmapProbe7")
    ip_packet=build_default_ipv6(target)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase
    tcp_packet.ack=tcpAck
    tcp_packet.urgptr=0
    tcp_packet.flags=''
    tcp_packet.options=[('WScale', 10), ('NOP', ''), ('MSS', 265), ('Timestamp', (0xFFFFFFFF,0L)), ('SAckOK', '')]
    tcp_packet.window=128
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 8 (T3)
    test6_ids.append("NMAP_OS_PROBE_TCP_8")
    test6_descriptions.append("TCP/SYN|FIN|URG|PSH/OpenPort/NmapProbe8")
    ip_packet=build_default_ipv6(target)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase
    tcp_packet.ack=tcpAck
    tcp_packet.urgptr=0
    tcp_packet.flags='SFUP'
    tcp_packet.options=[('WScale', 10), ('NOP', ''), ('MSS', 265), ('Timestamp', (0xFFFFFFFF,0L)), ('SAckOK', '')]
    tcp_packet.window=256
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 9 (T4)
    test6_ids.append("NMAP_OS_PROBE_TCP_9")
    test6_descriptions.append("TCP/ACK/OpenPort/NmapProbe9")
    ip_packet=build_default_ipv6(target)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase
    tcp_packet.ack=tcpAck
    tcp_packet.urgptr=0
    tcp_packet.flags='A'
    tcp_packet.options=[('WScale', 10), ('NOP', ''), ('MSS', 265), ('Timestamp', (0xFFFFFFFF,0L)), ('SAckOK', '')]
    tcp_packet.window=1024
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 10 (T5)
    test6_ids.append("NMAP_OS_PROBE_TCP_10")
    test6_descriptions.append("TCP/SYN/ClosedPort/NmapProbe10")
    ip_packet=build_default_ipv6(target)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=closed_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase
    tcp_packet.ack=tcpAck
    tcp_packet.urgptr=0
    tcp_packet.flags='S'
    tcp_packet.options=[('WScale', 10), ('NOP', ''), ('MSS', 265), ('Timestamp', (0xFFFFFFFF,0L)), ('SAckOK', '')]
    tcp_packet.window=31337
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 11 (T6)
    test6_ids.append("NMAP_OS_PROBE_TCP_11")
    test6_descriptions.append("TCP/ACK/ClosedPort/NmapProbe11")
    ip_packet=build_default_ipv6(target)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=closed_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase
    tcp_packet.ack=tcpAck
    tcp_packet.urgptr=0
    tcp_packet.flags='A'
    tcp_packet.options=[('WScale', 10), ('NOP', ''), ('MSS', 265), ('Timestamp', (0xFFFFFFFF,0L)), ('SAckOK', '')]
    tcp_packet.window=32768
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 12 (T7)
    test6_ids.append("NMAP_OS_PROBE_TCP_12")
    test6_descriptions.append("TCP/FIN|PSH|URG/ClosedPort/NmapProbe12")
    ip_packet=build_default_ipv6(target)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=closed_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase
    tcp_packet.ack=tcpAck
    tcp_packet.urgptr=0
    tcp_packet.flags='FPU'
    tcp_packet.options=[('WScale', 15), ('NOP', ''), ('MSS', 265), ('Timestamp', (0xFFFFFFFF,0L)), ('SAckOK', '')]
    tcp_packet.window=65535
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 13 (IE 1)
    test6_ids.append("NMAP_OS_PROBE_ICMP_1")
    test6_descriptions.append("ICMP/EchoRequest/TClass=0/NmapProbe13")
    ip_packet=build_default_ipv6(target)
    ip_packet.tclass=0
    icmp_packet=build_default_icmpv6()
    icmp_packet.code=9
    icmp_packet.seq=295
    icmp_packet.id=0xABCD
    icmp_packet.data='\x00'*120
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 14 (IE 2)
    test6_ids.append("NMAP_OS_PROBE_ICMP_2")
    test6_descriptions.append("ICMP/EchoRequest/TClass=4/NmapProbe14")
    ip_packet=build_default_ipv6(target)
    ip_packet.tclass=4
    icmp_packet=build_default_icmpv6()
    icmp_packet.code=9
    icmp_packet.seq=295+1
    icmp_packet.id=0xABCD+1
    icmp_packet.data='\x00'*150
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 15 (U1)
    test6_ids.append("NMAP_OS_PROBE_UDP")
    test6_descriptions.append("ICMP/EchoRequest/TClass=4/NmapProbe14")
    ip_packet=build_default_ipv6(target)
    udp_packet=build_default_udp()
    udp_packet.dport=closed_port_g
    udp_packet.sport=45535
    payload='\x43'*300
    final_packet=ip_packet/udp_packet/payload
    test6_packets.append(final_packet)

    #########################
    # ICMPv6-ORIENTED TESTS #
    #########################

    # TEST 16
    test6_ids.append("ICMPEcho_0")
    test6_descriptions.append("ICMP/EchoReq/PL=0")
    ip_packet=build_default_ipv6(target)
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 17
    test6_ids.append("ICMPEcho_1")
    test6_descriptions.append("ICMP/EchoReq/PL=32")
    ip_packet=build_default_ipv6(target)
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data=ASCII_PAYLOAD_32
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 18
    test6_ids.append("ICMPEcho_2")
    test6_descriptions.append("ICMP/EchoReq/PL=1280-40-8=1232")
    ip_packet=build_default_ipv6(target)
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="A"*1232
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 19
    test6_ids.append("ICMPEcho_3")
    test6_descriptions.append("ICMP/EchoReq/PL=1280-40-8+1=1233")
    ip_packet=build_default_ipv6(target)
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="B"*1233
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 20
    test6_ids.append("ICMPEcho_4")
    test6_descriptions.append("ICMP/EchoReq/PL=32/BadSum")
    ip_packet=build_default_ipv6(target)
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data=ASCII_PAYLOAD_32
    icmp_packet.cksum=0xABCD
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 21
    test6_ids.append("ICMPNSol_0")
    test6_descriptions.append("ICMP/NSol/Dst=target/Addr=target")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_NS()
    icmp_packet.code=0
    icmp_packet.tgt=target;
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 22
    test6_ids.append("ICMPNSol_1")
    test6_descriptions.append("ICMP/NSol/Dst=target/Addr=target/ICMPCode=0x01")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_NS()
    icmp_packet.code=0x01
    icmp_packet.tgt=target;
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 23
    test6_ids.append("ICMPNSol_2")
    test6_descriptions.append("ICMP/NSol/Dst=target/Addr=target/ICMPCode=0xAB")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_NS()
    icmp_packet.code=0xAB
    icmp_packet.tgt=target;
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 24
    test6_ids.append("ICMPNSol_3")
    test6_descriptions.append("ICMP/NSol/Dst=target/Addr=::0")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_NS()
    icmp_packet.code=0
    icmp_packet.tgt="::0"
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 25
    test6_ids.append("ICMPNSol_4")
    test6_descriptions.append("ICMP/NSol/Dst=target/Addr=::0/ICMPCode=0xCD")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_NS()
    icmp_packet.code=0xCD
    icmp_packet.tgt="::0"
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 26
    test6_ids.append("ICMPNSol_5")
    test6_descriptions.append("ICMP/NSol/Dst=target/Addr=target/ICMPv6 Opts (LLAddr=0)")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_NS()
    icmp_packet.code=0
    icmp_packet.tgt=target
    icmp_options=ICMPv6NDOptSrcLLAddr()
    icmp_options.lladdr='00:00:00:00:00:00'
    final_packet=ip_packet/icmp_packet/icmp_options
    test6_packets.append(final_packet)

    # TEST 27
    test6_ids.append("ICMPNSol_6")
    test6_descriptions.append("ICMP/NSol/Dst=target/Addr=target/ICMPv6 Opts (LLAddr='AA:BB:CC:DD:EE:FF')")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_NS()
    icmp_packet.code=0
    icmp_packet.tgt=target
    icmp_options=ICMPv6NDOptSrcLLAddr()
    icmp_options.lladdr='AA:BB:CC:DD:EE:FF'
    final_packet=ip_packet/icmp_packet/icmp_options
    test6_packets.append(final_packet)

    # TEST 28
    test6_ids.append("ICMPNSol_7")
    test6_descriptions.append("ICMP/NSol/Dst=target/Addr=target/Bogus ICMPv6 Opt for NSol (mtu=1280)")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_NS()
    icmp_packet.code=0
    icmp_packet.tgt=target
    icmp_options=ICMPv6NDOptMTU()
    icmp_options.mtu=1280
    final_packet=ip_packet/icmp_packet/icmp_options
    test6_packets.append(final_packet)

    # TEST 29
    test6_ids.append("ICMPNSol_8")
    test6_descriptions.append("ICMP/NSol/Dst=target/Addr=target/Bogus ICMPv6 Opt for NSol (mtu=0)")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_NS()
    icmp_packet.code=0
    icmp_packet.tgt=target
    icmp_options=ICMPv6NDOptMTU()
    icmp_options.mtu=0
    final_packet=ip_packet/icmp_packet/icmp_options
    test6_packets.append(final_packet)

    # TEST 30
    test6_ids.append("ICMPNSol_9")
    test6_descriptions.append("ICMP/NSol/Dst=target/Addr=target/ICMPv6NDOptSrcLLAddr(addr=1a:2b:3c:4d:5e:6f) + ICMPv6NDOptMTU(mtu=1450)")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_NS()
    icmp_packet.code=0xCD
    icmp_packet.tgt=target
    icmp_option_1=ICMPv6NDOptSrcLLAddr()
    icmp_option_1.lladdr='1A:2B:3C:4D:5E:6F'
    icmp_option_2=ICMPv6NDOptMTU()
    icmp_option_2.mtu=1450
    icmp_options=icmp_option_1/icmp_option_2
    final_packet=ip_packet/icmp_packet/icmp_options
    test6_packets.append(final_packet)

    # TEST 31
    test6_ids.append("ICMPHAADReq_0")
    test6_descriptions.append("ICMP/HAAD Request/Dst=target/Code=Id=Res=0")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6HAADRequest()
    icmp_packet.code=0
    icmp_packet.id=0
    icmp_packet.res=0
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 32
    test6_ids.append("ICMPHAADReq_1")
    test6_descriptions.append("ICMP/HAAD Request/Dst=target/Code=0xFA/Id=Res=0")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6HAADRequest()
    icmp_packet.code=0xFA
    icmp_packet.id=0
    icmp_packet.res=0
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 33
    test6_ids.append("ICMPHAADReq_2")
    test6_descriptions.append("ICMP/HAAD Request/Dst=target/Code=0/Id=0xABCD/Res=0x1234")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6HAADRequest()
    icmp_packet.code=0
    icmp_packet.id=0xABCD
    icmp_packet.res=0x1234
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 34
    test6_ids.append("ICMPRSol_0")
    test6_descriptions.append("ICMP/RSol/Dst=target/ICMPCode=0x00/Reserved=0")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_RS()
    icmp_packet.code=0
    icmp_packet.res=0
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 35
    test6_ids.append("ICMPRSol_1")
    test6_descriptions.append("ICMP/RSol/Dst=target/ICMPCode=0xAA/Reserved=0")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_RS()
    icmp_packet.code=0xAA
    icmp_packet.res=0
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 36
    test6_ids.append("ICMPRSol_2")
    test6_descriptions.append("ICMP/RSol/Dst=target/ICMPCode=0x00/Reserved=0xAB0000CD")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_RS()
    icmp_packet.code=0
    icmp_packet.res=0xAB0000CD
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 37
    test6_ids.append("ICMPRSol_3")
    test6_descriptions.append("ICMP/RSol/Dst=target/ICMPCode=0x01/Reserved=0x00000001")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_RS()
    icmp_packet.code=0x01
    icmp_packet.res=0x00000001
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 38
    test6_ids.append("ICMPRSol_4")
    test6_descriptions.append("ICMP/RSol/Dst=target/ICMP_Option:LLAddr=0")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_RS()
    icmp_packet.code=0
    icmp_packet.res=0
    icmp_options=ICMPv6NDOptSrcLLAddr()
    icmp_options.lladdr='00:00:00:00:00:00'
    final_packet=ip_packet/icmp_packet/icmp_options
    test6_packets.append(final_packet)

    # TEST 39
    test6_ids.append("ICMPRSol_5")
    test6_descriptions.append("ICMP/RSol/Dst=target/ICMP_Option:LLAddr=00:11:22:33:44:55")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_RS()
    icmp_packet.code=0
    icmp_packet.res=0
    icmp_options=ICMPv6NDOptSrcLLAddr()
    icmp_options.lladdr='00:11:22:33:44:55'
    final_packet=ip_packet/icmp_packet/icmp_options
    test6_packets.append(final_packet)

    # TEST 40
    test6_ids.append("ICMPRSol_6")
    test6_descriptions.append("ICMP/RSol/Dst=target/Invalid ICMP_Option for RSol (mtu=1280")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_RS()
    icmp_packet.code=0
    icmp_packet.res=0
    icmp_options=ICMPv6NDOptMTU()
    icmp_options.mtu=1280
    final_packet=ip_packet/icmp_packet/icmp_options
    test6_packets.append(final_packet)

    # TEST 41
    test6_ids.append("ICMPRSol_7")
    test6_descriptions.append("ICMP/RSol/Dst=target/Invalid ICMP_Option for RSol (mtu=0)")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_RS()
    icmp_packet.code=0
    icmp_packet.res=0
    icmp_options=ICMPv6NDOptMTU()
    icmp_options.mtu=0
    final_packet=ip_packet/icmp_packet/icmp_options
    test6_packets.append(final_packet)

    # TEST 42
    test6_ids.append("ICMP_NI_Query_0")
    test6_descriptions.append("ICMP/NI Query NOOP/Dst=target/ICMP Code=1, Payload='.' (root) in DNS format")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryNOOP()
    icmp_packet.code=1  # RFC: On transmission, the ICMPv6 Code in a NOOP Query must be set to 1
    icmp_packet.qtype=0 # Qtype=NOOP
    icmp_packet.flags=0
    icmp_packet.nonce='\x01\x02\x03\x04\x05\x06\x07\x08'
    icmp_packet.unused=0
    icmp_packet.data='\x00'
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 43
    test6_ids.append("ICMP_NI_Query_1")
    test6_descriptions.append("ICMP/NI Query NOOP/Dst=target/ICMP Code=1, Payload=localhost (in DNS format)")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryNOOP()
    icmp_packet.code=1  # RFC: On transmission, the ICMPv6 Code in a NOOP Query must be set to 1
    icmp_packet.qtype=0 # Qtype=NOOP
    icmp_packet.flags=0
    icmp_packet.nonce='x02\x03\x04\x05\x06\x07\x08\x09'
    icmp_packet.unused=0
    icmp_packet.data="\x09localhost\x00"
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 44
    test6_ids.append("ICMP_NI_Query_2")
    test6_descriptions.append("ICMP/NI Query NOOP/Dst=target/ICMP Code=1, Payload=Bogus DNS formatted name (label length>63)")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryNOOP()
    icmp_packet.code=1  # RFC: On transmission, the ICMPv6 Code in a NOOP Query must be set to 1
    icmp_packet.qtype=0 # Qtype=NOOP
    icmp_packet.flags=0
    icmp_packet.nonce='\x03\x04\x05\x06\x07\x08\x09\x0A'
    icmp_packet.unused=0
    icmp_packet.data="\x40"+"0123456789012345678901234567890123456789012345678901234567890123"+"\x00"
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 45
    test6_ids.append("ICMP_NI_Query_3")
    test6_descriptions.append("ICMP/NI Query NOOP/Dst=target/ICMP Code=1, Payload=Bogus DNS formatted name (Characters missing)")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryNOOP()
    icmp_packet.code=1  # RFC: On transmission, the ICMPv6 Code in a NOOP Query must be set to 1
    icmp_packet.qtype=0 # Qtype=NOOP
    icmp_packet.flags=0
    icmp_packet.nonce='\x04\x05\x06\x07\x08\x09\x0A\x0B'
    icmp_packet.unused=0
    icmp_packet.data="\x3F"+"01234567890"+"\x00" # Wireshark reports "Malformed ICMPv6"
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 46
    test6_ids.append("ICMP_NI_Query_4")
    test6_descriptions.append("ICMP/NI Query NOOP/Dst=target/ICMP Code=0, Subject Addr=::0")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryNOOP()
    icmp_packet.code=0  # This is forbidden by RFC 4620
    icmp_packet.qtype=0 # Qtype=NOOP
    icmp_packet.flags=0
    icmp_packet.nonce='\x05\x06\x07\x08\x09\x0A\x0B\x0C'
    icmp_packet.unused=0
    icmp_packet.data='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 47
    test6_ids.append("ICMP_NI_Query_5")
    test6_descriptions.append("ICMP/NI Query NOOP/Dst=target/ICMP Code=0, Subject Addr=target's")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryNOOP()
    icmp_packet.code=0  # IPv6 Address. Using this in NOOP is forbidden by RFC 4620
    icmp_packet.qtype=0 # Qtype=NOOP
    icmp_packet.flags=0
    icmp_packet.nonce='\x06\x07\x08\x09\x0A\x0B\x0C\x0D'
    icmp_packet.unused=0
    icmp_packet.data=target
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 48
    test6_ids.append("ICMP_NI_Query_6")
    test6_descriptions.append("ICMP/NI Query NOOP/Dst=target/ICMP Code=0xAB (unknown), Payload=0x00")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryNOOP()
    icmp_packet.code=0xAB  # This one is also forbidden by RFC 4620
    icmp_packet.qtype=0 # Qtype=NOOP
    icmp_packet.flags=0
    icmp_packet.nonce='\x07\x08\x09\x0A\x0B\x0C\x0D\x0E'
    icmp_packet.unused=0
    icmp_packet.data='\x00'
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 49
    test6_ids.append("ICMP_NI_Query_7")
    test6_descriptions.append("ICMP/NI Query Unused/Dst=target/ICMP Code=1, Payload=localhost")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryNOOP()
    icmp_packet.code=1  # DNS name
    icmp_packet.qtype=1 # Qtype=Unused
    icmp_packet.flags=0
    icmp_packet.nonce='\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
    icmp_packet.unused=0
    icmp_packet.data="\x09localhost\x00"
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 50
    test6_ids.append("ICMP_NI_Query_8")
    test6_descriptions.append("ICMP/NI Query Unused/Dst=target/ICMP Code=0, Payload=target's addr")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryNOOP()
    icmp_packet.code=0  # IPv6 Address
    icmp_packet.qtype=1 # Qtype=Unused
    icmp_packet.flags=0
    icmp_packet.nonce='\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00'
    icmp_packet.unused=0
    icmp_packet.data=target
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 51
    test6_ids.append("ICMP_NI_Query_9")
    test6_descriptions.append("ICMP/NI Query Node Name/Dst=target/ICMP Code=1, Name=localhost")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryName()
    icmp_packet.code=1  # DNS Name
    icmp_packet.qtype=2 # Qtype=Query Name
    icmp_packet.flags=0
    icmp_packet.nonce='\x0A\x0B\x0C\x0D\x0E\x0F\x00\x01'
    icmp_packet.unused=0
    icmp_packet.data="\x09localhost\x00"
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 52
    test6_ids.append("ICMP_NI_Query_10")
    test6_descriptions.append("ICMP/NI Query Node Name/Dst=target/ICMP Code=0, Addr=target's")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryName()
    icmp_packet.code=0  # IPv6 Addr
    icmp_packet.qtype=2 # Qtype=Query Name
    icmp_packet.flags=0
    icmp_packet.nonce='\x0C\x0D\x0E\x0F\x00\x01\x02\x03'
    icmp_packet.unused=0
    icmp_packet.data=target
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 53
    test6_ids.append("ICMP_NI_Query_11")
    test6_descriptions.append("ICMP/NI Query Node Addresses IPv6/Dst=target/ICMP Code=0, Addr=target's, Flags=All addresses")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryIPv6()
    icmp_packet.code=0  # IPv6 Addr
    icmp_packet.qtype=3 # Qtype=Node Addresses (IPv6)
    icmp_packet.flags='ACLSG'
    icmp_packet.nonce='\x0D\x0E\x0F\x00\x01\x02\x03\x04'
    icmp_packet.unused=0
    icmp_packet.data=target
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 54
    test6_ids.append("ICMP_NI_Query_12")
    test6_descriptions.append("ICMP/NI Query Node Addresses IPv6/Dst=target/ICMP Code=0, Addr=target's, Flags=None")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryIPv6()
    icmp_packet.code=0  # IPv6 Addr
    icmp_packet.qtype=3 # Qtype=Node Addresses (IPv6)
    icmp_packet.flags=0
    icmp_packet.nonce='\x0E\x0F\x00\x01\x02\x03\x04\x05'
    icmp_packet.unused=0
    icmp_packet.data=target
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 55
    test6_ids.append("ICMP_NI_Query_13")
    test6_descriptions.append("ICMP/NI Query Node Addresses IPv6/Dst=target/ICMP Code=0, Name=localhost, Flags=All")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryIPv6()
    icmp_packet.code=1  # DNS Name
    icmp_packet.qtype=3 # Qtype=Node Addresses (IPv6)
    icmp_packet.flags='ACLSG'
    icmp_packet.nonce='\x0F\x00\x01\x02\x03\x04\x05\x06'
    icmp_packet.unused=0
    icmp_packet.data="\x09localhost\x00"
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 56
    test6_ids.append("ICMP_NI_Query_14")
    test6_descriptions.append("ICMP/NI Query Node Addresses IPv4/Dst=target/ICMP Code=0, Name=localhost, Flags='A'")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryIPv4()
    icmp_packet.code=1  # DNS Name
    icmp_packet.qtype=4 # Qtype=IPv4 Addresses
    icmp_packet.flags='A'
    icmp_packet.nonce='\x00\x01\x02\x03\x04\x05\x06\x07'
    icmp_packet.unused=0
    icmp_packet.data="\x09localhost\x00"
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 57
    test6_ids.append("ICMP_NI_Query_15")
    test6_descriptions.append("ICMP/NI Query Node Addresses IPv4/Dst=target/ICMP Code=0, Addr=target's, Flags='A'")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryIPv4()
    icmp_packet.code=0  # IPv6 Addr
    icmp_packet.qtype=4 # Qtype=IPv4 Addresses
    icmp_packet.flags='A'
    icmp_packet.nonce='\x01\x02\x03\x04\x05\x06\x07\x0A'
    icmp_packet.unused=0
    icmp_packet.data=target
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 58
    test6_ids.append("ICMP_NI_Query_16")
    test6_descriptions.append("ICMP/NI Query Bogus Op code/Dst=target/ICMP Code=0, Addr=target's")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryNOOP()
    icmp_packet.code=0  # IPv6 Addr
    icmp_packet.qtype=0xCAFE # Qtype=Bogus
    icmp_packet.flags='A'
    icmp_packet.nonce='\x01\x02\x03\x04\x05\x06\x07\x0B'
    icmp_packet.unused=0
    icmp_packet.data=target
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 59
    test6_ids.append("ICMP_NI_Query_17")
    test6_descriptions.append("ICMP/NI Query Bogus Op code/Dst=target/ICMP Code=Bogus")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6NIQueryNOOP()
    icmp_packet.code=0xFB  # Bogus
    icmp_packet.qtype=0xCAFE # Qtype=Bogus
    icmp_packet.flags='A'
    icmp_packet.nonce='\x01\x02\x03\x04\x05\x06\x07\x0C'
    icmp_packet.unused=0
    icmp_packet.data=target
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    ################################
    # IPv6 EXTENSION HEADERS TESTS #
    ################################

    # TEST 60
    test6_ids.append("ICMP_ExtHdrs_0")
    test6_descriptions.append("IPv6/ExtHdr DestOpts {Opts Empty} /TCP SYN")
    ip_packet=build_default_ipv6(target)
    ext_hdr=IPv6ExtHdrDestOpt()
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
    final_packet=ip_packet/ext_hdr/tcp_packet
    test6_packets.append(final_packet)

    # TEST 61
    test6_ids.append("ICMP_ExtHdrs_1")
    test6_descriptions.append("IPv6/ExtHdr DestOpts {Opts Empty} / No next Header")
    ip_packet=build_default_ipv6(target)
    ext_hdr=IPv6ExtHdrDestOpt()
    ext_hdr.nh=59 # No Next Header
    final_packet=ip_packet/ext_hdr
    test6_packets.append(final_packet)

    # TEST 62
    test6_ids.append("ICMP_ExtHdrs_2")
    test6_descriptions.append("IPv6/ExtHdr DestOpts {Opts Empty} / NextHeader=TCP but no TCP packet present")
    ip_packet=build_default_ipv6(target)
    ext_hdr=IPv6ExtHdrDestOpt()
    ext_hdr.nh=6 # TCP
    final_packet=ip_packet/ext_hdr
    test6_packets.append(final_packet)

    # TEST 63
    test6_ids.append("ICMP_ExtHdrs_3")
    test6_descriptions.append("IPv6/ExtHdr DestOpts {Option HAO (addr=target's)} / NextHeader=TCP SYN")
    ip_packet=build_default_ipv6(target)
    opt=HAO()
    opt.hoa=target
    ext_hdr=IPv6ExtHdrDestOpt(options=[opt])
    ext_hdr.nh=6 # TCP
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
    final_packet=ip_packet/ext_hdr/tcp_packet
    test6_packets.append(final_packet)

    # TEST 64
    test6_ids.append("ICMP_ExtHdrs_4")
    test6_descriptions.append("IPv6/ExtHdr DestOpts {Unrecognized option 0x80} / NextHeader=TCP SYN")
    ip_packet=build_default_ipv6(target)
    ip_packet.nh=60 # Dest Opts
    opt='\x06' # Next Header=TCP
    opt=opt+'\x01' # Header extension length=1 group of 8 octets (the first 8 are included)
    opt=opt+'\x01\x04\x00\x00\x00\x00' # Padding option (4 NULL bytes of padding)
    opt=opt+'\x80\x06\xAB\xCD\xAB\xCD\xAB\xCD' # Unknown option whose first two bits are
                                               # "10" so the receiver sends an ICMP error msg.
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
    # NOTE: Scapy does not generate a valid TCP sum for this test, but it
    # shouldn't matter because the packet should be discarded at the network
    # layer (due to the unknown option).
    final_packet=ip_packet/opt/tcp_packet
    test6_packets.append(final_packet)

    # TEST 65
    test6_ids.append("ICMP_ExtHdrs_5")
    test6_descriptions.append("IPv6/ExtHdr Hop-by-Hop {Option Router Alert (MLD)} / NextHeader=TCP SYN")
    ip_packet=build_default_ipv6(target)
    opt=RouterAlert()
    opt.value=0 # Datagram contains a Multicast Listener Discovery Message
    ext_hdr=IPv6ExtHdrHopByHop(options=[opt])
    ext_hdr.nh=6 # TCP
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
    final_packet=ip_packet/ext_hdr/tcp_packet
    test6_packets.append(final_packet)

    # TEST 66
    test6_ids.append("ICMP_ExtHdrs_6")
    test6_descriptions.append("IPv6/ExtHdr Hop-by-Hop {Option Router Alert (MLD)} / NextHeader=ICMPv6 MLD Query")
    ip_packet=build_default_ipv6(target)
    opt=RouterAlert()
    opt.value=0 # Datagram contains a Multicast Listener Discovery Message
    ext_hdr=IPv6ExtHdrHopByHop(options=[opt])
    ext_hdr.nh=58 # ICMPv6
    icmp_packet=ICMPv6MLQuery()
    #icmp_packet.mladdr= How can I set this?
    final_packet=ip_packet/ext_hdr/icmp_packet
    test6_packets.append(final_packet)

    # TEST 67
    test6_ids.append("ICMP_ExtHdrs_7")
    test6_descriptions.append("IPv6/ExtHdr Hop-by-Hop {Option Router Alert (RSVP)} / NextHeader=TCP SYN")
    ip_packet=build_default_ipv6(target)
    opt=RouterAlert()
    opt.value=1 # Datagram contains RSVP message.
    ext_hdr=IPv6ExtHdrHopByHop(options=[opt])
    ext_hdr.nh=6 # TCP
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
    final_packet=ip_packet/ext_hdr/tcp_packet
    test6_packets.append(final_packet)

    # TEST 68
    test6_ids.append("ICMP_ExtHdrs_8")
    test6_descriptions.append("IPv6/ExtHdr Hop-by-Hop {Option Router Alert (RSVP)} / NextHeader=RSVP PATH message")
    ip_packet=build_default_ipv6(target)
    opt=RouterAlert()
    opt.value=1 # Datagram contains RSVP message.
    ext_hdr=IPv6ExtHdrHopByHop(options=[opt])
    ext_hdr.nh=46 # RSVP
    # This payload was taken from:
    # http://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=rsvp-PATH-RESV.pcap
    # It contains hard coded values that don't apply to our target, but at
    # least is a valid payload.
    payload='\x10\x01\x0a\x55\xfe\x00\x00\x88\x00\x0c\x01\x01\x0a\x01\x0c\x01'+\
            '\x11\x00\x40\x04\x00\x0c\x03\x01\x0a\x01\x0c\x02\x08\x00\x04\x03'+\
            '\x00\x08\x05\x01\x00\x00\x75\x30\x00\x0c\x0b\x01\x0a\x01\x18\x04'+\
            '\x00\x00\x40\x04\x00\x24\x0c\x02\x00\x00\x00\x07\x01\x00\x00\x06'+\
            '\x7f\x00\x00\x05\x45\xbb\x80\x00\x45\xbb\x80\x00\x45\xbb\x80\x00'+\
            '\x00\x00\x00\x00\x7f\xff\xff\xff\x00\x30\x0d\x02\x00\x00\x00\x0a'+\
            '\x01\x00\x00\x08\x04\x00\x00\x01\x00\x00\x00\x02\x06\x00\x00\x01'+\
            '\x49\x98\x96\x80\x08\x00\x00\x01\x00\x00\x00\x00\x0a\x00\x00\x01'+\
            '\x00\x00\x05\xdc\x05\x00\x00\x00'
    final_packet=ip_packet/ext_hdr/payload
    test6_packets.append(final_packet)

    # TEST 69
    test6_ids.append("ICMP_ExtHdrs_9")
    test6_descriptions.append("IPv6/ExtHdr Hop-by-Hop {Option Router Alert (Active Networks)} / NextHeader=TCP SYN")
    ip_packet=build_default_ipv6(target)
    opt=RouterAlert()
    opt.value=2 # Datagram contains an Active Networks message.
    ext_hdr=IPv6ExtHdrHopByHop(options=[opt])
    ext_hdr.nh=6 # TCP
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
    final_packet=ip_packet/ext_hdr/tcp_packet
    test6_packets.append(final_packet)

    # TEST 70
    test6_ids.append("ICMP_ExtHdrs_10")
    test6_descriptions.append("IPv6 Next Header=Routing Hdr but no header present.")
    ip_packet=build_default_ipv6(target)
    ip_packet.nh=43 # 0=Hop by Hop extension header
    final_packet=ip_packet
    test6_packets.append(final_packet)

    # TEST 71
    test6_ids.append("ICMP_ExtHdrs_11")
    test6_descriptions.append("IPv6 Next Header=Hop-by-Hop but no header present.")
    ip_packet=build_default_ipv6(target)
    ip_packet.nh=0 # 0=Hop by Hop extension header
    final_packet=ip_packet
    test6_packets.append(final_packet)

    # TEST 72
    test6_ids.append("ICMP_ExtHdrs_12")
    test6_descriptions.append("IPv6/ExtHdr Hop-by-Hop Wrong length")
    ip_packet=build_default_ipv6(target)
    opt=RouterAlert()
    opt.value=2 # Datagram contains an Active Networks message.
    ext_hdr=IPv6ExtHdrHopByHop(options=[opt])
    ext_hdr.nh=6 # TCP
    ext_hdr.len=32 # (264 bytes)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
    final_packet=ip_packet/ext_hdr/tcp_packet
    test6_packets.append(final_packet)

    # TEST 73
    test6_ids.append("ICMP_ExtHdrs_13")
    test6_descriptions.append("IPv6/ExtHdr Hop-by-Hop Wrong length (datagram contains 4 bytes more than it says)")
    ip_packet=build_default_ipv6(target)
    ip_packet.plen=8
    opt=RouterAlert()
    opt.value=2 # Datagram contains an Active Networks message.
    ext_hdr=IPv6ExtHdrHopByHop(options=[opt])
    ext_hdr.nh=59 # No Next Header
    final_packet=ip_packet/ext_hdr/'\xDE\xAD\xBE\xEF'
    test6_packets.append(final_packet)

    # TEST 74
    test6_ids.append("ICMP_ExtHdrs_14")
    test6_descriptions.append("IPv6/ExtHdr Hop-by-Hop Wrong length (datagram contains 400 bytes more than it says)")
    ip_packet=build_default_ipv6(target)
    ip_packet.plen=8
    opt=RouterAlert()
    opt.value=2 # Datagram contains an Active Networks message.
    ext_hdr=IPv6ExtHdrHopByHop(options=[opt])
    ext_hdr.nh=59 # No Next Header
    final_packet=ip_packet/ext_hdr/('\xDD\xAA\xBE\xEF'*100)
    test6_packets.append(final_packet)

    # TEST 75
    test6_ids.append("ICMP_ExtHdrs_15")
    test6_descriptions.append("IPv6/ExtHdr Hop-by-Hop Wrong length (datagram contains 4 bytes less than it says)")
    ip_packet=build_default_ipv6(target)
    ip_packet.plen=16
    opt=RouterAlert()
    opt.value=2 # Datagram contains an Active Networks message.
    ext_hdr=IPv6ExtHdrHopByHop(options=[opt])
    ext_hdr.nh=59 # No Next Header
    final_packet=ip_packet/ext_hdr/'\xFE\xED\xCA\xFE'
    test6_packets.append(final_packet)

    # TEST 76
    test6_ids.append("ICMP_ExtHdrs_16")
    test6_descriptions.append("IPv6/ExtHdr Hop-by-Hop Wrong length (datagram contains 400 bytes less than it says)")
    ip_packet=build_default_ipv6(target)
    ip_packet.plen=412
    opt=RouterAlert()
    opt.value=2 # Datagram contains an Active Networks message.
    ext_hdr=IPv6ExtHdrHopByHop(options=[opt])
    ext_hdr.nh=59 # No Next Header
    final_packet=ip_packet/ext_hdr/'\xFE\xED\xCD\xFD'
    test6_packets.append(final_packet)

    # TEST 77
    test6_ids.append("ICMP_ExtHdrs_17")
    test6_descriptions.append("IPv6/ExtHdr Hop-by-Hop with 6 PAD1/ICMPv6 Echo Request/Payload=150B")
    ip_packet=build_default_ipv6(target)
    ip_packet.nh=0 # Hop by hop
    ext_hdr='\x3A\x00\x00\x00\x00\x00\x00\x00' # NH=ICMPv6 followed by six PAD1
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\xBA"*150
    final_packet=ip_packet/ext_hdr/icmp_packet
    test6_packets.append(final_packet)

    # TEST 78
    test6_ids.append("ICMP_ExtHdrs_18")
    test6_descriptions.append("IPv6/Two hop-by-hop extension headers/ICMPv6 Echo Request/Payload=150B")
    ip_packet=build_default_ipv6(target)
    ip_packet.nh=0 # Hop by hop
    ext_hdr='\x00\x00\x00\x00\x00\x00\x00\x00' # NH=HopByHop followed by six PAD1
    ext_hdr2='\x3A\x00\x00\x00\x00\x00\x00\x00' # NH=ICMPv6 followed by six PAD1
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\xBB"*150
    final_packet=ip_packet/ext_hdr/ext_hdr2/icmp_packet
    test6_packets.append(final_packet)

    # TEST 79
    test6_ids.append("ICMP_ExtHdrs_19")
    test6_descriptions.append("IPv6/128 hop-by-hop extension headers/ICMPv6 Echo Request/Payload=150B")
    ip_packet=build_default_ipv6(target)
    ip_packet.nh=0 # Hop by hop
    extension_hdr=''
    ext_hdr_1='\x00\x00\x00\x00\x00\x00\x00\x00' # NH=HopByHop followed by six PAD1
    for i in range(0, 127) :
        extension_hdr=extension_hdr+ext_hdr_1
    ext_hdr_2='\x3A\x00\x00\x00\x00\x00\x00\x00' # NH=ICMPv6 followed by six PAD1
    extension_hdr=extension_hdr+ext_hdr_2
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\xBC"*150
    final_packet=ip_packet/extension_hdr/icmp_packet
    test6_packets.append(final_packet)

    # TEST 80
    test6_ids.append("ICMP_ExtHdrs_20")
    test6_descriptions.append("IPv6/ExtHdr Destination with 6 PAD1/ICMPv6 Echo Request/Payload=150B")
    ip_packet=build_default_ipv6(target)
    ip_packet.nh=0x3c # Destination Options
    ext_hdr='\x3A\x00\x00\x00\x00\x00\x00\x00' # NH=ICMPv6 followed by six PAD1
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\xBD"*150
    final_packet=ip_packet/ext_hdr/icmp_packet
    test6_packets.append(final_packet)

    # TEST 81
    test6_ids.append("ICMP_ExtHdrs_21")
    test6_descriptions.append("IPv6/Two Destination extension headers/ICMPv6 Echo Request/Payload=150B")
    ip_packet=build_default_ipv6(target)
    ip_packet.nh=0x3c # Destination Options
    ext_hdr='\x3C\x00\x00\x00\x00\x00\x00\x00' # NH=DestOps followed by six PAD1
    ext_hdr2='\x3A\x00\x00\x00\x00\x00\x00\x00' # NH=ICMPv6 followed by six PAD1
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\xBE"*150
    final_packet=ip_packet/ext_hdr/ext_hdr2/icmp_packet
    test6_packets.append(final_packet)

    # TEST 82
    test6_ids.append("ICMP_ExtHdrs_22")
    test6_descriptions.append("IPv6/128 Destination extension headers/ICMPv6 Echo Request/Payload=150B")
    ip_packet=build_default_ipv6(target)
    ip_packet.nh=0x3c # Destination Options
    extension_hdr=''
    ext_hdr_1='\x3C\x00\x00\x00\x00\x00\x00\x00' # NH=DestOps followed by six PAD1
    for i in range(0, 127) :
        extension_hdr=extension_hdr+ext_hdr_1
    ext_hdr_2='\x3A\x00\x00\x00\x00\x00\x00\x00' # NH=ICMPv6 followed by six PAD1
    extension_hdr=extension_hdr+ext_hdr_2
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\xBF"*150
    final_packet=ip_packet/extension_hdr/icmp_packet
    test6_packets.append(final_packet)

    # TEST 83
    test6_ids.append("ICMP_ExtHdrs_23")
    test6_descriptions.append("IPv6/Fragmented ICMPv6 Echo Request/Payload=1500B, First Datagram PLEN=1440. (Two packets sent!)")
    ip_packet=build_default_ipv6(target)
    frag_hdr=IPv6ExtHdrFragment()
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\xC0"*1500
    final_packet=ip_packet/frag_hdr/icmp_packet
    finals=fragment6(final_packet, fragSize=1480)
    test6_packets.append(finals)

    # TEST 84
    test6_ids.append("ICMP_ExtHdrs_24")
    test6_descriptions.append("IPv6/Fragmented ICMPv6 Echo Request/Payload=1500B, First Datagram PLEN=520. (Three packets sent)")
    ip_packet=build_default_ipv6(target)
    frag_hdr=IPv6ExtHdrFragment()
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\xAA"*504 + "\xBB"*512 + "\xCC"*484
    final_packet=ip_packet/frag_hdr/icmp_packet
    finals=fragment6(final_packet, fragSize=560)
    test6_packets.append(finals)

    # The two following tests produce a deprecation warning. This will prevent
    # the warnings from being printed.
    warnings.filterwarnings("ignore", category=DeprecationWarning)

    # TEST 85
    test6_ids.append("ICMP_ExtHdrs_25")
    test6_descriptions.append("IPv6/Fragmented ICMPv6 Echo Request/Payload=65535B, PLEN=1440. (46 packets sent)")
    ip_packet=build_default_ipv6(target)
    frag_hdr=IPv6ExtHdrFragment()
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\xDD"*65000         # This used to equal 65535 but since it fails in Python>=2.7, it was changed to 65001
    final_packet=ip_packet/frag_hdr/icmp_packet
    finals=fragment6(final_packet, fragSize=1480)
    test6_packets.append(finals)

    # TEST 86
    test6_ids.append("ICMP_ExtHdrs_26")
    test6_descriptions.append("IPv6/Fragmented ICMPv6 Echo Request/Payload=65800B (>65535), PLEN=1440. (46 packets sent)")
    ip_packet=build_default_ipv6(target)
    frag_hdr=IPv6ExtHdrFragment()
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\xEE"*65001        # This used to equal 65800 but since it fails in Python>=2.7, it was changed to 65001
    final_packet=ip_packet/frag_hdr/icmp_packet
    finals=fragment6(final_packet, fragSize=1480)
    test6_packets.append(finals)

    # Clear the warning filter list, so the rest of warnings (if they exist)
    # get printed out.
    warnings.resetwarnings()

    # TEST 87
    test6_ids.append("ICMP_ExtHdrs_27")
    test6_descriptions.append("IPv6/Fragmented packet that overlaps from the start. Both fragments are ICMP Echo Requests but differ on their payload")
    ip_packet_1=build_default_ipv6(target)
    frag_hdr_1=IPv6ExtHdrFragment()
    frag_hdr_1.m=1
    frag_hdr_1.offset=0
    frag_hdr_1.id=0x12345678
    icmp_packet_1=build_default_icmpv6()
    icmp_packet_1.seq=get_icmp_seq_number()
    icmp_packet_1.data="\xFF"*128
    final_packet_1=ip_packet_1/frag_hdr_1/icmp_packet_1

    ip_packet_2=build_default_ipv6(target)
    frag_hdr_2=IPv6ExtHdrFragment()
    frag_hdr_2.m=0
    frag_hdr_2.offset=0
    frag_hdr_2.id=0x12345678
    icmp_packet_2=build_default_icmpv6()
    icmp_packet_2.seq=get_icmp_seq_number()
    icmp_packet_2.data="\x01"*128
    final_packet_2=ip_packet_2/frag_hdr_2/icmp_packet_2
    finals=[final_packet_1,  final_packet_2]
    test6_packets.append(finals)

    # TEST 88
    test6_ids.append("ICMP_ExtHdrs_28")
    test6_descriptions.append("IPv6/Fragmented packet that overlaps from byte #8. ICMP EchoReq overwritten. Payload cksum collision.")
    ip_packet_1=build_default_ipv6(target)
    frag_hdr_1=IPv6ExtHdrFragment()
    frag_hdr_1.m=1
    frag_hdr_1.offset=0
    frag_hdr_1.id=0x34567812
    frag_hdr_1.nh=58 # ICMPv6
    icmp_packet_1=build_default_icmpv6()
    icmp_packet_1.seq=get_icmp_seq_number()
    icmp_packet_1.data="\x00\x00\xFF\xFF"*10
    final_packet_1=ip_packet_1/frag_hdr_1/icmp_packet_1

    ip_packet_2=build_default_ipv6(target)
    frag_hdr_2=IPv6ExtHdrFragment()
    frag_hdr_2.m=0
    frag_hdr_2.offset=1 # 1=8 octets
    frag_hdr_2.id=0x34567812
    frag_hdr_2.nh=58 # ICMPv6
    payload="\xFF\xFF\x00\x00"*10 # Checksum collision (same cksum as "\x00\x00\xFF\xFF"*10 )
    final_packet_2=ip_packet_2/frag_hdr_2/payload
    finals_t88=[final_packet_1,  final_packet_2]
    test6_packets.append(finals_t88)

    # TEST 89
    test6_ids.append("ICMP_ExtHdrs_29")
    test6_descriptions.append("IPv6/Fragmented packet that overlaps from byte #8. ICMP EchoReq overwritten. Payload cksum collision. (send last first)")
    finals_t89=[final_packet_2,  final_packet_1]
    test6_packets.append(finals_t89)

    # TEST 90
    test6_ids.append("ICMP_ExtHdrs_30")
    test6_descriptions.append("IPv6/Hop-by-hop/DestOpts/Routing/ICMPv6 Echo request")
    ip_packet=build_default_ipv6(target)
    ext_1=IPv6ExtHdrHopByHop()
    ext_2=IPv6ExtHdrDestOpt()
    ext_3=IPv6ExtHdrRouting()
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x02"*16
    final_packet=ip_packet/ext_1/ext_2/ext_3/icmp_packet
    test6_packets.append(final_packet)

    # TEST 91
    test6_ids.append("ICMP_ExtHdrs_31")
    test6_descriptions.append("IPv6/Hop-by-hop/Routing/DestOpts/ICMPv6 Echo request (Headers ordered incorrectly,  I)")
    ip_packet=build_default_ipv6(target)
    ext_1=IPv6ExtHdrHopByHop()
    ext_2=IPv6ExtHdrDestOpt()
    ext_3=IPv6ExtHdrRouting()
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x03"*16
    final_packet=ip_packet/ext_1/ext_3/ext_2/icmp_packet
    test6_packets.append(final_packet)

    # TEST 92
    test6_ids.append("ICMP_ExtHdrs_32")
    test6_descriptions.append("IPv6/DestOpts/Routing/Hop-by-hop/ICMPv6 Echo request (Headers ordered incorrectly, II)")
    ip_packet=build_default_ipv6(target)
    ext_1=IPv6ExtHdrHopByHop()
    ext_2=IPv6ExtHdrDestOpt()
    ext_3=IPv6ExtHdrRouting()
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x04"*16
    final_packet=ip_packet/ext_2/ext_3/ext_1/icmp_packet
    test6_packets.append(final_packet)

    # TEST 93
    test6_ids.append("ICMP_ExtHdrs_33")
    test6_descriptions.append("IPv6/Routing/Hop-by-hop/DestOpts/ICMPv6 Echo request (Headers ordered incorrectly, III)")
    ip_packet=build_default_ipv6(target)
    ext_1=IPv6ExtHdrHopByHop()
    ext_2=IPv6ExtHdrDestOpt()
    ext_3=IPv6ExtHdrRouting()
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x05"*16
    final_packet=ip_packet/ext_3/ext_1/ext_2/icmp_packet
    test6_packets.append(final_packet)

    # TEST 94
    test6_ids.append("ICMP_ExtHdrs_34")
    test6_descriptions.append("IPv6/Hop-by-hop/DestOpts/Routing/DestOpts/ICMPv6 Echo request (Two DestOpts, allowed by RFC)")
    ip_packet=build_default_ipv6(target)
    ext_1=IPv6ExtHdrHopByHop()
    ext_2=IPv6ExtHdrDestOpt()
    ext_3=IPv6ExtHdrRouting()
    ext_4=IPv6ExtHdrDestOpt()
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x06"*16
    final_packet=ip_packet/ext_1/ext_2/ext_3/ext_4/icmp_packet
    test6_packets.append(final_packet)

    # TEST 95
    test6_ids.append("ICMP_ExtHdrs_35")
    test6_descriptions.append("IPv6/Hop-by-hop/DestOpts/Routing/DestOpts/ICMPv6 Echo request (>2 DestOpts, NOT allowed by RFC)")
    ip_packet=build_default_ipv6(target)
    ext_1=IPv6ExtHdrHopByHop()
    ext_2=IPv6ExtHdrDestOpt()
    ext_3=IPv6ExtHdrRouting()
    ext_4=IPv6ExtHdrDestOpt()
    ext_5=IPv6ExtHdrDestOpt()
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x07"*16
    final_packet=ip_packet/ext_1/ext_2/ext_3/ext_4/ext_5/icmp_packet
    test6_packets.append(final_packet)

    # TEST 96
    test6_ids.append("ICMP_ExtHdrs_36")
    test6_descriptions.append("IPv6/Hop-by-hop with OPT=Jumbo Payload. IPv6 PLEN=0, Jumbolen=0)")
    ip_packet=build_default_ipv6(target)
    opt=Jumbo()
    opt.jumboplen=0
    ext_1=IPv6ExtHdrHopByHop(options=[opt])
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x08"*16
    final_packet=ip_packet/ext_1/icmp_packet
    final_packet.plen=0
    test6_packets.append(final_packet)

    # TEST 97
    test6_ids.append("ICMP_ExtHdrs_37")
    test6_descriptions.append("IPv6/Hop-by-hop with OPT=Jumbo Payload. IPv6 PLEN=0 Jumbolen=32)")
    ip_packet=build_default_ipv6(target)
    opt=Jumbo()
    opt.jumboplen=32
    ext_1=IPv6ExtHdrHopByHop(options=[opt])
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x09"*16
    final_packet=ip_packet/ext_1/icmp_packet
    final_packet.plen=0
    test6_packets.append(final_packet)

    # TEST 98
    test6_ids.append("ICMP_ExtHdrs_38")
    test6_descriptions.append("IPv6/Hop-by-hop with OPT=Jumbo Payload. IPv6 PLEN=0 Jumbolen=65535)")
    ip_packet=build_default_ipv6(target)
    opt=Jumbo()
    opt.jumboplen=65535
    ext_1=IPv6ExtHdrHopByHop(options=[opt])
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x0A"*16
    final_packet=ip_packet/ext_1/icmp_packet
    final_packet.plen=0
    test6_packets.append(final_packet)

    # TEST 99
    test6_ids.append("ICMP_ExtHdrs_39")
    test6_descriptions.append("IPv6/Hop-by-hop with OPT=Jumbo Payload. IPv6 PLEN=0 Jumbolen=100000)")
    ip_packet=build_default_ipv6(target)
    opt=Jumbo()
    opt.jumboplen=100000
    ext_1=IPv6ExtHdrHopByHop(options=[opt])
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x0B"*16
    final_packet=ip_packet/ext_1/icmp_packet
    final_packet.plen=0
    test6_packets.append(final_packet)

    # TEST 100
    test6_ids.append("ICMP_ExtHdrs_40")
    test6_descriptions.append("IPv6/Hop-by-hop with Two OPT=Jumbo Payload. IPv6 PLEN=O")
    ip_packet=build_default_ipv6(target)
    opt=Jumbo()
    opt.jumboplen=0
    opt2=Jumbo()
    opt2.jumboplen=65536
    ext_1=IPv6ExtHdrHopByHop(options=[opt,opt2])
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x0C"*16
    final_packet=ip_packet/ext_1/icmp_packet
    final_packet.plen=0
    test6_packets.append(final_packet)

    # TEST 101
    test6_ids.append("ICMP_ExtHdrs_41")
    test6_descriptions.append("IPv6/Hop-by-hop with 128 OPT=Jumbo Payload. IPv6 PLEN=O")
    ip_packet=build_default_ipv6(target)
    opt=Jumbo()
    opt.jumboplen=65536
    opt2=[]
    for i in range(0, 128) :
        opt2=opt2+[opt]
    ext_1=IPv6ExtHdrHopByHop(options=opt2)
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x0D"*16
    final_packet=ip_packet/ext_1/icmp_packet
    final_packet.plen=0
    test6_packets.append(final_packet)

    # TEST 102
    test6_ids.append("ICMP_ExtHdrs_42")
        # RFC 2675: The Jumbo Payload option must not be used in a packet that carries a Fragment header.
    test6_descriptions.append("IPv6/Hop-by-hop with OPT=Jumbo Payload/Fragment Header (two packets sent)")
    ip_packet=build_default_ipv6(target)
    opt=Jumbo()
    opt.jumboplen=65536
    ext_1=IPv6ExtHdrHopByHop(options=[opt])
    ext_2=IPv6ExtHdrFragment()
    ext_2.id=0x38741272
    ext_2.m=1 # More fragments=Yes
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x0E"*696 +"\x0F"*328
    final_packet=ip_packet/ext_1/ext_2/icmp_packet
    finals=fragment6(final_packet, fragSize=760)
    test6_packets.append(finals)

    # TEST 103
    test6_ids.append("ICMP_ExtHdrs_43")
       # From RFC 2675:
       # error: IPv6 Payload Length = 0 and
       #      IPv6 Next Header = Hop-by-Hop Options and
       #      Jumbo Payload option not present
       #
       #      Code: 0
       #      Pointer: high-order octet of the IPv6 Payload Length
    test6_descriptions.append("IPv6 with PLEN=0/Hop-by-hop without Jumbo Payload")
    ip_packet=build_default_ipv6(target)
    ext_1=IPv6ExtHdrHopByHop()
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x10"*16
    final_packet=ip_packet/ext_1/icmp_packet
    final_packet.plen=0
    test6_packets.append(final_packet)

    # TEST 104
    test6_ids.append("ICMP_ExtHdrs_44")
       # From RFC 2675:
       # error: IPv6 Payload Length != 0 and
       #      Jumbo Payload option present
       #
       #      Code: 0
       #      Pointer: Option Type field of the Jumbo Payload option
    test6_descriptions.append("IPv6 with PLEN!=0/Hop-by-hop with Jumbo Payload")
    ip_packet=build_default_ipv6(target)
    opt=Jumbo()
    opt.jumboplen=92319
    ext_1=IPv6ExtHdrHopByHop(options=[opt])
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x11"*16
    final_packet=ip_packet/ext_1/icmp_packet
    test6_packets.append(final_packet)

    # TEST 105
    test6_ids.append("ICMP_ExtHdrs_45")
    test6_descriptions.append("IPv6 with PLEN!=0/Hop-by-hop with OPT=Tunnel Encapsulation Limit (l=0)")
    ip_packet=build_default_ipv6(target)
    opt=PadN()      # Use PadN as a template
    opt.otype=0x04  # Tunnel Encapsulation Limit (RFC 2473)
    opt.optlen=1
    opt.optdata='\x00' # limit=0
    ext_1=IPv6ExtHdrHopByHop(options=[opt])
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x12"*16
    final_packet=ip_packet/ext_1/icmp_packet
    test6_packets.append(final_packet)

    # TEST 106
    test6_ids.append("ICMP_ExtHdrs_46")
    test6_descriptions.append("IPv6 with PLEN!=0/Hop-by-hop with OPT=Tunnel Encapsulation Limit (l=1)")
    ip_packet=build_default_ipv6(target)
    opt=PadN()      # Use PadN as a template
    opt.otype=0x04  # Tunnel Encapsulation Limit
    opt.optlen=1
    opt.optdata='\x01' # limit=1
    ext_1=IPv6ExtHdrHopByHop(options=[opt])
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x13"*16
    final_packet=ip_packet/ext_1/icmp_packet
    test6_packets.append(final_packet)

    # TEST 107
    test6_ids.append("ICMP_ExtHdrs_47")
    test6_descriptions.append("IPv6/Hop-by-Hop with OPT=Quick-Start with RR=0 /TCP SYN)")
    ip_packet=build_default_ipv6(target)
        #    0                   1                   2                   3
        #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #   |   Option      |  Length=8     | Func. | Rate  |   QS TTL      |
        #   |               |               | 0000  |Request|               |
        #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #   |                        QS Nonce                           | R |
        #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    opt=PadN()      # Use PadN as a template
    opt.otype=0x26  #  Quick-Start (RFC 4782)
    opt.optlen=6
    opt.optdata='\x00\xE6\xF0\xF0\xB0\x00' # Func=0000 (rate request), RReq=0 (0 Kbps), QTTL=230 (xE6), QNonce=0xF0F0B000 Reserved=00
    ext=IPv6ExtHdrHopByHop(options=[opt])
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
    final_packet=ip_packet/ext/tcp_packet
    test6_packets.append(final_packet)

    # TEST 108
    test6_ids.append("ICMP_ExtHdrs_48")
    test6_descriptions.append("IPv6/Hop-by-Hop with OPT=Quick-Start with RR=15 /TCP SYN)")
    ip_packet=build_default_ipv6(target)
    opt=PadN()      # Use PadN as a template
    opt.otype=0x26  #  Quick-Start (RFC 4782)
    opt.optlen=6
    opt.optdata='\x0F\xE6\xF1\xF1\xB0\x00' # Func=0000 (rate request), RReq=F (1,310,720 Kbps), QTTL=230 (xE6), QNonce=0xF1F1B000 Reserved=00
    ext=IPv6ExtHdrHopByHop(options=[opt])
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
    final_packet=ip_packet/ext/tcp_packet
    test6_packets.append(final_packet)

    # TEST 109
    test6_ids.append("ICMP_ExtHdrs_49")
    test6_descriptions.append("IPv6/Hop-by-Hop with OPT=Quick-Start Report/TCP SYN)")
    ip_packet=build_default_ipv6(target)
    opt=PadN()      # Use PadN as a template
    opt.otype=0x26  #  Quick-Start (RFC 4782)
    opt.optlen=6
    opt.optdata='\x82\x00\xF2\xF2\xB0\x00' # Func=1000 (rate report), RRep=2 (160 Kbps), Unused=0, QNonce=0xF2F2B000 Reserved=00
    ext=IPv6ExtHdrHopByHop(options=[opt])
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
    final_packet=ip_packet/ext/tcp_packet
    test6_packets.append(final_packet)

    # TEST 110
    test6_ids.append("ICMP_ExtHdrs_50")
    test6_descriptions.append("IPv6/Hop-by-Hop with OPT=CALIPSO/TCP SYN)")
    ip_packet=build_default_ipv6(target)
        #                                 ------------------------------
        #                                 | Option Type | Option Length|
        #   +-------------+---------------+-------------+--------------+
        #   |             CALIPSO Domain of Interpretation             |
        #   +-------------+---------------+-------------+--------------+
        #   | Cmpt Length |  Sens Level   |     Checksum (CRC-16)      |
        #   +-------------+---------------+-------------+--------------+
        #   |      Compartment Bitmap (Optional; variable length)      |
        #   +-------------+---------------+-------------+--------------+
    opt=PadN()      # Use PadN as a template
    opt.otype=0x07  # CALIPSO (RFC 5570)
    opt.optlen=8
    opt.optdata='\xA0\xA1\xA2\xA3\x00\xFE\x00\x00' # DOI=0x, Clen=0, SLevel=0xFE, Csum=0x0000, CBmap=N/A
    ext=IPv6ExtHdrHopByHop(options=[opt])
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
    final_packet=ip_packet/ext/tcp_packet
    test6_packets.append(final_packet)

    #######################
    # MISCELLANEOUS TESTS #
    #######################

    # TEST 111
    test6_ids.append("ICMP_Misc_1")
    test6_descriptions.append("ICMP Inverse Neighbor Discovery Solicitation (to target's unicast addr)")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_INDSol() # RFC 3122
    opt_1=ICMPv6NDOptSrcLLAddr() # Source link layer address
    opt_2=ICMPv6NDOptDstLLAddr() # Target link layer address
    final_packet=ip_packet/icmp_packet/opt_1/opt_2
    test6_packets.append(final_packet)

    # TEST 112
    test6_ids.append("ICMP_Misc_2")
    test6_descriptions.append("ICMP Inverse Neighbor Discovery Solicitation (to target's unicast addr) Both Options missing")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_INDSol() # RFC 3122
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 113
    test6_ids.append("ICMP_Misc_3")
    test6_descriptions.append("ICMP Inverse Neighbor Discovery Solicitation (to target's unicast addr) 1 Option missing")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_INDSol() # RFC 3122
    opt=ICMPv6NDOptDstLLAddr() # Target link layer address
    final_packet=ip_packet/icmp_packet/opt
    test6_packets.append(final_packet)

    # TEST 114
    test6_ids.append("ICMP_Misc_4")
    test6_descriptions.append("ICMP Mobile Prefix Solicitation")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6MPSol() # RFC 3122
    icmp_packet.id=0x3474
    opt=HAO() # Home Address Option
    opt.hoa=target
    ext_hdr=IPv6ExtHdrDestOpt(options=[opt])
    final_packet=ip_packet/ext_hdr/icmp_packet
    test6_packets.append(final_packet)

    # TEST 115
    test6_ids.append("ICMP_Misc_5")
    test6_descriptions.append("ICMP Mobile Prefix Solicitation with no HAO present")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6MPSol() # RFC 3122
    icmp_packet.id=0x3345
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 116
    test6_ids.append("ICMP_Misc_6")
    test6_descriptions.append("ICMP Mobile Prefix Solicitation with ICMP Code!=0")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6MPSol() # RFC 3122
    icmp_packet.id=0x3352
    icmp_packet.code=33
    opt=HAO() # Home Address Option
    opt.hoa=target
    ext_hdr=IPv6ExtHdrDestOpt(options=[opt])
    final_packet=ip_packet/ext_hdr/icmp_packet
    test6_packets.append(final_packet)

    # TEST 117
    test6_ids.append("ICMP_Misc_7")
    test6_descriptions.append("ICMP Certificate Path Solicitation (Retrieve all certs)")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6MPSol() # Use ICMP MPrefix Sol as a template
    icmp_packet.type=148 # Certification Path Solicitation Message (RFC 3971)
    icmp_packet.id=0x1632
    icmp_packet.code=0
    icmp_packet.res=65535 # Component=65535 (all certs)
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 118
    test6_ids.append("ICMP_Misc_8")
    test6_descriptions.append("ICMP Certificate Path Solicitation (Retrieve cert #65530)")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6MPSol() # Use ICMP MPrefix Sol as a template
    icmp_packet.type=148 # Certification Path Solicitation Message (RFC 3971)
    icmp_packet.id=0x1632
    icmp_packet.code=0
    icmp_packet.res=65530 # Component=65530 (Cert No. 65530)
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 119
    test6_ids.append("ICMP_Misc_9")
    test6_descriptions.append("ICMP Certificate Path Solicitation with ID=0")
    ip_packet=build_default_ipv6(target)
    icmp_packet=ICMPv6MPSol() # Use ICMP MPrefix Sol as a template
    icmp_packet.type=148 # Certification Path Solicitation Message (RFC 3971)
    icmp_packet.id=0 # From RFC 3971: the Identifier field MUST NOT be zero
    icmp_packet.code=0
    icmp_packet.res=65535 # Component=65535 (all certs)
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 120
    test6_ids.append("ICMP_Misc_10")
    test6_descriptions.append("ICMP/EchoReq/BadSum(sum=0x4444)")
    ip_packet=build_default_ipv6(target)
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.cksum=0x4444
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 121
    test6_ids.append("ICMP_Misc_11")
    test6_descriptions.append("ICMP/EchoReq/BadSum(sum=0)")
    ip_packet=build_default_ipv6(target)
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.cksum=0x0000
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 122
    test6_ids.append("ICMP_Misc_12")
    test6_descriptions.append("IPv6/DestOpts extension header with a PadN that does not contain 0x00 bytes")
    ip_packet=build_default_ipv6(target)
    ip_packet.nh=0x3c # Destination Options
    ext_hdr='\x3A\x00\x01\x04\x44\x33\x22\x11' # NH=ICMPv6 followed by PADN(4 non-zero bytes)
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x14"*150
    final_packet=ip_packet/ext_hdr/icmp_packet
    test6_packets.append(final_packet)

    # TEST 123
    test6_ids.append("ICMP_Misc_13")
    test6_descriptions.append("IPv6/Hop-by-Hop extension header with a PadN that does not contain 0x00 bytes")
    ip_packet=build_default_ipv6(target)
    ip_packet.nh=0x00 # Hop-by-hop extension header
    ext_hdr='\x3A\x00\x01\x04\x55\x66\x77\x88' # NH=ICMPv6 followed by PADN(4 non-zero bytes)
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x15"*150
    final_packet=ip_packet/ext_hdr/icmp_packet
    test6_packets.append(final_packet)

    # TEST 124
    test6_ids.append("ICMP_Misc_14")
    test6_descriptions.append("IPv6 with Plen=0/ICMP Echo")
    ip_packet=build_default_ipv6(target)
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x16"*32
    final_packet=ip_packet/icmp_packet
    final_packet.plen=0
    test6_packets.append(final_packet)

    # TEST 125
    test6_ids.append("ICMP_Misc_15")
    test6_descriptions.append("IPv6/Hop-By-Hop with a lot of PadN and an unknown option at the end/ICMP Echo")
    ip_packet=build_default_ipv6(target)
    ip_packet.nh=0x00 # Hop-by-hop extension header
    ext='\x3A'    # Next header=ICMPv6
    ext=ext+'\x80'   # Len
    for i in range(0, 128):
        ext=ext+'\x01\x06\x00\x00\x00\x00\x00\x00'
    ext=ext+'\x80\x04\x00\x00\x00\x00' # Unknown option that starts with 10b
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x17"*32
    final_packet=ip_packet/ext/icmp_packet
    test6_packets.append(final_packet)

    # TEST 126
    test6_ids.append("ICMP_Misc_16")
    test6_descriptions.append("IPv6 in IPv6/ICMP Echo")
    ip_packet=build_default_ipv6(target)
    ip_packet2=build_default_ipv6(target)
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x18"*32
    final_packet=ip_packet/ip_packet2/icmp_packet
    test6_packets.append(final_packet)

    # TEST 127
    test6_ids.append("ICMP_Misc_17")
    test6_descriptions.append("IPv4 in IPv6/ICMPv4 Echo")
    ip_packet=build_default_ipv6(target)
    ip_packet.nh=4 # IPv4
    ip_packet2=IP()
    ip_packet2.src="127.0.0.1"
    ip_packet2.dst="127.0.0.1"
    icmp_packet=ICMP()
    icmp_packet.id=0x4433
    icmp_packet.seq=get_icmp_seq_number()
    final_packet=ip_packet/ip_packet2/icmp_packet
    test6_packets.append(final_packet)

    # TEST 128
    test6_ids.append("ICMP_Misc_18")
    test6_descriptions.append("IPv6/NextHeader=Unknown")
    ip_packet=build_default_ipv6(target)
    ip_packet.nh=255 # IANA Reserverd protocol value
    payload="\x3b" + "\x11"*31
    final_packet=ip_packet/payload
    test6_packets.append(final_packet)

    # TEST 129
    test6_ids.append("ICMP_Misc_19")
    test6_descriptions.append("IPv6/NextHeader=Shim6")
    ip_packet=build_default_ipv6(target)
    ip_packet.nh=140 # Shim6
    payload="\x3b\x00\x81" + "\x00"*6
    final_packet=ip_packet/payload
    test6_packets.append(final_packet)

    # TEST 130
    test6_ids.append("ICMP_Misc_20")
    test6_descriptions.append("IPv6/MobileIPv6 (Binding Refresh Request)")
    ip_packet=build_default_ipv6(target)
    payload=MIP6MH_BRR()
    final_packet=ip_packet/payload
    test6_packets.append(final_packet)

    # TEST 131
    test6_ids.append("ICMP_Misc_21")
    test6_descriptions.append("IPv6/MobileIPv6 (Home Test Init)")
    ip_packet=build_default_ipv6(target)
    payload=MIP6MH_HoTI()
    final_packet=ip_packet/payload
    test6_packets.append(final_packet)

    # TEST 132
    test6_ids.append("ICMP_Misc_22")
    test6_descriptions.append("IPv6/MobileIPv6 (Care-of Test Init)")
    ip_packet=build_default_ipv6(target)
    payload=MIP6MH_CoTI()
    final_packet=ip_packet/payload
    test6_packets.append(final_packet)

    # TEST 133
    test6_ids.append("ICMP_Misc_23")
    test6_descriptions.append("IPv6/MobileIPv6 (Home Test Init) with NH!=59")
    ip_packet=build_default_ipv6(target)
    mobile6=MIP6MH_HoTI()
    # From RFC=3775: The Payload Proto field MUST be IPPROTO_NONE (59 decimal).
    #    Otherwise, the node MUST discard the message and SHOULD send ICMP
    #    Parameter Problem, Code 0
    mobile6.nh=58 # NH=ICMPv6
    icmp_packet=build_default_icmpv6()
    final_packet=ip_packet/mobile6/icmp_packet
    test6_packets.append(final_packet)

    # TEST 134
    test6_ids.append("ICMP_Misc_24")
    test6_descriptions.append("IPv6/MobileIPv6 (Home Test Init) with wrong length")
    ip_packet=build_default_ipv6(target)
    mobile6=MIP6MH_HoTI()
    # From RFC=3775: the Header Len field in the Mobility Header MUST NOT be less
    #    than the length specified for this particular type of message in
    mobile6.len=0
    final_packet=ip_packet/mobile6
    test6_packets.append(final_packet)

    # TEST 135
    test6_ids.append("ICMP_Misc_25")
    test6_descriptions.append("IPv6/MobileIPv6 (Home Test Init) with wrong length in opts")
    ip_packet=build_default_ipv6(target)
    mobile6=MIP6MH_HoTI()
    # From RFC=3775: the Header Len field in the Mobility Header MUST NOT be less
    #    than the length specified for this particular type of message in
    mobile6.len=128
    final_packet=ip_packet/mobile6/ ('\xDE'*1000)
    test6_packets.append(final_packet)

    # TEST 136
    test6_ids.append("ICMP_Misc_26")
    test6_descriptions.append("IPv6 with Flow Label=0/ICMP Echo")
    ip_packet=build_default_ipv6(target)
    ip_packet.fl=0
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x19"*32
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 137
    test6_ids.append("ICMP_Misc_27")
    test6_descriptions.append("IPv6 with Flow Label=0xFFFFF/ICMP Echo")
    ip_packet=build_default_ipv6(target)
    ip_packet.fl=0xFFFFF
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x1A"*32
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 138
    test6_ids.append("ICMP_Misc_28")
    test6_descriptions.append("IPv6 with Flow Label=0/TCP SYN")
    ip_packet=build_default_ipv6(target)
    ip_packet.fl=0
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 139
    test6_ids.append("ICMP_Misc_29")
    test6_descriptions.append("IPv6 with Flow Label=0xFFFFF/TCP SYN")
    ip_packet=build_default_ipv6(target)
    ip_packet.fl=0xFFFFF
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 140
    test6_ids.append("ICMP_Misc_30")
    test6_descriptions.append("IPv6 with Flow Label=0/UDP to closed port")
    ip_packet=build_default_ipv6(target)
    ip_packet.fl=0
    udp_packet=build_default_udp()
    udp_packet.dport=closed_port_g
    udp_packet.sport=get_source_port_number()
    payload="\x1B"*44
    final_packet=ip_packet/udp_packet/payload
    test6_packets.append(final_packet)

    # TEST 141
    test6_ids.append("ICMP_Misc_31")
    test6_descriptions.append("IPv6 with Flow Label=0xFFFFF/UDP to closed port")
    ip_packet=build_default_ipv6(target)
    ip_packet.fl=0xFFFFF
    udp_packet=build_default_udp()
    udp_packet.dport=closed_port_g
    udp_packet.sport=get_source_port_number()
    payload="\x1C"*44
    final_packet=ip_packet/udp_packet/payload
    test6_packets.append(final_packet)

    # TEST 142
    test6_ids.append("ICMP_Misc_32")
    test6_descriptions.append("IPv6 with Traffic Class=0xFF/ICMP Echo")
    ip_packet=build_default_ipv6(target)
    ip_packet.tc=0xFF
    icmp_packet=build_default_icmpv6()
    icmp_packet.seq=get_icmp_seq_number()
    icmp_packet.data="\x1D"*32
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 143
    test6_ids.append("ICMP_Misc_33")
    test6_descriptions.append("IPv6 with Traffic Class=0xFF/TCP SYN")
    ip_packet=build_default_ipv6(target)
    ip_packet.tc=0xFF
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 144
    test6_ids.append("ICMP_Misc_34")
    test6_descriptions.append("IPv6 with Traffic Class=0xFF/UDP to closed port")
    ip_packet=build_default_ipv6(target)
    ip_packet.tc=0xFF
    udp_packet=build_default_udp()
    udp_packet.dport=closed_port_g
    udp_packet.sport=get_source_port_number()
    payload="\x1E"*44
    final_packet=ip_packet/udp_packet/payload
    test6_packets.append(final_packet)

    # TEST 145
    test6_ids.append("ICMP_Misc_35")
    test6_descriptions.append("IPv6/First fragment with a payload that is not multiple of 8")
        # From RFC 2460:
        # "If the length of a fragment, as derived from the fragment packet's
        # Payload Length field, is not a multiple of 8 octets and the M flag
        # of that fragment is 1, then that fragment must be discarded and an
        # ICMP Parameter Problem, Code 0, message should be sent to the
        # source of the fragment, pointing to the Payload Length field of
        # the fragment packet."
        #
        # NOTE: The absence of a reply to this test is significant and should
        #       be considered. @todo TODO
    ip_packet=build_default_ipv6(target)
    frag_hdr=IPv6ExtHdrFragment()
    frag_hdr.m=1 # More fragments=Yes
    frag_hdr.id=0xdc3a7b35
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='PA'
    tcp_packet.ack=0x3a347bcd
    tcp_packet.seq=0x7bcd3a34
    payload="Connection: Keep-Alive\r\nProxy-Connection: Keep-Alive\r\nContent-Length: 2131431\r\n"
    final_packet=ip_packet/frag_hdr/tcp_packet/payload
    test6_packets.append(final_packet)

    # TEST 146
    test6_ids.append("ICMP_Misc_36")
    test6_descriptions.append("IPv6/Some fragment (not first, not last) with a payload that is not multiple of 8")
        # NOTE: The absence of a reply to this test is significant and should
        #       be considered. @todo TODO
    ip_packet=build_default_ipv6(target)
    frag_hdr=IPv6ExtHdrFragment()
    frag_hdr.m=1 # More fragments=Yes
    frag_hdr.offset=803
    frag_hdr.id=0xd23a7b23
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='PA'
    tcp_packet.ack=0x3a312cd2
    tcp_packet.seq=0x3ecd3a34
    payload="Connection: Keep-Alive\r\nProxy-Connection: Keep-Alive\r\nContent-Length: 4431611\r\n"
    final_packet=ip_packet/frag_hdr/tcp_packet/payload
    test6_packets.append(final_packet)

    # TEST 147
    test6_ids.append("ICMP_Misc_37")
    test6_descriptions.append("ICMP/NSol/Dst=target/Addr=target/Flag R=1")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_NS()
    icmp_packet.R=1
    icmp_packet.code=0
    icmp_packet.tgt=target;
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 148
    test6_ids.append("ICMP_Misc_38")
    test6_descriptions.append("ICMP/NSol/Dst=target/Addr=target/Flag S=1")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_NS()
    icmp_packet.S=1
    icmp_packet.code=0
    icmp_packet.tgt=target;
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 149
    test6_ids.append("ICMP_Misc_39")
    test6_descriptions.append("ICMP/NSol/Dst=target/Addr=target/Flag O=1")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_NS()
    icmp_packet.O=1
    icmp_packet.code=0
    icmp_packet.tgt=target;
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 150
    test6_ids.append("ICMP_Misc_40")
    test6_descriptions.append("ICMP/NSol/Dst=target/Addr=target/All flags set(RSO)")
    ip_packet=build_default_ipv6(target)
    ip_packet.hlim=255
    icmp_packet=ICMPv6ND_NS()
    icmp_packet.R=1
    icmp_packet.S=1
    icmp_packet.O=1
    icmp_packet.code=0
    icmp_packet.tgt=target;
    final_packet=ip_packet/icmp_packet
    test6_packets.append(final_packet)

    # TEST 151
    test6_ids.append("TCP_Misc_1")
    test6_descriptions.append("IPv6/TCP SYN with User Timeout Option=1min)")
    ip_packet=build_default_ipv6(target)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
    tcp_packet.options=[(0x1c, '\x80\x01')] # TCP UTO with timeout=1min
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 152
    test6_ids.append("TCP_Misc_2")
    test6_descriptions.append("IPv6/TCP SYN with User Timeout Option=0sec)")
    ip_packet=build_default_ipv6(target)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
    tcp_packet.options=[(0x1c, '\x00\x00')] # Timeout=0secs
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 153
    test6_ids.append("TCP_Misc_3")
    test6_descriptions.append("IPv6/TCP SYN Authentication option)")
    ip_packet=build_default_ipv6(target)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
    tcp_packet.options=[(0x1d, '\x01\x01\x0F\x0E\x0D\x0C\x0B\x0A\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00')]
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

    # TEST 154
    test6_ids.append("TCP_Misc_4")
    test6_descriptions.append("IPv6/TCP SYN with the Space Communications Protocol Capabilities Option)")
    ip_packet=build_default_ipv6(target)
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.flags='S'
        # The option tells this to the receiver:
        #    Sender willing to operate connection in BETS mode.
        #    OK to send short form of SNACK Option.
        #    OK to send long form of SNACK Option.
        #    OK to compress TCP header
        #    Network-layer timestamps not available
        #
        # For more info, check "SPACE COMMUNICATIONS PROTOCOL SPECIFICATION (SCPS), CCSDS 714.0-B-2"
    tcp_packet.options=[(0x14, '\xF0\x01')]
    final_packet=ip_packet/tcp_packet
    test6_packets.append(final_packet)

def set_up_ipv4_tests(target):

    # TEST 0
    test4_ids.append("NMAP_OS_PROBE_TCP_0")
    test4_descriptions.append("TCP/SYN/OpenPort/NmapProbe0")
    ip_packet=build_default_ipv4(target)
    ip_packet.tos=0
    ip_packet.flags=0
    ip_packet.frag=0
    ip_packet.ttl=43
    ip_packet.id=0xdabf
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase+0
    tcp_packet.ack=tcpAck
    tcp_packet.flags='S'
    tcp_packet.options=[('WScale', 10), ('NOP', None), ('MSS',1460), ('Timestamp', (0xFFFFFFFF,0L)), ('SAckOK', '')]
    tcp_packet.window=1
    final_packet=ip_packet/tcp_packet
    test4_packets.append(final_packet)

    # TEST 1
    test4_ids.append("NMAP_OS_PROBE_TCP_1")
    test4_descriptions.append("TCP/SYN/OpenPort/NmapProbe1")
    ip_packet=build_default_ipv4(target)
    ip_packet.tos=0
    ip_packet.flags=0
    ip_packet.frag=0
    ip_packet.ttl=58
    ip_packet.id=0x2bd3
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase+1
    tcp_packet.ack=tcpAck
    tcp_packet.flags='S'
    tcp_packet.options=[('MSS', 1400), ('WScale', 0), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF,0L)), ('EOL', '')]
    tcp_packet.window=63
    final_packet=ip_packet/tcp_packet
    test4_packets.append(final_packet)

    # TEST 2
    test4_ids.append("NMAP_OS_PROBE_TCP_2")
    test4_descriptions.append("TCP/SYN/OpenPort/NmapProbe2")
    ip_packet=build_default_ipv4(target)
    ip_packet.tos=0
    ip_packet.flags=0
    ip_packet.frag=0
    ip_packet.ttl=54
    ip_packet.id=0x2777
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase+2
    tcp_packet.ack=tcpAck
    tcp_packet.flags='S'
    tcp_packet.options=[('Timestamp', (0xFFFFFFFF,0L)), ('NOP', ''), ('NOP', ''), ('WScale', 5), ('NOP', ''), ('MSS', 640)]
    tcp_packet.window=4
    final_packet=ip_packet/tcp_packet
    test4_packets.append(final_packet)

    # TEST 3
    test4_ids.append("NMAP_OS_PROBE_TCP_3")
    test4_descriptions.append("TCP/SYN/OpenPort/NmapProbe3")
    ip_packet=build_default_ipv4(target)
    ip_packet.tos=0
    ip_packet.flags=0
    ip_packet.frag=0
    ip_packet.ttl=57
    ip_packet.id=0xed5f
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase+3
    tcp_packet.ack=tcpAck
    tcp_packet.flags='S'
    tcp_packet.options=[('SAckOK', ''), ('Timestamp', (0xFFFFFFFF,0L)), ('WScale', 10),  ('EOL', '')]
    tcp_packet.window=4
    final_packet=ip_packet/tcp_packet
    test4_packets.append(final_packet)

    # TEST 4
    test4_ids.append("NMAP_OS_PROBE_TCP_4")
    test4_descriptions.append("TCP/SYN/OpenPort/NmapProbe4")
    ip_packet=build_default_ipv4(target)
    ip_packet.tos=0
    ip_packet.flags=0
    ip_packet.frag=0
    ip_packet.ttl=42
    ip_packet.id=0xda83
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase+4
    tcp_packet.ack=tcpAck
    tcp_packet.flags='S'
    tcp_packet.options=[('MSS', 536), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF,0L)), ('WScale', 10), ('EOL', '')]
    tcp_packet.window=16
    final_packet=ip_packet/tcp_packet
    test4_packets.append(final_packet)

    # TEST 5
    test4_ids.append("NMAP_OS_PROBE_TCP_5")
    test4_descriptions.append("TCP/SYN/OpenPort/NmapProbe5")
    ip_packet=build_default_ipv4(target)
    ip_packet.tos=0
    ip_packet.flags=0
    ip_packet.frag=0
    ip_packet.ttl=40
    ip_packet.id=0x3fa8
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase+5
    tcp_packet.ack=tcpAck
    tcp_packet.flags='S'
    tcp_packet.options=[('MSS', 265), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF,0L))]
    tcp_packet.window=512
    final_packet=ip_packet/tcp_packet
    test4_packets.append(final_packet)

    # TEST 6 ECN
    test4_ids.append("NMAP_OS_PROBE_TCP_6")
    test4_descriptions.append("TCP/CWR|ECN|SYN/OpenPort/NmapProbe6")
    ip_packet=build_default_ipv4(target)
    ip_packet.tos=0
    ip_packet.flags=0
    ip_packet.frag=0
    ip_packet.ttl=42
    ip_packet.id=0xa5f8
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase
    tcp_packet.ack=0
    tcp_packet.urgptr=0xF7F5
    tcp_packet.flags='CES'
    tcp_packet.options=[('WScale', 10), ('NOP', ''), ('MSS', 1460), ('SAckOK', ''), ('NOP', ''), ('NOP', '')]
    tcp_packet.window=3
    final_packet=ip_packet/tcp_packet
    test4_packets.append(final_packet)

    # TEST 7 (T2)
    test4_ids.append("NMAP_OS_PROBE_TCP_7")
    test4_descriptions.append("TCP/NullFlags/OpenPort/NmapProbe7")
    ip_packet=build_default_ipv4(target)
    ip_packet.tos=0
    ip_packet.flags=0x02 # Don't Fragment=1
    ip_packet.frag=0
    ip_packet.ttl=59
    ip_packet.id=0x1044
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase
    tcp_packet.ack=tcpAck
    tcp_packet.urgptr=0
    tcp_packet.flags=''
    tcp_packet.options=[('WScale', 10), ('NOP', ''), ('MSS', 265), ('Timestamp', (0xFFFFFFFF,0L)), ('SAckOK', '')]
    tcp_packet.window=128
    final_packet=ip_packet/tcp_packet
    test4_packets.append(final_packet)

    # TEST 8 (T3)
    test4_ids.append("NMAP_OS_PROBE_TCP_8")
    test4_descriptions.append("TCP/SYN|FIN|URG|PSH/OpenPort/NmapProbe8")
    ip_packet=build_default_ipv4(target)
    ip_packet.tos=0
    ip_packet.flags=0
    ip_packet.frag=0
    ip_packet.ttl=46
    ip_packet.id=0xfc92
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase
    tcp_packet.ack=tcpAck
    tcp_packet.urgptr=0
    tcp_packet.flags='SFUP'
    tcp_packet.options=[('WScale', 10), ('NOP', ''), ('MSS', 265), ('Timestamp', (0xFFFFFFFF,0L)), ('SAckOK', '')]
    tcp_packet.window=256
    final_packet=ip_packet/tcp_packet
    test4_packets.append(final_packet)

    # TEST 9 (T4)
    test4_ids.append("NMAP_OS_PROBE_TCP_9")
    test4_descriptions.append("TCP/ACK/OpenPort/NmapProbe9")
    ip_packet=build_default_ipv4(target)
    ip_packet.tos=0
    ip_packet.flags=0x02 # Don't Fragment=1
    ip_packet.frag=0
    ip_packet.ttl=46
    ip_packet.id=0x33ef
    tcp_packet=build_default_tcp()
    tcp_packet.dport=open_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase
    tcp_packet.ack=tcpAck
    tcp_packet.urgptr=0
    tcp_packet.flags='A'
    tcp_packet.options=[('WScale', 10), ('NOP', ''), ('MSS', 265), ('Timestamp', (0xFFFFFFFF,0L)), ('SAckOK', '')]
    tcp_packet.window=1024
    final_packet=ip_packet/tcp_packet
    test4_packets.append(final_packet)

    # TEST 10 (T5)
    test4_ids.append("NMAP_OS_PROBE_TCP_10")
    test4_descriptions.append("TCP/SYN/ClosedPort/NmapProbe10")
    ip_packet=build_default_ipv4(target)
    ip_packet.tos=0
    ip_packet.flags=0
    ip_packet.frag=0
    ip_packet.ttl=45
    ip_packet.id=0xc263
    tcp_packet=build_default_tcp()
    tcp_packet.dport=closed_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase
    tcp_packet.ack=tcpAck
    tcp_packet.urgptr=0
    tcp_packet.flags='S'
    tcp_packet.options=[('WScale', 10), ('NOP', ''), ('MSS', 265), ('Timestamp', (0xFFFFFFFF,0L)), ('SAckOK', '')]
    tcp_packet.window=31337
    final_packet=ip_packet/tcp_packet
    test4_packets.append(final_packet)

    # TEST 11 (T6)
    test4_ids.append("NMAP_OS_PROBE_TCP_11")
    test4_descriptions.append("TCP/ACK/ClosedPort/NmapProbe11")
    ip_packet=build_default_ipv4(target)
    ip_packet.tos=0
    ip_packet.flags=0x02 # Don't Fragment=1
    ip_packet.frag=0
    ip_packet.ttl=57
    ip_packet.id=0xbf42
    tcp_packet=build_default_tcp()
    tcp_packet.dport=closed_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase
    tcp_packet.ack=tcpAck
    tcp_packet.urgptr=0
    tcp_packet.flags='A'
    tcp_packet.options=[('WScale', 10), ('NOP', ''), ('MSS', 265), ('Timestamp', (0xFFFFFFFF,0L)), ('SAckOK', '')]
    tcp_packet.window=32768
    final_packet=ip_packet/tcp_packet
    test4_packets.append(final_packet)

    # TEST 12 (T7)
    test4_ids.append("NMAP_OS_PROBE_TCP_12")
    test4_descriptions.append("TCP/FIN|PSH|URG/ClosedPort/NmapProbe12")
    ip_packet=build_default_ipv4(target)
    ip_packet.tos=0
    ip_packet.flags=0
    ip_packet.frag=0
    ip_packet.ttl=47
    ip_packet.id=0xf0ba
    tcp_packet=build_default_tcp()
    tcp_packet.dport=closed_port_g
    tcp_packet.sport=get_source_port_number()
    tcp_packet.seq=tcpSeqBase
    tcp_packet.ack=tcpAck
    tcp_packet.urgptr=0
    tcp_packet.flags='FPU'
    tcp_packet.options=[('WScale', 15), ('NOP', ''), ('MSS', 265), ('Timestamp', (0xFFFFFFFF,0L)), ('SAckOK', '')]
    tcp_packet.window=65535
    final_packet=ip_packet/tcp_packet
    test4_packets.append(final_packet)

    # TEST 13 (IE 1)
    test4_ids.append("NMAP_OS_PROBE_ICMP_1")
    test4_descriptions.append("ICMP/EchoRequest/TOS=0/NmapProbe13")
    ip_packet=build_default_ipv4(target)
    ip_packet.tos=0
    ip_packet.flags=0x02 # Don't Fragment=1
    ip_packet.frag=0
    ip_packet.ttl=42
    ip_packet.id=0xa666
    icmp_packet=build_default_icmpv4()
    icmp_packet.code=9
    icmp_packet.seq=295
    icmp_packet.id=0xABCD
    icmp_packet.data='\x00'*120
    final_packet=ip_packet/icmp_packet
    test4_packets.append(final_packet)

    # TEST 14 (IE 2)
    test4_ids.append("NMAP_OS_PROBE_ICMP_2")
    test4_descriptions.append("ICMP/EchoRequest/TOS=4/NmapProbe14")
    ip_packet=build_default_ipv4(target)
    ip_packet.tos=0x04
    ip_packet.flags=0
    ip_packet.frag=0
    ip_packet.ttl=39
    ip_packet.id=0xb785
    icmp_packet=build_default_icmpv4()
    icmp_packet.code=9
    icmp_packet.seq=295+1
    icmp_packet.id=0xABCD+1
    icmp_packet.data='\x00'*150
    final_packet=ip_packet/icmp_packet
    test4_packets.append(final_packet)

    # TEST 15 (U1)
    test4_ids.append("NMAP_OS_PROBE_UDP")
    test4_descriptions.append("ICMP/EchoRequest/TClass=4/NmapProbe14")
    ip_packet=build_default_ipv4(target)
    ip_packet.tos=0
    ip_packet.flags=0
    ip_packet.frag=0
    ip_packet.ttl=58
    ip_packet.id=0x1042
    udp_packet=build_default_udp()
    udp_packet.dport=closed_port_g
    udp_packet.sport=45535
    payload='\x43'*300
    final_packet=ip_packet/udp_packet/payload
    test4_packets.append(final_packet)

def run_all_tests(target6, target4, from_test, to_test):

    # Run the tests
    if target6!=None :
        for i in range(from_test, min( len(test6_ids), to_test) ) :
            res=run_test(i, test6_ids[i], test6_descriptions[i], test6_packets[i], 6)
            test6_replies.append(res)
            time.sleep(inter_test_delay_g) # Wait for a bit before the next test
    if target4!=None:
        if from_test>=0 and from_test<=len(test4_ids) :
            for i in range(from_test, min( len(test4_ids), to_test)) :
                res=run_test(i, test4_ids[i], test4_descriptions[i], test4_packets[i], 4)
                test4_replies.append(res)
                time.sleep(inter_test_delay_g) # Wait for a bit before the next test

def run_timing_dependent_tests() :
    global inter_packet_delay_g

    # Select the appropriate packets
    packets4=test4_packets[0:6]
    packets6=test6_packets[0:6]

    # Set the interpacket delay to 100ms
    ipdbak=inter_packet_delay_g
    inter_packet_delay_g=0.1 # 100ms

    if target_host6_g!=None :
        run_test_multiple(1000, "IPv6_NmapProbes_100ms", "Time dependent IPv6 probes", packets6, 6)
    if target_host4_g!=None :
        run_test_multiple(2000, "IPv4_NmapProbes_100ms", "Time dependent IPv4 probes", packets4, 4)

    # Restore original inter packet delay
    inter_packet_delay_g=ipdbak

# This function builds a boolean vector from the test6_replies list, which contains
# an IPv6 object if a response was received or the None object otherwise. The
# result vector is stored in the global result_vector6 list.
def build_result_vector6():
    for i in range(0, len(test6_replies)) :
        if test6_replies[i]==None :
            result_vector6.append(0)
        else :
            result_vector6.append(1)

# This function builds a boolean vector from the test4_replies list, which contains
# an IPv4 object if a response was received or the None object otherwise. The
# result vector is stored in the global result_vector6 list.
def build_result_vector4():
    for i in range(0, len(test4_replies)) :
        if test4_replies[i]==None :
            result_vector4.append(0)
        else :
            result_vector4.append(1)

def del_scapy_routes():
    for i in range(0, len(conf.route6.routes) ):
        conf.route6.routes.pop()

def get_interface_src_ipv6(interface_name):
    for i in range(0, len(conf.route6.routes) ):
        if conf.route6.routes[i][3] == interface_name :
            if type(conf.route6.routes[i][4])==list :
                return conf.route6.routes[i][4][0]
            else :
                return conf.route6.routes[i][4]
    return None

def get_target_mac_address(target, interface):
    try:
        target_tmp = inet_pton(AF_INET6, target)
    except socket.error:
        print "inet_pton() failed on get_target_mac_address() - sigh."
    
    byte_13 = hex(unpack('B', target_tmp[13])[0])[2:]
    byte_14 = hex(unpack('B', target_tmp[14])[0])[2:]
    byte_15 = hex(unpack('B', target_tmp[15])[0])[2:]
    
    # RFC-2464, 7. Address Mapping -- Multicast
    eth_dst_address = '33:33:ff:' + byte_13 + ':' + byte_14 + ':' + byte_15
    eth_hdr = Ether(dst = eth_dst_address)
    
    # RFC-4861, 4.3. Neighbor Solicitation Message Format
    # RFC-4291, 2.7.1. Pre-Defined Multicast Addresses - Solicited-Node Address:  FF02:0:0:0:0:1:FFXX:XXXX
    ipv6_dst_address = 'ff02::1:ff' + byte_13 + ':' + byte_14 + byte_15
    ip_hdr = IPv6(dst = ipv6_dst_address)
    icmp_hdr = ICMPv6ND_NS(tgt=target)
    my_mac_address = get_if_hwaddr(interface)
    icmp_ns_src_lladdr = ICMPv6NDOptSrcLLAddr(lladdr = my_mac_address)
    final_packet=eth_hdr/ip_hdr/icmp_hdr/icmp_ns_src_lladdr
    ans, unans=srp(final_packet, iface=interface, verbose=0, timeout=capture_timeout_g, retry=packet_retries_g)
    if ans:
        if len(ans[0]) > 1 :
            if type(ans[0][1][0])==scapy.layers.l2.Ether :
                if type(ans[0][1][0].payload) == scapy.layers.inet6.IPv6 :
                    if type(ans[0][1][0].payload.payload)==scapy.layers.inet6.ICMPv6ND_NA :
                        return ans[0][1][0].src
    return None
def start_clock():
    global start_time_g
    start_time_g  = time.time()

def get_time_elapsed():
    now = time.time()
    return now-start_time_g

# Command line argument parsing
def argparser():
    global first_test_g, last_test_g, capture_timeout_g, packet_retries_g, interface_g, debug_g, inter_test_delay_g, send_eth_g, target_host6_g, target_host4_g, target_os_details_g, interactive_mode_g, open_port_g, closed_port_g, target_mac_addr_g, do_connectivity_test_g
    opts, args = getopt.gnu_getopt(sys.argv[1:], "h", ["help", "ot=", "ct=", "from=", "to=", "timeout=", "retries=", "test=", "interface=", "debug", "delay=", "send-eth", "send-ip", "addr4=", "noports", "interactive", "gwmac=", "force"])
    for o, a in opts:
        if o == "--ot":
            open_port_g = int(a)
        elif o == "--ct":
            closed_port_g = int(a)
        elif o == "-h" or o == "--help":
            print_usage()
            sys.exit()
        elif o == "--from":
            first_test_g=int(a)
        elif o == "--to":
            last_test_g=int(a)
        elif o == "--test":
            first_test_g=int(a)
            last_test_g=int(a)
        elif o == "--timeout":
            capture_timeout_g=int(a)
        elif o == "--retries":
            packet_retries_g=int(a)
        elif o == "--interface" :
            interface_g=str(a)
        elif o == "--debug" :
            debug_g=True
        elif o == "--delay" :
            inter_test_delay_g=int(a)
        elif o == "--send-eth" :
            send_eth_g=True
        elif o == "--send-ip" :
            send_eth_g=False
        elif o == "--addr4":
            target_host4_g=str(a)
        elif o == "--noports":
            open_port_g=DEFAULT_OPEN_PORT_IN_TARGET
            closed_port_g=DEFAULT_CLOSED_PORT_IN_TARGET
        elif o == "--interactive":
            interactive_mode_g=True
        elif o == "--gwmac":
            target_mac_addr_g=str(a)
        elif o == "--force":
            do_connectivity_test_g=False
        else :
            exit(1)

    # PARAMETER VALIDATION

    # Check we have enough args
    if len(sys.argv)<2 :
        print_usage()
        exit(1)

    # Now check if we are root
    if not os.geteuid() == 0 :
        sys.exit('ERROR: You must be root to run this program')

    # Check if interactive mode was requested
    if interactive_mode_g==True:
        interactive_mode()
    else :
        target_host6_g=args[0] # Store target host

    # Check that we have the necessary port numbers
    if open_port_g==None :
        return "ERROR: You need to supply a target's open port or use --noports explicitly"
    if closed_port_g==None :
        closed_port_g=DEFAULT_CLOSED_PORT_IN_TARGET


    # If user did not specify --send-eth or --send-ip, make a choice
    if send_eth_g==None :
        # If target is link local, send at the ethernet level
        if target_host6_g.lower().startswith("fe80") :
            send_eth_g=True
        elif target_host6_g == "::1" or target_host6_g=='localhost' :
            send_eth_g=False
            conf.L3socket=L3RawSocket6
        elif interface_g!=None :
            send_eth_g=True
        else :
            send_eth_g=False

    # Check that we have an interface name if we need one
    if send_eth_g==True and interface_g==None :
        return "ERROR: Interface name needed."
    elif send_eth_g==True and interface_g!=None:
        del_scapy_routes()
        mytarget=target_host6_g+"/128"
        conf.route6.add(dst=mytarget, gw=mytarget, dev=interface_g)
    elif send_eth_g==False and interface_g==None :
        interface_g=conf.iface

    return None

def interactive_mode():
    global interface_g, send_eth_g, target_host6_g, target_host4_g, target_os_details_g, open_port_g, closed_port_g
    print "[+] First of all, we need you to provide some details:"

    # Request target's IPv6 Address
    target_host6_g=ask_interactive_target_addr6()
    if target_host6_g.startswith("fe80::") :
        interface_g=ask_interactive_interface()
        send_eth_g=True
    else :
        send_eth_g=False

    # Request target's IPv4 address
    ip4=ask_interactive_target_addr4()
    if ip4!=None :
        target_host4_g=ip4

    # Request open and closed ports
    open_port_g=ask_interactive_openport()
    closed_port_g=ask_interactive_closedport()

def ask_interactive_target_addr6():
    while True:
        addr=raw_input("  |_ Target's IPv6 address: ")
        if addr!=None and len(addr)>0 :
            break
    return addr

def ask_interactive_target_addr4():
    addr=raw_input("  |_ Target's IP (version 4) address [Press ENTER to skip IPv4]: ")
    if addr==None or len(addr)==0 :
        return None
    else :
        return addr

def ask_interactive_interface():
    while True:
        print "  |_ Supplied IPv6 address is link-local. Please specify which"
        iface=raw_input("     network interface should be used: ")
        if iface!=None and len(iface)>0 :
            break
    return iface

def ask_interactive_openport():
    while True:
        port=raw_input("  |_ OPEN port in target [Press ENTER to default to "+str(DEFAULT_OPEN_PORT_IN_TARGET)+"]: ")
        if port==None or len(port)==0 :
            return DEFAULT_OPEN_PORT_IN_TARGET
        elif port.isdigit() :
            return int(port)

def ask_interactive_closedport():
    while True:
        port=raw_input("  |_ CLOSED port in target [Press ENTER to default to "+str(DEFAULT_CLOSED_PORT_IN_TARGET)+"]: ")
        if port==None or len(port)==0 :
            return DEFAULT_CLOSED_PORT_IN_TARGET
        elif port.isdigit() :
            return int(port)

def ask_interactive_osdetails():

    os= ( ("Linux",  ("CentOs", "Debian", "Fedora", "Gentoo", "Mandriva", "Mint", "Redhat", "Slackware", "Suse", "Ubuntu", "Other") ),
          ("BSD",    ("DragonFlyBSD", "FreeBSD", "NetBSD", "OpenBSD", "PC-BSD", "Other") ),
          ("Windows",("Windows XP", "Windows Vista", "Windows 7", "2003 Server", "2008 Server", "Other") ),
          ("MacOS X",("Puma", "Jaguar", "Panther", "Tiger", "Leopard", "Snow Leopard", "Lion", "Other") ),
          ("Solaris",("Sun Solaris", "OpenSolaris", "OpenIndiana", "SchilliX", "Other") ),
          ("Other",  ("Router", "Firewall", "Switch", "Proxy", "Other") )
        )

    while True :

        # Request OS type
        print "==================TARGET OS TYPES =================="
        for i in range(0, len(os)):
            print "    " + str(i) + ") " + os[i][0]
        while True:
            os_type=raw_input("[+] Please enter the target's OS type: ")
            if len(os_type)<=0 or os_type.isdigit()==False:
                os_type=-1
            else :
                os_type=int(os_type)
            if os_type>=0 and os_type<len(os) :
                break

        # Request OS sub-type
        print "================TARGET OS SUB-TYPES ================"
        for i in range(0, len(os[os_type][1])):
            print "    " + str(i) + ") " + os[os_type][1][i]
        while True:
            os_subtype=raw_input("[+] Please enter the target's OS sub type: ")
            if len(os_subtype)<=0 or os_subtype.isdigit()==False:
                os_subtype=-1
            else :
                os_subtype=int(os_subtype)
            if os_subtype>=0 and os_subtype<len(os[os_type][1]) :
                break
        print "=================TARGET OS VERSION ================="
        if os[os_type][1][os_subtype]=="Other" :
            if os[os_type][0] == "Other" :
                os_version=raw_input("[+] Please enter Vendor, OS name and OS version (Eg: Cisco Catalyst 4500 12.2SG): ")
            else :
                os_version=raw_input("[+] Please enter OS sub-type and OS version (eg: IOS 12.2SB): ")
        else :
            if os[os_type][0] == "Windows" :
                os_version=raw_input("[+] Please enter Windows version (Eg: SP2, Enterprise...): ")
            elif os[os_type][0] == "Linux" :
                os_version=raw_input("[+] Please enter kernel's version (Eg: 2.6.32): ")
            elif os[os_type][0] == "BSD" :
                os_version=raw_input("[+] Please enter BSD's version (Eg: 8.1): ")
            elif os[os_type][0] == "Solaris" :
                os_version=raw_input("[+] Please enter Solaris' version (Eg: 2009.06): ")
            elif os[os_type][0] == "MacOS X" :
                os_version=raw_input("[+] Please enter the output of 'uname -a': ")
            else:
                os_version=raw_input("[+] Please enter any version information about the target OS: ")

        print "[+] You have entered the following information:"
        print " |_ OS Type:    " + os[os_type][0]
        print " |_ OS Subtype: " + os[os_type][1][os_subtype]
        print " |_ OS Version: " + os_version
        final=raw_input("[+] [+] Is the information correct? [Y/n]: ")

        if final!="N" and final!="n" :
            break

    result=(os[os_type][0], os[os_type][1][os_subtype], os_version)
    return result

def write_results_file():
    output_file = open(output_file_name_g, "w")

    # Write initial header
    header=get_results_file_header()
    for line in header :
        output_file.write(line)
        output_file.write("\r\n")

    # Write OS details request if we don't have OS info
    if target_os_details_g==None:
        req=get_results_file_osrequest()
        for line in req :
            output_file.write(line)
            output_file.write("\r\n")

    # Write the actual results
    for line in output_data:
        output_file.write(line)
        output_file.write("\r\n")
    output_file.close()

# Dummy signal handler to prevent Python from displaying a bunch of stack info
# when users press CTRL-C
def signal_handler(signal, frame):
        print "\nQUITTING!"
        sys.exit(0)

def test_connectivity():
    result6=False
    result4=True

    print "[+] PERFORMING CONNECTIVITY TEST... "

    if target_host6_g!=None :
        # Test we have IPv6 connectivity: send TCP SYN and check for responses
        ip_packet1=build_default_ipv6(target_host6_g)
        ip_packet2=build_default_ipv6(target_host6_g)
        tcp_packet=build_default_tcp()
        tcp_packet.dport=open_port_g
        tcp_packet.sport=23456
        tcp_packet.seq=217342
        tcp_packet.ack=0
        tcp_packet.flags='S'
        icmp_packet=ICMPv6EchoRequest()
        final_packets=[ip_packet1/tcp_packet, ip_packet2/icmp_packet]
        # Send the packet and listen for responses
        sys.stdout.write("[+] IPv6 connectivity: ")
        sys.stdout.flush()
        if send_eth_g == True:
            response6=send_and_receive_eth(final_packets, verbosity=0)
        else:
            response6=send_and_receive(final_packets, verbosity=0)
        if response6 :
            print "YES"
            result6=True
        else :
            print "NO"
            result6=False

    if target_host4_g!=None :

        # Special case: localhost needs some adjustments
        if send_eth_g==False and (target_host4_g=='127.0.0.1' or target_host4_g=='localhost') :
            tmp=conf.L3socket
            conf.L3socket = L3RawSocket
        
        # Test we have IPv4 connectivity: send TCP SYN and check for responses
        ip_packet1=build_default_ipv4(target_host4_g)
        ip_packet2=build_default_ipv4(target_host4_g)
        tcp_packet=build_default_tcp()
        tcp_packet.dport=open_port_g
        tcp_packet.sport=23456
        tcp_packet.seq=217342
        tcp_packet.ack=0
        tcp_packet.flags='S'
        icmp_packet=ICMP(type=8)
        final_packets=[ip_packet1/tcp_packet, ip_packet2/icmp_packet]
        # Send the packet and listen for responses
        sys.stdout.write("[+] IPv4 connectivity: ")
        sys.stdout.flush()
        if send_eth_g == True:
            response4=send_and_receive_eth(final_packets, verbosity=0)
        else:
            response4=send_and_receive(final_packets, verbosity=0)
        if response4 :
            print "YES"
            result4=True
        else :
            print "NO"
            result4=False

        # Restore original L3 socket
        if send_eth_g==False and (target_host4_g=='127.0.0.1' or target_host4_g=='localhost') :
            conf.L3socket=tmp

    # If we got responses -> we have connectivity -> test passed
    if (result6==True and result4==True) :
        return True
    # One or both (IPv4 an IPv6) tests failed -> test not passed
    else :
        print_debug_info()
        if result6==True and result4==False :
            print "ERROR: It seems that you don't have IPv4 connectivity with the target. "
        elif result6==False and result4==True :
            print "ERROR: It seems that you don't have IPv6 connectivity with the target. "
        else :
            print "ERROR: It seems that you don't have IPv6 and IPv4 connectivity with the target. "
        print "Please check the information displayed above for any configuration"
        print "error. You may want to force the script to send packets at the "
        if(send_eth_g==True) :
            print "IP level (instead of the Ethernet level), passing --send-ip"
        else :
            print "Ethernet level (instead of the IP level), passing --send-eth"
        print "If you are sure your configuration is correct and you wish to"
        print "skip this connectivity test, please run the script again passing"
        print "the parameter --force"

        return False


def main():

    global target_os_details_g, target_mac_addr_g, source_ipv6_addr_g

    # Start clock
    start_clock()

    # Parse command line parameters
    res=argparser()
    if res != None :
        print res
        exit(1)

    # Print welcome banner
    print_welcome_banner()

    # If we are sending at the ethernet level, get some details
    if send_eth_g==True and target_mac_addr_g==None:
        print "[+] Resolving target's MAC address"

        # Obtain target's MAC address
        mac=get_target_mac_address(target_host6_g, interface_g)
        if mac == None:
            print "ERROR: Could not resolve target's MAC address"
            exit(1)
        else :
            target_mac_addr_g=mac
            print "[+] "+ target_host6_g + " is at " + target_mac_addr_g

    if send_eth_g==True:

        # Obtain source IPv6 address
        ipaddr=get_interface_src_ipv6(interface_g)
        if ipaddr== None:
            print "ERROR: Could not determine IPv6 address of interface " + str(interface_g)
            exit(1)
        else :
            source_ipv6_addr_g=ipaddr

    # Prepare all test packets
    if target_host6_g!=None :
        set_up_ipv6_tests(target_host6_g)
    if target_host6_g!=None :
        set_up_ipv4_tests(target_host4_g)

    # First of all, perform a connectivity test, to see if we are all set up
    # for the OS probes.
    if do_connectivity_test_g==True :
        if test_connectivity()==False :
            exit(1)

    # Run main the tests
    run_all_tests(target_host6_g, target_host4_g, first_test_g, last_test_g+1)

    # Run time dependent tests only when all others are requested
    if first_test_g==0 and last_test_g> len(test6_ids) :
        run_timing_dependent_tests() # Nmap OS probes that are sent 100ms apart

    # Build result vectors
    build_result_vector6()
    build_result_vector4()

    # Request target's OS details
    if interactive_mode_g==True :
        target_os_details_g=ask_interactive_osdetails()

    # If debug mode is enabled, print some debugging info
    if debug_g==True :
        print_debug_info()

    # Print test results
    print_test_results()

    # Ok, now that we are done, create an output file to store relevant info.
    write_results_file()

# ENTRY EXECUTION POINT
signal.signal(signal.SIGINT, signal_handler)
main()
