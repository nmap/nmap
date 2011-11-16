CC = gcc
CCOPT =
DEFS = 
NBASEDIR=../../nbase
NSOCKLIB=../src/libnsock.a
NBASELIB=$(NBASEDIR)/libnbase.a
OPENSSLLIB=-lssl -lpcap -lcrypto
INCLS = -I../include -I$(NBASEDIR)
CFLAGS =  -I/usr/local/include -Wall -g $(CCOPT) $(DEFS) $(INCLS)
LDFLAGS =
PCAPBASEDIR=../../libpcap
PCAPLIB=$(PCAPBASEDIR)/libpcap.a
RM = rm -f

TARGETS = nsock_test_timers nsock_telnet

all: $(TARGETS)

nsock_telnet: nsock_telnet.o $(NSOCKLIB)
	$(CC) -o $@ $(CFLAGS) nsock_telnet.o $(NSOCKLIB) $(NBASELIB) $(OPENSSLLIB)

nsock_test_timers: nsock_test_timers.o $(NSOCKLIB)
	$(CC) -o $@ $(CFLAGS) nsock_test_timers.o $(NSOCKLIB) $(NBASELIB) $(OPENSSLLIB)

nsock_pcap: nsock_pcap.o $(NSOCKLIB) $(PCAPLIB)
	$(CC) -o $@ $(CFLAGS) nsock_pcap.o $(NSOCKLIB) $(NBASELIB) $(OPENSSLLIB) $(PCAPLIB)

clean:
	$(RM) *.o $(TARGETS)
