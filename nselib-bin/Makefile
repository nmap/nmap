PLATFORM=powerpc-apple-darwin9.1.0

CC = gcc
CXX = g++
CCOPT = 
DBGFLAGS = 


SHTOOL = ../shtool
INSTALL = $(SHTOOL) install 
 
LIBTOOL= ./libtool
LTFLAGS = --tag=CC --silent

all: bit.so

bit.so: bit.c ./../ltmain.sh
	$(LIBTOOL) $(LTFLAGS) --mode=compile $(CC) -I../liblua/ $(CFLAGS) -c bit.c
	$(LIBTOOL) $(LTFLAGS) --mode=link $(CC) -avoid-version -module -rpath /usr/local/lib -o bit.la bit.lo
	mv .libs/bit.so bit.so

clean: 
	rm -f bit.so *.la *.lo
	rm -rf .libs

distclean: clean
	rm -f Makefile config.log config.status libtool 
