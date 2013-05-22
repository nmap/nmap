#
# nsock regression test suite
# Same license as nmap -- see http://nmap.org/book/man-legal.html
##

NBASEDIR=../../nbase
NSOCKLIB=../src/libnsock.a
NBASELIB=$(NBASEDIR)/libnbase.a

CC 	= gcc
CFLAGS	= -Wall -O0 -ggdb -I../include/ -I$(NBASEDIR)
LDFLAGS	= -lssl -lpcap -lcrypto

SRC = tests_main.c \
      basic.c \
      timer.c \
      logs.c \
      connect.c \
      ghlists.c

OBJ = $(SRC:.c=.o)

EXE = tests_main

all: $(SRC) $(EXE)

$(EXE): $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) -o $@ $(NSOCKLIB) $(NBASELIB)

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	$(RM) $(OBJ) $(EXE)

rebuild: clean $(EXE)

.PHONY: clean rebuild
