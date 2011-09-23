CXX ?= g++
CC ?= gcc
CFLAGS = -Wall -Wconversion -O3 -fPIC
LIBS = blas/blas.a
SHVER = 1
AR = ar
RANLIB = ranlib
#LIBS = -lblas

all: train predict

lib: linear.o tron.o blas/blas.a
	$(CXX) -shared -dynamiclib linear.o tron.o blas/blas.a -o liblinear.so.$(SHVER)

liblinear.a: linear.o tron.o blas/blas.a
	$(AR) rcv liblinear.a linear.o tron.o blas/*.o
	$(RANLIB) liblinear.a

train: tron.o linear.o train.c blas/blas.a
	$(CXX) $(CFLAGS) -o train train.c tron.o linear.o $(LIBS)

predict: tron.o linear.o predict.c blas/blas.a
	$(CXX) $(CFLAGS) -o predict predict.c tron.o linear.o $(LIBS)

tron.o: tron.cpp tron.h
	$(CXX) $(CFLAGS) -c -o tron.o tron.cpp

linear.o: linear.cpp linear.h
	$(CXX) $(CFLAGS) -c -o linear.o linear.cpp

blas/blas.a:
	cd blas; $(MAKE) OPTFLAGS='$(CFLAGS)' CC='$(CC)';

clean:
	cd blas;	$(MAKE) clean
	rm -f *~ tron.o linear.o train predict liblinear.so.$(SHVER) liblinear.a
