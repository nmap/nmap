CXX ?= g++
CC ?= gcc
CFLAGS = -Wall -Wconversion -O3 -fPIC
LIBS = blas/blas.a
#LIBS = -lblas
SHVER = 5
AR = ar
RANLIB = ranlib
OS = $(shell uname)
ifeq ($(OS),Darwin)
	SHARED_LIB_FLAG = -dynamiclib -Wl,-install_name,liblinear.so.$(SHVER)
else
	SHARED_LIB_FLAG = -shared -Wl,-soname,liblinear.so.$(SHVER)
endif

all: train predict

lib: linear.o newton.o blas/blas.a
	$(CXX) $(SHARED_LIB_FLAG) linear.o newton.o blas/blas.a -o liblinear.so.$(SHVER)

liblinear.a: linear.o newton.o blas/blas.a
	$(AR) rcv liblinear.a linear.o newton.o blas/*.o
	$(RANLIB) liblinear.a

train: newton.o linear.o train.c blas/blas.a
	$(CXX) $(CFLAGS) -o train train.c newton.o linear.o $(LIBS)

predict: newton.o linear.o predict.c blas/blas.a
	$(CXX) $(CFLAGS) -o predict predict.c newton.o linear.o $(LIBS)

newton.o: newton.cpp newton.h
	$(CXX) $(CFLAGS) -c -o newton.o newton.cpp

linear.o: linear.cpp linear.h
	$(CXX) $(CFLAGS) -c -o linear.o linear.cpp

blas/blas.a: blas/*.c blas/*.h
	make -C blas OPTFLAGS='$(CFLAGS)' CC='$(CC)';

clean:
	make -C blas clean
	make -C matlab clean
	rm -f *~ newton.o linear.o train predict liblinear.so.$(SHVER)
