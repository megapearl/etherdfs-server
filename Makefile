#
# ethersrv-linux makefile for Linux (GCC)
# http://etherdfs.sourceforge.net
#
# Copyright (C) 2017, 2018 Mateusz Viste
#

CFLAGS = -O2 -Wall -std=gnu89 -pedantic -Wextra -s -Wno-long-long -Wno-variadic-macros -Wformat-security

ifdef VERSION
CFLAGS += -DPVER=\"$(VERSION)\"
endif

LDFLAGS = -lpcap

CC = gcc

ethersrv: ethersrv.c fs.c fs.h lock.c lock.h debug.h
	$(CC) ethersrv.c fs.c lock.c -o ethersrv $(CFLAGS) $(LDFLAGS)

clean:
	rm -f ethersrv *.o
