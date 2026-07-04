#
# ethersrv-linux makefile for Linux (GCC)
# http://etherdfs.sourceforge.net
#
# Copyright (C) 2017, 2018 Mateusz Viste
#

CFLAGS = -O2 -Wall -std=gnu89 -pedantic -Wextra -s -Wno-long-long -Wno-variadic-macros -Wformat-security

# Version is derived from git tags (git describe) unless VERSION is passed in
# (builddocker.sh / the Dockerfile pass it explicitly). Never hardcoded.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo unknown)
CFLAGS += -DPVER=\"$(VERSION)\"

LDFLAGS = -lpcap

CC = gcc

ethersrv: ethersrv.c fs.c fs.h lock.c lock.h debug.h
	$(CC) ethersrv.c fs.c lock.c -o ethersrv $(CFLAGS) $(LDFLAGS)

clean:
	rm -f ethersrv *.o
