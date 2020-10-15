PREFIX      ?= /usr/local
HELPER_PATH  = $(PREFIX)/lib/afl
BIN_PATH     = $(PREFIX)/bin

VERSION     = $(shell grep '^\#define VERSION ' ../config.h | cut -d '"' -f2)

CXXFLAGS    ?= -O3 -funroll-loops -std=c++17
CXXFLAGS    += -Wall -Werror -D_FORTIFY_SOURCE=2 -Wno-pointer-sign \
               -DVERSION=\"$(VERSION)\" -Wno-variadic-macros

LDFLAGS     ?= -lpthread

PROGS = ../afl-blackbox-watchdog

all: $(PROGS)

../afl-blackbox-watchdog: Watchdog.cpp ThreadPool.h
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

.NOTPARALLEL: clean

clean:
	rm -f $(PROGS)