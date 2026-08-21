CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -Werror -std=c11 -fPIC -D_POSIX_C_SOURCE=200809L -I.
OBJS    = dafsa.o dafsa_state.o dafsa_core.o dafsa_persist.o dafsa_view.o \
          dafsa_crc32.o dafsa_wal.o dafsa_build.o dafsa_rank.o dafsa_view_rank.o

.PHONY: all clean
all: libdafsa.so

libdafsa.so: $(OBJS)
	$(CC) -shared -fPIC $(CFLAGS) -o $@ $(OBJS)

%.o: %.c dafsa.h dafsa_internal.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) libdafsa.so
