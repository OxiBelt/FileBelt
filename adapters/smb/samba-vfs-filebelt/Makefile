# SPDX-License-Identifier: GPL-3.0-or-later

# Samba headers and ABI are supplied by the pinned 4.24.6 build environment.
SAMBA_VERSION ?= 4.24.6
CC ?= cc
CFLAGS ?= -O2 -fPIC -Wall -Wextra -Werror
SAMBA_CFLAGS ?= $(shell pkg-config --cflags samba 2>/dev/null)
SAMBA_LDFLAGS ?= $(shell pkg-config --libs samba 2>/dev/null)

all: vfs_filebelt.so

vfs_filebelt.so: source/vfs_filebelt.c
	@test "$(SAMBA_VERSION)" = "4.24.6"
	$(CC) $(CFLAGS) $(SAMBA_CFLAGS) -shared -o $@ $< $(SAMBA_LDFLAGS)

clean:
	rm -f vfs_filebelt.so
