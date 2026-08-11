# SPDX-License-Identifier: LGPL-3.0-or-later

CC ?= cc
CFLAGS ?= -O2 -fPIC -Wall -Wextra -Werror -Wconversion -Wformat=2
GANESHA_SOURCE ?=
GANESHA_BUILD ?=
NTIRPC_INCLUDE ?= /usr/include/ntirpc
ABI_CPPFLAGS = -DFILEBELT_GANESHA_ABI \
	-I$(GANESHA_BUILD)/src/include -I$(GANESHA_BUILD)/include \
	-I$(GANESHA_SOURCE)/src/include -I$(GANESHA_SOURCE)/src \
	-I$(NTIRPC_INCLUDE)

.PHONY: check abi-check

check:
	$(CC) $(CFLAGS) -c fsal_filebelt.c -o /tmp/filebelt-fsal-filebelt.o
	rm -f /tmp/filebelt-fsal-filebelt.o

abi-check:
	test -n "$(GANESHA_SOURCE)"
	test -n "$(GANESHA_BUILD)"
	$(CC) $(CFLAGS) $(ABI_CPPFLAGS) -c abi_probe.c -o /tmp/filebelt-fsal-abi-probe.o
	$(CC) $(CFLAGS) $(ABI_CPPFLAGS) -c fsal_filebelt.c -o /tmp/filebelt-fsal-filebelt-abi.o
	rm -f /tmp/filebelt-fsal-abi-probe.o /tmp/filebelt-fsal-filebelt-abi.o
