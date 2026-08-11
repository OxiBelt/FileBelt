# SPDX-License-Identifier: LGPL-3.0-or-later

CC ?= cc
CFLAGS ?= -O2 -fPIC -Wall -Wextra -Werror -Wconversion -Wformat=2
GANESHA_SOURCE ?=
GANESHA_BUILD ?=
NTIRPC_INCLUDE ?= /usr/include/ntirpc
ABI_EXTRA_CPPFLAGS ?=
ABI_CPPFLAGS = -DFILEBELT_GANESHA_ABI \
	-isystem $(GANESHA_BUILD)/src/include -isystem $(GANESHA_BUILD)/include \
	-isystem $(GANESHA_SOURCE)/src/include -isystem $(GANESHA_SOURCE)/src \
	-isystem $(NTIRPC_INCLUDE) $(ABI_EXTRA_CPPFLAGS)

.PHONY: check abi-check

check:
	$(CC) $(CFLAGS) -c fsal_filebelt.c -o /tmp/filebelt-fsal-filebelt.o
	$(CC) $(CFLAGS) -c filebelt_wire.c -o /tmp/filebelt-wire.o
	$(CC) $(CFLAGS) wire_test.c filebelt_wire.c -o /tmp/filebelt-wire-test
	$(CC) $(CFLAGS) projection_test.c filebelt_projection.c -o /tmp/filebelt-projection-test
	/tmp/filebelt-wire-test
	/tmp/filebelt-projection-test
	rm -f /tmp/filebelt-fsal-filebelt.o /tmp/filebelt-wire.o /tmp/filebelt-wire-test /tmp/filebelt-projection-test

abi-check:
	test -n "$(GANESHA_SOURCE)"
	test -n "$(GANESHA_BUILD)"
	$(CC) $(CFLAGS) $(ABI_CPPFLAGS) -c abi_probe.c -o /tmp/filebelt-fsal-abi-probe.o
	$(CC) $(CFLAGS) $(ABI_CPPFLAGS) -c fsal_filebelt.c -o /tmp/filebelt-fsal-filebelt-abi.o
	$(CC) $(CFLAGS) $(ABI_CPPFLAGS) -c filebelt_wire.c -o /tmp/filebelt-wire-abi.o
	$(CC) $(CFLAGS) $(ABI_CPPFLAGS) -c filebelt_control.c -o /tmp/filebelt-control-abi.o
	$(CC) $(CFLAGS) $(ABI_CPPFLAGS) -c filebelt_protocol.c -o /tmp/filebelt-protocol-abi.o
	$(CC) $(CFLAGS) $(ABI_CPPFLAGS) -c filebelt_projection.c -o /tmp/filebelt-projection-abi.o
	$(CC) $(CFLAGS) $(ABI_CPPFLAGS) -c filebelt_handle.c -o /tmp/filebelt-handle-abi.o
	$(CC) $(CFLAGS) $(ABI_CPPFLAGS) -DFILEBELT_CALLBACKS_QUALIFIED -c filebelt_export.c -o /tmp/filebelt-export-abi.o
	rm -f /tmp/filebelt-fsal-abi-probe.o /tmp/filebelt-fsal-filebelt-abi.o /tmp/filebelt-wire-abi.o /tmp/filebelt-control-abi.o /tmp/filebelt-protocol-abi.o /tmp/filebelt-projection-abi.o /tmp/filebelt-handle-abi.o /tmp/filebelt-export-abi.o
