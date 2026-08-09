# SPDX-License-Identifier: LGPL-3.0-or-later

CC ?= cc
CFLAGS ?= -O2 -fPIC -Wall -Wextra -Werror

.PHONY: check

check:
	$(CC) $(CFLAGS) -c fsal_filebelt.c -o /tmp/filebelt-fsal-filebelt.o
	rm -f /tmp/filebelt-fsal-filebelt.o
