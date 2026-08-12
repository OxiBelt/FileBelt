/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef FILEBELT_CREDENTIALS_H
#define FILEBELT_CREDENTIALS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

ssize_t filebelt_receive_authenticated_packet(
	int descriptor, pid_t peer_pid, uid_t peer_uid, gid_t peer_gid,
	uint8_t *packet, size_t capacity);

#endif /* FILEBELT_CREDENTIALS_H */
