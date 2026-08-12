/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "filebelt_credentials.h"

#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>

static ssize_t receive_with_expected(bool passcred, pid_t pid, uid_t uid,
				     gid_t gid)
{
	int descriptors[2];
	int enabled = 1;
	uint8_t packet[8];
	ssize_t received;

	assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
			  descriptors) == 0);
	if (passcred && setsockopt(descriptors[1], SOL_SOCKET, SO_PASSCRED,
				  &enabled, sizeof(enabled)) != 0) {
		perror("setsockopt SO_PASSCRED");
		assert(false);
	}
	assert(send(descriptors[0], "packet", 6, MSG_NOSIGNAL) == 6);
	received = filebelt_receive_authenticated_packet(
		descriptors[1], pid, uid, gid, packet, sizeof(packet));
	assert(close(descriptors[0]) == 0);
	assert(close(descriptors[1]) == 0);
	return received;
}

int main(void)
{
	pid_t pid = getpid();
	uid_t uid = geteuid();
	gid_t gid = getegid();

	assert(receive_with_expected(true, pid, uid, gid) == 6);
	assert(receive_with_expected(false, pid, uid, gid) == -1);
	assert(receive_with_expected(true, pid + 1, uid, gid) == -1);
	assert(receive_with_expected(true, pid, uid + 1U, gid) == -1);
	assert(receive_with_expected(true, pid, uid, gid + 1U) == -1);
	return 0;
}
