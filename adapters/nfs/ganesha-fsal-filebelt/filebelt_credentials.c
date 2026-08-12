/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "filebelt_credentials.h"

#include <sys/socket.h>

ssize_t filebelt_receive_authenticated_packet(
	int descriptor, pid_t peer_pid, uid_t peer_uid, gid_t peer_gid,
	uint8_t *packet, size_t capacity)
{
	union {
		struct cmsghdr alignment;
		uint8_t bytes[CMSG_SPACE(sizeof(struct ucred))];
	} control;
	struct iovec vector = { .iov_base = packet, .iov_len = capacity };
	struct msghdr message = {
		.msg_iov = &vector,
		.msg_iovlen = 1,
		.msg_control = control.bytes,
		.msg_controllen = sizeof(control.bytes),
	};
	ssize_t received = recvmsg(descriptor, &message, MSG_TRUNC);

	if (received < 0 || (message.msg_flags & MSG_CTRUNC) != 0)
		return -1;
	for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header != NULL;
	     header = CMSG_NXTHDR(&message, header)) {
		if (header->cmsg_level == SOL_SOCKET &&
		    header->cmsg_type == SCM_CREDENTIALS &&
		    header->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
			const struct ucred *credentials =
				(const struct ucred *)CMSG_DATA(header);

			if (credentials->pid == peer_pid &&
			    credentials->uid == peer_uid &&
			    credentials->gid == peer_gid)
				return received;
		}
	}
	return -1;
}
