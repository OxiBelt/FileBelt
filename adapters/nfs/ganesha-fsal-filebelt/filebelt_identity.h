/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef FILEBELT_IDENTITY_H
#define FILEBELT_IDENTITY_H

#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>

enum {
	FILEBELT_BRIDGE_UID = 10001,
	FILEBELT_BRIDGE_GID = 10001,
	FILEBELT_GANESHA_UID = 10002,
	FILEBELT_GANESHA_GID = 10002,
	FILEBELT_IPC_GID = 10003
};

static inline bool filebelt_process_identity_matches(
	uid_t uid, gid_t gid, uid_t expected_uid, gid_t expected_gid)
{
	return uid == expected_uid && gid == expected_gid;
}

static inline bool filebelt_socket_identity_matches(
	mode_t mode, uid_t uid, gid_t gid, uid_t expected_uid)
{
	return S_ISSOCK(mode) && uid == expected_uid &&
	       gid == FILEBELT_IPC_GID && (mode & 0777U) == 0660U;
}

#endif /* FILEBELT_IDENTITY_H */
