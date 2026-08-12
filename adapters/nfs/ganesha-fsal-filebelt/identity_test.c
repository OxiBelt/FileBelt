/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "filebelt_identity.h"

#include <assert.h>

int main(void)
{
	mode_t socket_mode = S_IFSOCK | 0660U;

	assert(filebelt_process_identity_matches(
		FILEBELT_BRIDGE_UID, FILEBELT_BRIDGE_GID,
		FILEBELT_BRIDGE_UID, FILEBELT_BRIDGE_GID));
	assert(!filebelt_process_identity_matches(
		FILEBELT_GANESHA_UID, FILEBELT_BRIDGE_GID,
		FILEBELT_BRIDGE_UID, FILEBELT_BRIDGE_GID));
	assert(!filebelt_process_identity_matches(
		FILEBELT_BRIDGE_UID, FILEBELT_GANESHA_GID,
		FILEBELT_BRIDGE_UID, FILEBELT_BRIDGE_GID));

	assert(filebelt_socket_identity_matches(
		socket_mode, FILEBELT_BRIDGE_UID, FILEBELT_IPC_GID,
		FILEBELT_BRIDGE_UID));
	assert(!filebelt_socket_identity_matches(
		S_IFSOCK | 0600U, FILEBELT_BRIDGE_UID, FILEBELT_IPC_GID,
		FILEBELT_BRIDGE_UID));
	assert(!filebelt_socket_identity_matches(
		S_IFSOCK | 0664U, FILEBELT_BRIDGE_UID, FILEBELT_IPC_GID,
		FILEBELT_BRIDGE_UID));
	assert(!filebelt_socket_identity_matches(
		S_IFSOCK | 0666U, FILEBELT_BRIDGE_UID, FILEBELT_IPC_GID,
		FILEBELT_BRIDGE_UID));
	assert(!filebelt_socket_identity_matches(
		S_IFREG | 0660U, FILEBELT_BRIDGE_UID, FILEBELT_IPC_GID,
		FILEBELT_BRIDGE_UID));
	assert(!filebelt_socket_identity_matches(
		socket_mode, FILEBELT_GANESHA_UID, FILEBELT_IPC_GID,
		FILEBELT_BRIDGE_UID));
	assert(!filebelt_socket_identity_matches(
		socket_mode, FILEBELT_BRIDGE_UID, FILEBELT_BRIDGE_GID,
		FILEBELT_BRIDGE_UID));
	return 0;
}
