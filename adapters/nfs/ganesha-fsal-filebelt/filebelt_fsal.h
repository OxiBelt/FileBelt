/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef FILEBELT_FSAL_H
#define FILEBELT_FSAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FILEBELT_PRINCIPAL_BYTES 513
#define FILEBELT_SOURCE_ADDRESS_BYTES 46
#define FILEBELT_GSS_BINDING_BYTES 32
#define FILEBELT_CLIENT_ID_BYTES 17
#define FILEBELT_NFS_SESSION_ID_BYTES 33

struct filebelt_fsal_request_context {
	char principal[FILEBELT_PRINCIPAL_BYTES];
	uint8_t gss_binding[FILEBELT_GSS_BINDING_BYTES];
	char source_address[FILEBELT_SOURCE_ADDRESS_BYTES];
	uint64_t context_expires_at_unix_seconds;
	char client_id[FILEBELT_CLIENT_ID_BYTES];
	char nfs_session_id[FILEBELT_NFS_SESSION_ID_BYTES];
	uint32_t slot_id;
	uint64_t sequence_id;
	uint32_t operation_index;
};

int filebelt_fsal_frame_length(const uint8_t prefix[4], uint32_t *length);

#ifdef FILEBELT_GANESHA_ABI
bool filebelt_fsal_capture_request(struct filebelt_fsal_request_context *output);
#endif

#endif /* FILEBELT_FSAL_H */
