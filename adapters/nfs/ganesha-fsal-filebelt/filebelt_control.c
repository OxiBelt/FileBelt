/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "filebelt_internal.h"
#include "filebelt_credentials.h"
#include "filebelt_identity.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define FILEBELT_CONTROL_SOCKET "/run/filebelt-nfs/ganesha-control.sock"

struct control_request {
	char request_id[FILEBELT_UUID_BYTES];
	char boot_id[FILEBELT_UUID_BYTES];
	uint64_t feature_generation;
	uint64_t export_generation;
	uint8_t manifest_digest[32];
	struct filebelt_manifest_entry *entries;
	size_t entry_count;
	bool drain;
};

static bool copy_string(const struct filebelt_pb_field *field, char *output,
			size_t capacity)
{
	if (field->wire_type != 2 || field->length == 0 ||
	    field->length >= capacity || memchr(field->bytes, '\0', field->length))
		return false;
	memcpy(output, field->bytes, field->length);
	output[field->length] = '\0';
	return true;
}

static bool canonical_uuid(const char *value)
{
	for (size_t index = 0; index < FILEBELT_UUID_BYTES - 1; index++) {
		char byte = value[index];
		bool hyphen = index == 8 || index == 13 || index == 18 || index == 23;

		if (hyphen ? byte != '-' : !((byte >= '0' && byte <= '9') ||
					       (byte >= 'a' && byte <= 'f')))
			return false;
	}
	return value[FILEBELT_UUID_BYTES - 1] == '\0';
}

static bool parse_export(const uint8_t *encoded, size_t encoded_length,
			 struct filebelt_manifest_entry *entry)
{
	struct filebelt_pb_cursor cursor;
	struct filebelt_pb_field field;
	unsigned int seen = 0;
	char expected_path[FILEBELT_EXPORT_PATH_BYTES];
	int path_length;

	memset(entry, 0, sizeof(*entry));
	filebelt_pb_cursor_init(&cursor, encoded, encoded_length);
	while (cursor.offset < cursor.length && filebelt_pb_next(&cursor, &field)) {
		switch (field.number) {
		case 1:
			if (field.wire_type != 0 || (seen & 1U) != 0)
				return false;
			entry->export_id = field.varint;
			seen |= 1U;
			break;
		case 2:
			if ((seen & 2U) != 0 ||
			    !copy_string(&field, entry->drive_id,
					 sizeof(entry->drive_id)))
				return false;
			seen |= 2U;
			break;
		case 3:
			if ((seen & 4U) != 0 ||
			    !copy_string(&field, entry->export_path,
					 sizeof(entry->export_path)))
				return false;
			seen |= 4U;
			break;
		case 4:
			if (field.wire_type != 0 || (seen & 8U) != 0)
				return false;
			entry->generation = field.varint;
			seen |= 8U;
			break;
		case 5:
			if (field.wire_type != 2 || (seen & 16U) != 0 ||
			    field.length != FILEBELT_HANDLE_BYTES)
				return false;
			memcpy(entry->root_handle, field.bytes, field.length);
			seen |= 16U;
			break;
		case 6:
			if (field.wire_type != 0 || (seen & 32U) != 0 ||
			    field.varint != 1)
				return false;
			entry->read_only = true;
			seen |= 32U;
			break;
		default:
			return false;
		}
	}
	if (!filebelt_pb_finished(&cursor) || (seen & 31U) != 31U ||
	    entry->export_id == 0 || entry->generation == 0 ||
	    !canonical_uuid(entry->drive_id))
		return false;
	path_length = snprintf(expected_path, sizeof(expected_path),
			       "/filebelt/%s", entry->drive_id);
	return path_length > 0 && (size_t)path_length < sizeof(expected_path) &&
	       strcmp(entry->export_path, expected_path) == 0;
}

static bool append_export(struct control_request *request,
			  const struct filebelt_manifest_entry *entry)
{
	struct filebelt_manifest_entry *resized;

	if (request->entry_count >= FILEBELT_MAX_EXPORTS ||
	    (request->entry_count != 0 &&
	     request->entries[request->entry_count - 1].export_id >= entry->export_id))
		return false;
	resized = realloc(request->entries,
			  (request->entry_count + 1) * sizeof(*resized));
	if (resized == NULL)
		return false;
	request->entries = resized;
	request->entries[request->entry_count++] = *entry;
	return true;
}

static bool parse_request(const uint8_t *encoded, size_t encoded_length,
			  struct control_request *request)
{
	struct filebelt_pb_cursor cursor;
	struct filebelt_pb_field field;
	unsigned int seen = 0;
	uint32_t format = 0;

	memset(request, 0, sizeof(*request));
	filebelt_pb_cursor_init(&cursor, encoded, encoded_length);
	while (cursor.offset < cursor.length && filebelt_pb_next(&cursor, &field)) {
		switch (field.number) {
		case 1:
			if (field.wire_type != 0 || (seen & 1U) != 0 ||
			    field.varint > UINT32_MAX)
				goto invalid;
			format = (uint32_t)field.varint;
			seen |= 1U;
			break;
		case 2:
			if ((seen & 2U) != 0 ||
			    !copy_string(&field, request->request_id,
					 sizeof(request->request_id)))
				goto invalid;
			seen |= 2U;
			break;
		case 3:
			if ((seen & 4U) != 0 ||
			    !copy_string(&field, request->boot_id,
					 sizeof(request->boot_id)))
				goto invalid;
			seen |= 4U;
			break;
		case 4:
			if (field.wire_type != 0 || (seen & 8U) != 0)
				goto invalid;
			request->feature_generation = field.varint;
			seen |= 8U;
			break;
		case 5:
			if (field.wire_type != 0 || (seen & 16U) != 0)
				goto invalid;
			request->export_generation = field.varint;
			seen |= 16U;
			break;
		case 6:
			if (field.wire_type != 2 || (seen & 32U) != 0 ||
			    field.length != sizeof(request->manifest_digest))
				goto invalid;
			memcpy(request->manifest_digest, field.bytes, field.length);
			seen |= 32U;
			break;
		case 7: {
			struct filebelt_manifest_entry entry;

			if (!parse_export(field.bytes, field.length, &entry) ||
			    !append_export(request, &entry))
				goto invalid;
			break;
		}
		case 8:
			if (field.wire_type != 0 || (seen & 64U) != 0 ||
			    field.varint != 1)
				goto invalid;
			request->drain = true;
			seen |= 64U;
			break;
		default:
			goto invalid;
		}
	}
	if (!filebelt_pb_finished(&cursor) || format != FILEBELT_WIRE_FORMAT ||
	    !canonical_uuid(request->request_id) ||
	    !canonical_uuid(request->boot_id))
		goto invalid;
	if (request->drain) {
		if (request->feature_generation != 0 ||
		    request->export_generation != 0 || (seen & 32U) != 0 ||
		    request->entry_count != 0)
			goto invalid;
	} else if (request->feature_generation == 0 ||
		   request->export_generation == 0 || (seen & 32U) == 0) {
		goto invalid;
	}
	for (size_t index = 0; index < request->entry_count; index++) {
		if (request->entries[index].generation > request->export_generation)
			goto invalid;
	}
	return true;
invalid:
	free(request->entries);
	memset(request, 0, sizeof(*request));
	return false;
}

static bool encode_response(const struct control_request *request,
			    uint8_t *encoded, size_t capacity,
			    size_t *encoded_length)
{
	struct filebelt_pb_buffer response;
	uint8_t entry_storage[160];

	filebelt_pb_init(&response, encoded, capacity);
	if (!filebelt_pb_uint64(&response, 1, FILEBELT_WIRE_FORMAT) ||
	    !filebelt_pb_string(&response, 2, request->request_id) ||
	    !filebelt_pb_bool(&response, 3, true))
		return false;
	for (size_t index = 0; index < request->entry_count; index++) {
		struct filebelt_pb_buffer entry;

		filebelt_pb_init(&entry, entry_storage, sizeof(entry_storage));
		if (!filebelt_pb_uint64(&entry, 1,
					request->entries[index].export_id) ||
		    !filebelt_pb_uint64(&entry, 2,
					request->entries[index].generation) ||
		    !filebelt_pb_bytes(&entry, 3,
				       request->entries[index].root_handle,
				       FILEBELT_HANDLE_BYTES) ||
		    !filebelt_pb_bytes(&response, 4, entry.data, entry.length))
			return false;
	}
	*encoded_length = response.length;
	return !response.failed;
}

static bool install_request(struct filebelt_fsal_export *export,
			    const struct control_request *request)
{
	struct filebelt_manifest_entry *replacement = NULL;
	struct filebelt_manifest_entry *previous = NULL;
	bool accepted = true;

	if (!request->drain && request->entry_count != 0) {
		replacement = malloc(request->entry_count * sizeof(*replacement));
		if (replacement == NULL)
			return false;
		memcpy(replacement, request->entries,
		       request->entry_count * sizeof(*replacement));
	}
	pthread_rwlock_wrlock(&export->manifest_lock);
	if (request->drain &&
	    (export->boot_id[0] == '\0' ||
	     strcmp(export->boot_id, request->boot_id) != 0)) {
		accepted = false;
		goto unlock;
	}
	previous = export->manifest;
	export->manifest = replacement;
	export->manifest_count = request->drain ? 0 : request->entry_count;
	export->feature_generation = request->drain ? 0 : request->feature_generation;
	export->export_generation = request->drain ? 0 : request->export_generation;
	memcpy(export->boot_id, request->boot_id, sizeof(export->boot_id));
	replacement = NULL;
unlock:
	pthread_rwlock_unlock(&export->manifest_lock);
	if (accepted)
		free(previous);
	free(replacement);
	return accepted;
}

static bool peer_is_bridge(int descriptor, pid_t *peer_pid)
{
	struct ucred peer;
	socklen_t length = sizeof(peer);

	if (peer_pid == NULL ||
	    getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &peer, &length) != 0 ||
	    length != sizeof(peer) ||
	    !filebelt_process_identity_matches(
		    peer.uid, peer.gid, FILEBELT_BRIDGE_UID,
		    FILEBELT_BRIDGE_GID))
		return false;
	*peer_pid = peer.pid;
	return true;
}

static void serve_control_packet(struct filebelt_fsal_export *export,
				 int descriptor)
{
	uint8_t *packet = NULL;
	uint8_t *response = NULL;
	struct control_request request;
	ssize_t received;
	size_t response_length;
	uint32_t payload_length;
	pid_t peer_pid = -1;

	if (!peer_is_bridge(descriptor, &peer_pid))
		return;
	packet = malloc(FILEBELT_MAX_FRAME_BYTES + 4U);
	response = malloc(FILEBELT_MAX_FRAME_BYTES + 4U);
	if (packet == NULL || response == NULL)
		goto out;
	received = filebelt_receive_authenticated_packet(
		descriptor, peer_pid, FILEBELT_BRIDGE_UID, FILEBELT_BRIDGE_GID,
		packet, FILEBELT_MAX_FRAME_BYTES + 4U);
	if (received < 4 || (size_t)received > FILEBELT_MAX_FRAME_BYTES + 4U ||
	    filebelt_fsal_frame_length(packet, &payload_length) != 0 ||
	    payload_length != (size_t)received - 4U ||
	    !parse_request(packet + 4U, payload_length, &request))
		goto out;
	/* Encode the complete readback before changing the installed set.  A
	 * resource failure must leave the previously admitted manifest intact. */
	if (!encode_response(&request, response + 4U,
			     FILEBELT_MAX_FRAME_BYTES, &response_length) ||
	    !install_request(export, &request) ||
	    response_length > UINT32_MAX)
		goto request_out;
	response[0] = (uint8_t)(response_length >> 24);
	response[1] = (uint8_t)(response_length >> 16);
	response[2] = (uint8_t)(response_length >> 8);
	response[3] = (uint8_t)response_length;
	(void)send(descriptor, response, response_length + 4U, MSG_NOSIGNAL);
request_out:
	free(request.entries);
out:
	free(response);
	free(packet);
}

static void *control_thread_main(void *opaque)
{
	struct filebelt_fsal_export *export = opaque;

	while (!atomic_load_explicit(&export->control_stopping,
					    memory_order_acquire)) {
		int descriptor = accept4(export->control_listener, NULL, NULL,
					 SOCK_CLOEXEC);
		int passcred = 1;

		if (descriptor < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (setsockopt(descriptor, SOL_SOCKET, SO_PASSCRED, &passcred,
			       sizeof(passcred)) != 0) {
			(void)close(descriptor);
			continue;
		}
		serve_control_packet(export, descriptor);
		(void)close(descriptor);
	}
	return NULL;
}

int filebelt_control_start(struct filebelt_fsal_export *export)
{
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	struct stat parent;
	struct stat existing;
	const char *parent_path = "/run/filebelt-nfs";
	int descriptor;
	int passcred = 1;

	if (!filebelt_process_identity_matches(
		    geteuid(), getegid(), FILEBELT_GANESHA_UID,
		    FILEBELT_GANESHA_GID) ||
	    lstat(parent_path, &parent) != 0 || !S_ISDIR(parent.st_mode) ||
	    (parent.st_mode & 007U) != 0 || parent.st_gid != FILEBELT_BRIDGE_GID)
		return -1;
	if (lstat(FILEBELT_CONTROL_SOCKET, &existing) == 0) {
		if (!filebelt_socket_identity_matches(
			    existing.st_mode, existing.st_uid, existing.st_gid,
			    FILEBELT_GANESHA_UID) ||
		    unlink(FILEBELT_CONTROL_SOCKET) != 0)
			return -1;
	} else if (errno != ENOENT) {
		return -1;
	}
	descriptor = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (descriptor < 0)
		return -1;
	memcpy(address.sun_path, FILEBELT_CONTROL_SOCKET,
	       sizeof(FILEBELT_CONTROL_SOCKET));
	if (bind(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0 ||
	    chown(FILEBELT_CONTROL_SOCKET, (uid_t)-1, FILEBELT_IPC_GID) != 0 ||
	    chmod(FILEBELT_CONTROL_SOCKET, 0660) != 0 ||
	    lstat(FILEBELT_CONTROL_SOCKET, &existing) != 0 ||
	    !filebelt_socket_identity_matches(
		    existing.st_mode, existing.st_uid, existing.st_gid,
		    FILEBELT_GANESHA_UID) ||
	    setsockopt(descriptor, SOL_SOCKET, SO_PASSCRED, &passcred,
		       sizeof(passcred)) != 0 ||
	    listen(descriptor, 16) != 0) {
		(void)close(descriptor);
		(void)unlink(FILEBELT_CONTROL_SOCKET);
		return -1;
	}
	export->control_listener = descriptor;
	atomic_store_explicit(&export->control_stopping, false,
			      memory_order_release);
	if (pthread_create(&export->control_thread, NULL, control_thread_main,
			   export) != 0) {
		(void)close(descriptor);
		(void)unlink(FILEBELT_CONTROL_SOCKET);
		export->control_listener = -1;
		return -1;
	}
	export->control_started = true;
	return 0;
}

void filebelt_control_stop(struct filebelt_fsal_export *export)
{
	if (!export->control_started)
		return;
	atomic_store_explicit(&export->control_stopping, true,
			      memory_order_release);
	(void)shutdown(export->control_listener, SHUT_RDWR);
	(void)close(export->control_listener);
	(void)pthread_join(export->control_thread, NULL);
	(void)unlink(FILEBELT_CONTROL_SOCKET);
	export->control_listener = -1;
	export->control_started = false;
}

bool filebelt_manifest_by_name(struct filebelt_fsal_export *export,
			      const char *name,
			      struct filebelt_manifest_entry *entry)
{
	bool found = false;

	pthread_rwlock_rdlock(&export->manifest_lock);
	for (size_t index = 0; index < export->manifest_count; index++) {
		if (strcmp(export->manifest[index].drive_id, name) == 0) {
			*entry = export->manifest[index];
			found = true;
			break;
		}
	}
	pthread_rwlock_unlock(&export->manifest_lock);
	return found;
}

bool filebelt_manifest_by_export_id(struct filebelt_fsal_export *export,
				   uint64_t export_id,
				   struct filebelt_manifest_entry *entry)
{
	bool found = false;

	pthread_rwlock_rdlock(&export->manifest_lock);
	for (size_t index = 0; index < export->manifest_count; index++) {
		if (export->manifest[index].export_id == export_id) {
			*entry = export->manifest[index];
			found = true;
			break;
		}
	}
	pthread_rwlock_unlock(&export->manifest_lock);
	return found;
}

size_t filebelt_manifest_snapshot(struct filebelt_fsal_export *export,
				 struct filebelt_manifest_entry *entries,
				 size_t capacity)
{
	size_t count;

	pthread_rwlock_rdlock(&export->manifest_lock);
	count = export->manifest_count;
	if (count <= capacity && count != 0)
		memcpy(entries, export->manifest, count * sizeof(*entries));
	pthread_rwlock_unlock(&export->manifest_lock);
	return count;
}
