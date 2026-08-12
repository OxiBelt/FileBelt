/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "filebelt_wire.h"
#include "filebelt_credentials.h"
#include "filebelt_identity.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

enum {
	FILEBELT_PB_VARINT = 0,
	FILEBELT_PB_LENGTH_DELIMITED = 2,
	FILEBELT_FRAME_PREFIX_BYTES = 4
};

static bool append(struct filebelt_pb_buffer *buffer, const void *value,
		   size_t length)
{
	if (buffer == NULL || value == NULL || buffer->failed ||
	    length > buffer->capacity - buffer->length) {
		if (buffer != NULL)
			buffer->failed = true;
		return false;
	}
	memcpy(buffer->data + buffer->length, value, length);
	buffer->length += length;
	return true;
}

static bool put_varint(struct filebelt_pb_buffer *buffer, uint64_t value)
{
	uint8_t encoded[10];
	size_t length = 0;

	do {
		uint8_t byte = (uint8_t)(value & UINT64_C(0x7f));

		value >>= 7;
		if (value != 0)
			byte |= UINT8_C(0x80);
		encoded[length++] = byte;
	} while (value != 0 && length < sizeof(encoded));
	return append(buffer, encoded, length);
}

static bool put_key(struct filebelt_pb_buffer *buffer, uint32_t field,
		    uint8_t wire_type)
{
	if (field == 0 || field > UINT32_C(0x1fffffff) ||
	    (wire_type != FILEBELT_PB_VARINT &&
	     wire_type != FILEBELT_PB_LENGTH_DELIMITED)) {
		buffer->failed = true;
		return false;
	}
	return put_varint(buffer, ((uint64_t)field << 3) | wire_type);
}

void filebelt_pb_init(struct filebelt_pb_buffer *buffer, uint8_t *data,
		      size_t capacity)
{
	if (buffer == NULL)
		return;
	buffer->data = data;
	buffer->length = 0;
	buffer->capacity = capacity;
	buffer->failed = data == NULL && capacity != 0;
}

bool filebelt_pb_uint64(struct filebelt_pb_buffer *buffer, uint32_t field,
		       uint64_t value)
{
	return put_key(buffer, field, FILEBELT_PB_VARINT) &&
	       put_varint(buffer, value);
}

bool filebelt_pb_bool(struct filebelt_pb_buffer *buffer, uint32_t field,
		     bool value)
{
	return filebelt_pb_uint64(buffer, field, value ? 1U : 0U);
}

bool filebelt_pb_bytes(struct filebelt_pb_buffer *buffer, uint32_t field,
		      const void *value, size_t length)
{
	if (length > UINT32_MAX || (value == NULL && length != 0)) {
		buffer->failed = true;
		return false;
	}
	return put_key(buffer, field, FILEBELT_PB_LENGTH_DELIMITED) &&
	       put_varint(buffer, length) &&
	       (length == 0 || append(buffer, value, length));
}

bool filebelt_pb_string(struct filebelt_pb_buffer *buffer, uint32_t field,
		       const char *value)
{
	return value != NULL &&
	       filebelt_pb_bytes(buffer, field, value, strlen(value));
}

void filebelt_pb_cursor_init(struct filebelt_pb_cursor *cursor,
			    const uint8_t *data, size_t length)
{
	if (cursor == NULL)
		return;
	cursor->data = data;
	cursor->length = length;
	cursor->offset = 0;
	cursor->previous_field = 0;
}

static bool read_varint(struct filebelt_pb_cursor *cursor, uint64_t *value)
{
	uint64_t decoded = 0;
	unsigned int shift = 0;
	size_t start = cursor->offset;

	while (cursor->offset < cursor->length && shift < 70) {
		uint8_t byte = cursor->data[cursor->offset++];

		if (shift == 63 && (byte & UINT8_C(0xfe)) != 0)
			return false;
		decoded |= (uint64_t)(byte & UINT8_C(0x7f)) << shift;
		if ((byte & UINT8_C(0x80)) == 0) {
			/* Reject overlong protobuf varints. */
			if (cursor->offset - start > 1 && byte == 0)
				return false;
			*value = decoded;
			return true;
		}
		shift += 7;
	}
	return false;
}

bool filebelt_pb_next(struct filebelt_pb_cursor *cursor,
		     struct filebelt_pb_field *field)
{
	uint64_t key;
	uint64_t length;

	if (cursor == NULL || field == NULL || cursor->data == NULL ||
	    cursor->offset >= cursor->length || !read_varint(cursor, &key))
		return false;
	memset(field, 0, sizeof(*field));
	field->number = (uint32_t)(key >> 3);
	field->wire_type = (uint8_t)(key & 7U);
	if (field->number == 0 || field->number < cursor->previous_field)
		return false;
	cursor->previous_field = field->number;
	if (field->wire_type == FILEBELT_PB_VARINT) {
		return read_varint(cursor, &field->varint);
	}
	if (field->wire_type != FILEBELT_PB_LENGTH_DELIMITED ||
	    !read_varint(cursor, &length) || length > SIZE_MAX ||
	    (size_t)length > cursor->length - cursor->offset)
		return false;
	field->bytes = cursor->data + cursor->offset;
	field->length = (size_t)length;
	cursor->offset += field->length;
	return true;
}

bool filebelt_pb_finished(const struct filebelt_pb_cursor *cursor)
{
	return cursor != NULL && cursor->offset == cursor->length;
}

#ifdef FILEBELT_GANESHA_ABI

#include "fsal.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define FILEBELT_BRIDGE_SOCKET "/run/filebelt-nfs/bridge.sock"

struct filebelt_private_projection {
	uint64_t uid;
	uint64_t gid;
	uint64_t mapping_generation;
	uint64_t feature_generation;
	uint64_t expiry;
};

static bool lowercase_posix_name(const struct filebelt_pb_field *field)
{
	if (field->wire_type != FILEBELT_PB_LENGTH_DELIMITED ||
	    field->length == 0 || field->length > 255 ||
	    !(field->bytes[0] == '_' ||
	      (field->bytes[0] >= 'a' && field->bytes[0] <= 'z')))
		return false;
	for (size_t index = 1; index < field->length; index++) {
		uint8_t byte = field->bytes[index];

		if (!((byte >= 'a' && byte <= 'z') ||
		      (byte >= '0' && byte <= '9') || byte == '_' ||
		      byte == '.' || byte == '-'))
			return false;
	}
	return true;
}

static bool parse_export_ids(const struct filebelt_pb_field *field)
{
	size_t offset = 0;
	size_t count = 0;
	uint64_t previous = 0;

	if (field->wire_type != FILEBELT_PB_LENGTH_DELIMITED ||
	    field->length == 0)
		return false;
	while (offset < field->length) {
		uint64_t value = 0;
		unsigned int shift = 0;
		size_t start = offset;

		while (offset < field->length && shift < 70) {
			uint8_t byte = field->bytes[offset++];

			if (shift == 63 && (byte & UINT8_C(0xfe)) != 0)
				return false;
			value |= (uint64_t)(byte & UINT8_C(0x7f)) << shift;
			if ((byte & UINT8_C(0x80)) == 0) {
				if (offset - start > 1 && byte == 0)
					return false;
				break;
			}
			shift += 7;
		}
		if (shift >= 70 ||
		    (field->bytes[offset - 1] & UINT8_C(0x80)) != 0 ||
		    value == 0 || value <= previous || ++count > 1000U)
			return false;
		previous = value;
	}
	return count != 0;
}

static bool parse_projection(const uint8_t *encoded, size_t encoded_length,
			     struct filebelt_private_projection *projection)
{
	struct filebelt_pb_cursor cursor;
	struct filebelt_pb_field field;
	unsigned int seen = 0;

	memset(projection, 0, sizeof(*projection));
	filebelt_pb_cursor_init(&cursor, encoded, encoded_length);
	while (cursor.offset < cursor.length && filebelt_pb_next(&cursor, &field)) {
		switch (field.number) {
		case 1:
			if ((seen & 1U) != 0 || !lowercase_posix_name(&field))
				return false;
			seen |= 1U;
			break;
		case 2:
			if ((seen & 2U) != 0 || !lowercase_posix_name(&field))
				return false;
			seen |= 2U;
			break;
		case 3:
			if (field.wire_type != FILEBELT_PB_VARINT ||
			    (seen & 4U) != 0 || field.varint == 0 ||
			    field.varint == 65534U || field.varint > 4294967294U)
				return false;
			projection->uid = field.varint;
			seen |= 4U;
			break;
		case 4:
			if (field.wire_type != FILEBELT_PB_VARINT ||
			    (seen & 8U) != 0 || field.varint == 0 ||
			    field.varint == 65534U || field.varint > 4294967294U)
				return false;
			projection->gid = field.varint;
			seen |= 8U;
			break;
		case 5:
			if (field.wire_type != FILEBELT_PB_VARINT ||
			    (seen & 16U) != 0 || field.varint == 0)
				return false;
			projection->mapping_generation = field.varint;
			seen |= 16U;
			break;
		case 6:
			if (field.wire_type != FILEBELT_PB_VARINT ||
			    (seen & 32U) != 0 || field.varint == 0)
				return false;
			projection->feature_generation = field.varint;
			seen |= 32U;
			break;
		case 7:
			if (field.wire_type != FILEBELT_PB_VARINT ||
			    (seen & 64U) != 0 || field.varint == 0 ||
			    field.varint > INT64_MAX)
				return false;
			projection->expiry = field.varint;
			seen |= 64U;
			break;
		case 8:
			if ((seen & 128U) != 0 || !parse_export_ids(&field))
				return false;
			seen |= 128U;
			break;
		default:
			return false;
		}
	}
	return filebelt_pb_finished(&cursor) && seen == 255U;
}

static bool parse_private_reply(
	const uint8_t *encoded, size_t encoded_length,
	struct filebelt_pb_field *vfs_response,
	struct filebelt_private_projection *projection)
{
	struct filebelt_pb_cursor cursor;
	struct filebelt_pb_field field;
	bool saw_response = false;
	bool saw_projection = false;

	memset(vfs_response, 0, sizeof(*vfs_response));
	filebelt_pb_cursor_init(&cursor, encoded, encoded_length);
	while (cursor.offset < cursor.length && filebelt_pb_next(&cursor, &field)) {
		if (field.number == 1 && !saw_response &&
		    field.wire_type == FILEBELT_PB_LENGTH_DELIMITED &&
		    field.length != 0) {
			*vfs_response = field;
			saw_response = true;
		} else if (field.number == 2 && !saw_projection &&
			   field.wire_type == FILEBELT_PB_LENGTH_DELIMITED &&
			   parse_projection(field.bytes, field.length, projection)) {
			saw_projection = true;
		} else {
			return false;
		}
	}
	return filebelt_pb_finished(&cursor) && saw_response && saw_projection;
}

static bool apply_projection(
	const struct filebelt_private_projection *projection)
{
	struct user_cred projected;
	time_t now = time(NULL);

	if (op_ctx == NULL || (uint64_t)(uid_t)projection->uid != projection->uid ||
	    (uint64_t)(gid_t)projection->gid != projection->gid || now < 0 ||
	    projection->expiry <= (uint64_t)now)
		return false;
	memset(&projected, 0, sizeof(projected));
	projected.caller_uid = (uid_t)projection->uid;
	projected.caller_gid = (gid_t)projection->gid;
	op_ctx->creds = projected;
	op_ctx->original_creds = projected;
	return true;
}

static void clear_bytes(void *data, size_t length)
{
	volatile uint8_t *bytes = data;

	while (length-- != 0)
		*bytes++ = 0;
}

static bool encode_authentication(
	const struct filebelt_fsal_request_context *context,
	struct filebelt_pb_buffer *authentication)
{
	return filebelt_pb_string(authentication, 1, context->principal) &&
	       filebelt_pb_bytes(authentication, 2, context->gss_binding,
				 FILEBELT_GSS_BINDING_BYTES) &&
	       filebelt_pb_string(authentication, 3, context->source_address) &&
	       filebelt_pb_uint64(authentication, 4,
				  context->context_expires_at_unix_seconds) &&
	       filebelt_pb_string(authentication, 5, context->client_id) &&
	       filebelt_pb_string(authentication, 6, context->nfs_session_id) &&
	       filebelt_pb_uint64(authentication, 7, context->slot_id) &&
	       filebelt_pb_uint64(authentication, 8, context->sequence_id) &&
	       filebelt_pb_uint64(authentication, 9, context->operation_index);
}

static int verified_bridge_socket(pid_t *peer_pid)
{
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	struct stat metadata;
	struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
	struct ucred peer;
	socklen_t peer_length = sizeof(peer);
	int descriptor;
	int passcred = 1;

	if (peer_pid == NULL ||
	    !filebelt_process_identity_matches(
		    geteuid(), getegid(), FILEBELT_GANESHA_UID,
		    FILEBELT_GANESHA_GID) ||
	    lstat(FILEBELT_BRIDGE_SOCKET, &metadata) != 0 ||
	    !filebelt_socket_identity_matches(
		    metadata.st_mode, metadata.st_uid, metadata.st_gid,
		    FILEBELT_BRIDGE_UID))
		return -1;
	descriptor = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (descriptor < 0)
		return -1;
	if (strlen(FILEBELT_BRIDGE_SOCKET) >= sizeof(address.sun_path))
		goto fail;
	memcpy(address.sun_path, FILEBELT_BRIDGE_SOCKET,
	       sizeof(FILEBELT_BRIDGE_SOCKET));
	if (setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		       sizeof(timeout)) != 0 ||
	    setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout,
		       sizeof(timeout)) != 0 ||
	    setsockopt(descriptor, SOL_SOCKET, SO_PASSCRED, &passcred,
		       sizeof(passcred)) != 0 ||
	    connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0 ||
	    getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &peer,
		       &peer_length) != 0 ||
	    peer_length != sizeof(peer) ||
	    !filebelt_process_identity_matches(
		    peer.uid, peer.gid, FILEBELT_BRIDGE_UID,
		    FILEBELT_BRIDGE_GID))
		goto fail;
	*peer_pid = peer.pid;
	return descriptor;
fail:
	(void)close(descriptor);
	return -1;
}

int filebelt_bridge_call(const struct filebelt_fsal_request_context *context,
			 uint32_t operation_tag, const uint8_t *operation,
			 size_t operation_length, uint8_t *response,
			 size_t response_capacity, size_t *response_length)
{
	uint8_t authentication_storage[1024];
	struct filebelt_pb_buffer authentication;
	struct filebelt_pb_buffer request;
	uint8_t *packet = NULL;
	ssize_t received;
	ssize_t sent;
	uint32_t payload_length;
	struct filebelt_pb_field vfs_response;
	struct filebelt_private_projection projection;
	int descriptor = -1;
	int result = -1;
	pid_t peer_pid = -1;

	if (context == NULL || operation == NULL || operation_length == 0 ||
	    operation_length > FILEBELT_MAX_FRAME_BYTES || response == NULL ||
	    response_length == NULL || response_capacity > FILEBELT_MAX_FRAME_BYTES)
		return -1;
	filebelt_pb_init(&authentication, authentication_storage,
			 sizeof(authentication_storage));
	if (!encode_authentication(context, &authentication))
		goto out;
	packet = malloc(FILEBELT_MAX_FRAME_BYTES + FILEBELT_FRAME_PREFIX_BYTES);
	if (packet == NULL)
		goto out;
	filebelt_pb_init(&request, packet + FILEBELT_FRAME_PREFIX_BYTES,
			 FILEBELT_MAX_FRAME_BYTES);
	if (!filebelt_pb_uint64(&request, 1, FILEBELT_WIRE_FORMAT) ||
	    !filebelt_pb_bytes(&request, 2, authentication.data,
			       authentication.length) ||
	    !filebelt_pb_uint64(&request, 3, operation_tag) ||
	    !filebelt_pb_bytes(&request, 4, operation, operation_length) ||
	    request.length > UINT32_MAX)
		goto out;
	payload_length = (uint32_t)request.length;
	packet[0] = (uint8_t)(payload_length >> 24);
	packet[1] = (uint8_t)(payload_length >> 16);
	packet[2] = (uint8_t)(payload_length >> 8);
	packet[3] = (uint8_t)payload_length;
	descriptor = verified_bridge_socket(&peer_pid);
	if (descriptor < 0)
		goto out;
	sent = send(descriptor, packet,
		    request.length + FILEBELT_FRAME_PREFIX_BYTES, MSG_NOSIGNAL);
	if (sent < 0 || (size_t)sent != request.length + FILEBELT_FRAME_PREFIX_BYTES)
		goto out;
	received = filebelt_receive_authenticated_packet(
		descriptor, peer_pid, FILEBELT_BRIDGE_UID, FILEBELT_BRIDGE_GID, packet,
		FILEBELT_MAX_FRAME_BYTES + FILEBELT_FRAME_PREFIX_BYTES);
	if (received < FILEBELT_FRAME_PREFIX_BYTES ||
	    (size_t)received > FILEBELT_MAX_FRAME_BYTES + FILEBELT_FRAME_PREFIX_BYTES)
		goto out;
	payload_length = ((uint32_t)packet[0] << 24) |
			 ((uint32_t)packet[1] << 16) |
			 ((uint32_t)packet[2] << 8) | packet[3];
	if (payload_length != (size_t)received - FILEBELT_FRAME_PREFIX_BYTES ||
	    !parse_private_reply(packet + FILEBELT_FRAME_PREFIX_BYTES,
				 payload_length, &vfs_response, &projection) ||
	    vfs_response.length > response_capacity || !apply_projection(&projection))
		goto out;
	memcpy(response, vfs_response.bytes, vfs_response.length);
	*response_length = vfs_response.length;
	result = 0;
out:
	if (descriptor >= 0)
		(void)close(descriptor);
	clear_bytes(authentication_storage, sizeof(authentication_storage));
	if (packet != NULL) {
		clear_bytes(packet,
			    FILEBELT_MAX_FRAME_BYTES + FILEBELT_FRAME_PREFIX_BYTES);
		free(packet);
	}
	return result;
}

#endif /* FILEBELT_GANESHA_ABI */
