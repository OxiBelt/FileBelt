/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef FILEBELT_WIRE_H
#define FILEBELT_WIRE_H

#include "filebelt_fsal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FILEBELT_WIRE_FORMAT 1U
#define FILEBELT_MAX_FRAME_BYTES 1114112U
#define FILEBELT_MAX_DATA_BYTES 1048576U

struct filebelt_pb_buffer {
	uint8_t *data;
	size_t length;
	size_t capacity;
	bool failed;
};

struct filebelt_pb_cursor {
	const uint8_t *data;
	size_t length;
	size_t offset;
	uint32_t previous_field;
};

struct filebelt_pb_field {
	uint32_t number;
	uint8_t wire_type;
	uint64_t varint;
	const uint8_t *bytes;
	size_t length;
};

void filebelt_pb_init(struct filebelt_pb_buffer *buffer, uint8_t *data,
		      size_t capacity);
bool filebelt_pb_uint64(struct filebelt_pb_buffer *buffer, uint32_t field,
		       uint64_t value);
bool filebelt_pb_bool(struct filebelt_pb_buffer *buffer, uint32_t field,
		     bool value);
bool filebelt_pb_bytes(struct filebelt_pb_buffer *buffer, uint32_t field,
		      const void *value, size_t length);
bool filebelt_pb_string(struct filebelt_pb_buffer *buffer, uint32_t field,
		       const char *value);
void filebelt_pb_cursor_init(struct filebelt_pb_cursor *cursor,
			    const uint8_t *data, size_t length);
bool filebelt_pb_next(struct filebelt_pb_cursor *cursor,
		     struct filebelt_pb_field *field);
bool filebelt_pb_finished(const struct filebelt_pb_cursor *cursor);

#ifdef FILEBELT_GANESHA_ABI
int filebelt_bridge_call(const struct filebelt_fsal_request_context *context,
			 uint32_t operation_tag, const uint8_t *operation,
			 size_t operation_length, uint8_t *response,
			 size_t response_capacity, size_t *response_length);
#endif

#endif /* FILEBELT_WIRE_H */
