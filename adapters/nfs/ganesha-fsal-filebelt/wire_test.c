/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "filebelt_wire.h"

#include <assert.h>
#include <string.h>

int main(void)
{
	uint8_t encoded[128];
	struct filebelt_pb_buffer buffer;
	struct filebelt_pb_cursor cursor;
	struct filebelt_pb_field field;
	static const uint8_t overlong[] = { 0x08, 0x80, 0x00 };

	filebelt_pb_init(&buffer, encoded, sizeof(encoded));
	assert(filebelt_pb_uint64(&buffer, 1, 300));
	assert(filebelt_pb_string(&buffer, 2, "filebelt"));
	assert(filebelt_pb_bytes(&buffer, 3, "\0\1", 2));
	filebelt_pb_cursor_init(&cursor, encoded, buffer.length);
	assert(filebelt_pb_next(&cursor, &field));
	assert(field.number == 1 && field.wire_type == 0 && field.varint == 300);
	assert(filebelt_pb_next(&cursor, &field));
	assert(field.number == 2 && field.length == 8 &&
	       memcmp(field.bytes, "filebelt", 8) == 0);
	assert(filebelt_pb_next(&cursor, &field));
	assert(field.number == 3 && field.length == 2);
	assert(filebelt_pb_finished(&cursor));

	filebelt_pb_cursor_init(&cursor, overlong, sizeof(overlong));
	assert(!filebelt_pb_next(&cursor, &field));
	return 0;
}
