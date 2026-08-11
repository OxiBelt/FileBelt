/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "filebelt_protocol.h"

#include <errno.h>
#include <string.h>

static bool set_slice(const struct filebelt_pb_field *field,
		      struct filebelt_slice *slice)
{
	if (field->wire_type != 2 || slice->data != NULL)
		return false;
	slice->data = field->bytes;
	slice->length = field->length;
	return true;
}

bool filebelt_response_parse(const uint8_t *encoded, size_t encoded_length,
			     struct filebelt_response *response)
{
	struct filebelt_pb_cursor cursor;
	struct filebelt_pb_field field;
	bool saw_protocol = false;
	bool saw_request = false;
	bool saw_error = false;

	if (encoded == NULL || response == NULL)
		return false;
	memset(response, 0, sizeof(*response));
	response->encoded = encoded;
	response->encoded_length = encoded_length;
	filebelt_pb_cursor_init(&cursor, encoded, encoded_length);
	while (cursor.offset < cursor.length && filebelt_pb_next(&cursor, &field)) {
		switch (field.number) {
		case 1:
			if (field.wire_type != 0 || saw_protocol || field.varint != 1)
				return false;
			saw_protocol = true;
			break;
		case 2:
			if (field.wire_type != 2 || saw_request || field.length != 36)
				return false;
			saw_request = true;
			break;
		case 3:
			if (field.wire_type != 0 || saw_error || field.varint > 19)
				return false;
			response->error = (uint32_t)field.varint;
			saw_error = true;
			break;
		case 6:
			if (!set_slice(&field, &response->handle_id))
				return false;
			break;
		case 7:
			if (!set_slice(&field, &response->write_session_id))
				return false;
			break;
		case 8:
			if (!set_slice(&field, &response->lock_id))
				return false;
			break;
		case 10:
			if (!set_slice(&field, &response->version_id))
				return false;
			break;
		case 13:
			if (field.wire_type != 0 || response->fencing_token != 0)
				return false;
			response->fencing_token = field.varint;
			break;
		case 15:
			if (!set_slice(&field, &response->data))
				return false;
			break;
		case 16:
			if (!set_slice(&field, &response->attributes))
				return false;
			break;
		case 17: /* Repeated directory entry, scanned on demand. */
			if (field.wire_type != 2)
				return false;
			break;
		case 18:
			if (!set_slice(&field, &response->next_cursor))
				return false;
			break;
		case 20:
			if (!set_slice(&field, &response->xattr_value))
				return false;
			break;
		case 21: /* Repeated xattr name, scanned by xattr callback. */
			if (field.wire_type != 2)
				return false;
			break;
		case 22:
			if (!set_slice(&field, &response->symlink_target))
				return false;
			break;
		case 23:
			if (!set_slice(&field, &response->state_id))
				return false;
			break;
		case 24:
			if (!set_slice(&field, &response->resource_id))
				return false;
			break;
		case 25:
			if (!set_slice(&field, &response->persistent_handle))
				return false;
			break;
		case 26:
			if (field.wire_type != 0 || response->export_id != 0)
				return false;
			response->export_id = field.varint;
			break;
		case 28:
			if (!set_slice(&field, &response->filesystem_info))
				return false;
			break;
		case 29:
			if (!set_slice(&field, &response->acl))
				return false;
			break;
		case 30:
			if (field.wire_type != 0 || response->sparse_offset != 0)
				return false;
			response->sparse_offset = field.varint;
			break;
		case 31:
			if (field.wire_type != 0 || field.varint > 1)
				return false;
			response->end_of_file = field.varint != 0;
			break;
		case 32: /* Repeated allowed action. */
			if (field.wire_type != 2)
				return false;
			break;
		case 34:
			if (!set_slice(&field, &response->lock_conflict))
				return false;
			break;
		default:
			/* Other defined envelope fields are not authoritative here. */
			if (field.number > 34)
				return false;
			break;
		}
	}
	return filebelt_pb_finished(&cursor) && saw_protocol && saw_request &&
	       saw_error && response->error != 0;
}

bool filebelt_lock_conflict_parse(const struct filebelt_slice *encoded,
				  struct filebelt_lock_conflict *conflict)
{
	struct filebelt_pb_cursor cursor;
	struct filebelt_pb_field field;
	bool saw_exclusive = false;
	bool saw_to_eof = false;

	if (encoded == NULL || encoded->data == NULL || conflict == NULL)
		return false;
	memset(conflict, 0, sizeof(*conflict));
	filebelt_pb_cursor_init(&cursor, encoded->data, encoded->length);
	while (cursor.offset < cursor.length && filebelt_pb_next(&cursor, &field)) {
		if (field.wire_type != 0)
			return false;
		switch (field.number) {
		case 1: conflict->offset = field.varint; break;
		case 2: conflict->length = field.varint; break;
		case 3:
			if (saw_exclusive || field.varint > 1)
				return false;
			conflict->exclusive = field.varint != 0;
			saw_exclusive = true;
			break;
		case 4:
			if (saw_to_eof || field.varint > 1)
				return false;
			conflict->to_eof = field.varint != 0;
			saw_to_eof = true;
			break;
		default: return false;
		}
	}
	return filebelt_pb_finished(&cursor) &&
	       ((conflict->to_eof && conflict->length == 0) ||
		(!conflict->to_eof && conflict->length != 0 &&
		 conflict->offset <= UINT64_MAX - conflict->length));
}

bool filebelt_attributes_parse(const struct filebelt_slice *encoded,
			       struct filebelt_node_attributes *attributes)
{
	struct filebelt_pb_cursor cursor;
	struct filebelt_pb_field field;

	if (encoded == NULL || encoded->data == NULL || attributes == NULL)
		return false;
	memset(attributes, 0, sizeof(*attributes));
	filebelt_pb_cursor_init(&cursor, encoded->data, encoded->length);
	while (cursor.offset < cursor.length && filebelt_pb_next(&cursor, &field)) {
		switch (field.number) {
		case 1: attributes->kind = (uint32_t)field.varint; break;
		case 2: attributes->size_bytes = field.varint; break;
		case 3:
			if (!set_slice(&field, &attributes->head_version_id)) return false;
			break;
		case 4: attributes->namespace_generation = field.varint; break;
		case 5: attributes->acl_generation = field.varint; break;
		case 6: attributes->modified_at = (int64_t)field.varint; break;
		case 7: attributes->read_only = field.varint != 0; break;
		case 8: attributes->mode = (uint32_t)field.varint; break;
		case 9: attributes->uid = field.varint; break;
		case 10: attributes->gid = field.varint; break;
		case 11: attributes->link_count = (uint32_t)field.varint; break;
		case 12: attributes->sparse = field.varint != 0; break;
		case 13: attributes->accessed_at = (int64_t)field.varint; break;
		case 14: attributes->created_at = (int64_t)field.varint; break;
		case 15: attributes->changed_at = (int64_t)field.varint; break;
		case 16:
			if (!set_slice(&field, &attributes->owner_name)) return false;
			break;
		case 17:
			if (!set_slice(&field, &attributes->group_name)) return false;
			break;
		default: return false;
		}
	}
	return filebelt_pb_finished(&cursor) && attributes->kind >= 1 &&
	       attributes->kind <= 3 && attributes->namespace_generation != 0 &&
	       attributes->acl_generation != 0 && attributes->mode <= 0777U;
}

static bool parse_entry(const uint8_t *encoded, size_t encoded_length,
			struct filebelt_directory_entry *entry)
{
	struct filebelt_pb_cursor cursor;
	struct filebelt_pb_field field;
	struct filebelt_slice attributes = { 0 };

	memset(entry, 0, sizeof(*entry));
	filebelt_pb_cursor_init(&cursor, encoded, encoded_length);
	while (cursor.offset < cursor.length && filebelt_pb_next(&cursor, &field)) {
		switch (field.number) {
		case 1:
			if (!set_slice(&field, &entry->resource_id)) return false;
			break;
		case 2:
			if (!set_slice(&field, &entry->display_name)) return false;
			break;
		case 3:
			if (!set_slice(&field, &attributes)) return false;
			break;
		case 4:
			if (!set_slice(&field, &entry->persistent_handle)) return false;
			break;
		default: return false;
		}
	}
	return filebelt_pb_finished(&cursor) && entry->resource_id.length == 36 &&
	       entry->display_name.length != 0 &&
	       entry->persistent_handle.length == FILEBELT_HANDLE_BYTES &&
	       filebelt_attributes_parse(&attributes, &entry->attributes);
}

size_t filebelt_response_entry_count(const struct filebelt_response *response)
{
	struct filebelt_pb_cursor cursor;
	struct filebelt_pb_field field;
	size_t count = 0;

	filebelt_pb_cursor_init(&cursor, response->encoded,
				 response->encoded_length);
	while (cursor.offset < cursor.length && filebelt_pb_next(&cursor, &field))
		if (field.number == 17)
			count++;
	return filebelt_pb_finished(&cursor) ? count : 0;
}

bool filebelt_response_entry(const struct filebelt_response *response,
			     size_t wanted,
			     struct filebelt_directory_entry *entry)
{
	struct filebelt_pb_cursor cursor;
	struct filebelt_pb_field field;
	size_t index = 0;

	filebelt_pb_cursor_init(&cursor, response->encoded,
				 response->encoded_length);
	while (cursor.offset < cursor.length && filebelt_pb_next(&cursor, &field)) {
		if (field.number == 17 && index++ == wanted)
			return parse_entry(field.bytes, field.length, entry);
	}
	return false;
}

bool filebelt_filesystem_info_parse(const struct filebelt_slice *encoded,
				    struct filebelt_filesystem_info *info)
{
	struct filebelt_pb_cursor cursor;
	struct filebelt_pb_field field;

	if (encoded == NULL || encoded->data == NULL || info == NULL)
		return false;
	memset(info, 0, sizeof(*info));
	filebelt_pb_cursor_init(&cursor, encoded->data, encoded->length);
	while (cursor.offset < cursor.length && filebelt_pb_next(&cursor, &field)) {
		if (field.wire_type != 0)
			return false;
		switch (field.number) {
		case 1: info->total_bytes = field.varint; break;
		case 2: info->free_bytes = field.varint; break;
		case 3: info->available_bytes = field.varint; break;
		case 4: info->total_files = field.varint; break;
		case 5: info->free_files = field.varint; break;
		case 6: info->maximum_file_size = field.varint; break;
		case 7:
			if (field.varint > UINT32_MAX) return false;
			info->maximum_name_bytes = (uint32_t)field.varint;
			break;
		case 8:
			if (field.varint > UINT32_MAX) return false;
			info->preferred_io_bytes = (uint32_t)field.varint;
			break;
		case 9:
			if (field.varint > 1) return false;
			info->supports_sparse_files = field.varint != 0;
			break;
		case 10:
			if (field.varint > 1) return false;
			info->supports_acl = field.varint != 0;
			break;
		case 11:
			if (field.varint > 1) return false;
			info->supports_xattr = field.varint != 0;
			break;
		default: return false;
		}
	}
	return filebelt_pb_finished(&cursor) && info->maximum_file_size != 0 &&
	       info->maximum_name_bytes != 0 && info->preferred_io_bytes != 0;
}

bool filebelt_acl_parse(const struct filebelt_slice *encoded,
			struct filebelt_acl *acl)
{
	struct filebelt_pb_cursor cursor;
	struct filebelt_pb_field field;

	if (encoded == NULL || encoded->data == NULL || acl == NULL)
		return false;
	memset(acl, 0, sizeof(*acl));
	acl->encoded = encoded->data;
	acl->encoded_length = encoded->length;
	filebelt_pb_cursor_init(&cursor, encoded->data, encoded->length);
	while (cursor.offset < cursor.length && filebelt_pb_next(&cursor, &field)) {
		switch (field.number) {
		case 1:
			if (field.wire_type != 0 || field.varint < 1 ||
			    field.varint > 2 || acl->representation != 0)
				return false;
			acl->representation = (uint32_t)field.varint;
			break;
		case 2:
			if (field.wire_type != 0 || field.varint == 0 ||
			    acl->generation != 0)
				return false;
			acl->generation = field.varint;
			break;
		case 3:
			if (field.wire_type != 2)
				return false;
			break;
		default: return false;
		}
	}
	return filebelt_pb_finished(&cursor) && acl->representation != 0 &&
	       acl->generation != 0;
}

static bool parse_packed_actions(const struct filebelt_pb_field *field,
				 struct filebelt_acl_entry *entry)
{
	size_t offset = 0;

	if (field->wire_type != 2)
		return false;
	while (offset < field->length) {
		uint64_t value = 0;
		unsigned int shift = 0;
		size_t start = offset;

		while (offset < field->length && shift < 70) {
			uint8_t byte;

			byte = field->bytes[offset++];
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
		    (field->bytes[offset - 1] & UINT8_C(0x80)) != 0)
			return false;
		if (value < 1 || value > 12 ||
		    entry->action_count >= sizeof(entry->actions) /
						 sizeof(entry->actions[0]))
			return false;
		entry->actions[entry->action_count++] = (uint32_t)value;
	}
	return entry->action_count != 0;
}

/* Decode a packed action list without accepting overlong varints. */
static bool packed_has_action(const uint8_t *encoded, size_t length,
			      uint32_t wanted)
{
	size_t offset = 0;

	while (offset < length) {
		uint64_t value = 0;
		unsigned int shift = 0;
		size_t start = offset;

		while (offset < length && shift < 70) {
			uint8_t byte = encoded[offset++];

			if (shift == 63 && (byte & UINT8_C(0xfe)) != 0)
				return false;
			value |= (uint64_t)(byte & UINT8_C(0x7f)) << shift;
			if ((byte & UINT8_C(0x80)) == 0) {
				if (offset - start > 1 && byte == 0)
					return false;
				if (value == wanted)
					return true;
				break;
			}
			shift += 7;
		}
		if (shift >= 70 ||
		    (offset == length &&
		     (encoded[offset - 1] & UINT8_C(0x80)) != 0))
			return false;
	}
	return false;
}

size_t filebelt_acl_entry_count(const struct filebelt_acl *acl)
{
	struct filebelt_pb_cursor cursor;
	struct filebelt_pb_field field;
	size_t count = 0;

	filebelt_pb_cursor_init(&cursor, acl->encoded, acl->encoded_length);
	while (cursor.offset < cursor.length && filebelt_pb_next(&cursor, &field))
		if (field.number == 3)
			count++;
	return filebelt_pb_finished(&cursor) ? count : 0;
}

bool filebelt_acl_entry(const struct filebelt_acl *acl, size_t wanted,
			struct filebelt_acl_entry *entry)
{
	struct filebelt_pb_cursor outer;
	struct filebelt_pb_field field;
	size_t index = 0;

	memset(entry, 0, sizeof(*entry));
	filebelt_pb_cursor_init(&outer, acl->encoded, acl->encoded_length);
	while (outer.offset < outer.length && filebelt_pb_next(&outer, &field)) {
		struct filebelt_pb_cursor inner;
		unsigned int seen = 0;

		if (field.number != 3 || index++ != wanted)
			continue;
		filebelt_pb_cursor_init(&inner, field.bytes, field.length);
		while (inner.offset < inner.length && filebelt_pb_next(&inner, &field)) {
			switch (field.number) {
			case 1:
				if (field.wire_type != 0 || field.varint != 1 ||
				    (seen & 1U) != 0) return false;
				seen |= 1U;
				break;
			case 2:
				if (field.wire_type != 0 || field.varint < 1 ||
				    field.varint > 5 || (seen & 2U) != 0) return false;
				entry->principal_kind = (uint32_t)field.varint;
				seen |= 2U;
				break;
			case 3:
				if (!set_slice(&field, &entry->principal)) return false;
				seen |= 4U;
				break;
			case 4:
				if (!parse_packed_actions(&field, entry)) return false;
				seen |= 8U;
				break;
			case 5:
				if (field.wire_type != 0 || field.varint < 1 ||
				    field.varint > 3 || (seen & 16U) != 0) return false;
				entry->inheritance = (uint32_t)field.varint;
				seen |= 16U;
				break;
			case 6:
				if (field.wire_type != 0 || field.varint != 1 ||
				    (seen & 32U) != 0) return false;
				entry->inherited = true;
				seen |= 32U;
				break;
			default: return false;
			}
		}
		return filebelt_pb_finished(&inner) && (seen & 27U) == 27U &&
		       ((entry->principal_kind <= 3 && entry->principal.length == 0) ||
			(entry->principal_kind >= 4 && entry->principal.length != 0));
	}
	return false;
}

size_t filebelt_response_xattr_count(const struct filebelt_response *response)
{
	struct filebelt_pb_cursor cursor;
	struct filebelt_pb_field field;
	size_t count = 0;

	filebelt_pb_cursor_init(&cursor, response->encoded,
				 response->encoded_length);
	while (cursor.offset < cursor.length && filebelt_pb_next(&cursor, &field))
		if (field.number == 21)
			count++;
	return filebelt_pb_finished(&cursor) ? count : 0;
}

bool filebelt_response_xattr_name(const struct filebelt_response *response,
				   size_t wanted,
				   struct filebelt_slice *name)
{
	struct filebelt_pb_cursor cursor;
	struct filebelt_pb_field field;
	size_t index = 0;

	memset(name, 0, sizeof(*name));
	filebelt_pb_cursor_init(&cursor, response->encoded,
				 response->encoded_length);
	while (cursor.offset < cursor.length && filebelt_pb_next(&cursor, &field))
		if (field.number == 21 && index++ == wanted)
			return set_slice(&field, name);
	return false;
}

bool filebelt_response_allows(const struct filebelt_response *response,
			      uint32_t action)
{
	struct filebelt_pb_cursor cursor;
	struct filebelt_pb_field field;

	filebelt_pb_cursor_init(&cursor, response->encoded,
				 response->encoded_length);
	while (cursor.offset < cursor.length && filebelt_pb_next(&cursor, &field))
		if (field.number == 32 && field.wire_type == 2 &&
		    packed_has_action(field.bytes, field.length, action))
			return true;
	return false;
}

bool filebelt_copy_slice(const struct filebelt_slice *slice, char *output,
			 size_t capacity)
{
	if (slice == NULL || slice->data == NULL || slice->length == 0 ||
	    slice->length >= capacity || memchr(slice->data, '\0', slice->length))
		return false;
	memcpy(output, slice->data, slice->length);
	output[slice->length] = '\0';
	return true;
}

fsal_status_t filebelt_vfs_status(uint32_t error)
{
	switch (error) {
	case 1: return fsalstat(ERR_FSAL_NO_ERROR, 0);
	case 2: return fsalstat(ERR_FSAL_INVAL, EINVAL);
	case 3: return fsalstat(ERR_FSAL_ACCESS, EACCES);
	case 4: return fsalstat(ERR_FSAL_ACCESS, EACCES);
	case 5: return fsalstat(ERR_FSAL_NOENT, ENOENT);
	case 6: return fsalstat(ERR_FSAL_EXIST, EEXIST);
	case 7: return fsalstat(ERR_FSAL_NOTDIR, ENOTDIR);
	case 8: return fsalstat(ERR_FSAL_ISDIR, EISDIR);
	case 9: return fsalstat(ERR_FSAL_NOTEMPTY, ENOTEMPTY);
	case 10: return fsalstat(ERR_FSAL_INVAL, EINVAL);
	case 11: return fsalstat(ERR_FSAL_EXIST, EEXIST);
	case 12: return fsalstat(ERR_FSAL_STALE, ESTALE);
	case 13: return fsalstat(ERR_FSAL_LOCKED, EAGAIN);
	case 14: return fsalstat(ERR_FSAL_DELAY, EAGAIN);
	case 15: return fsalstat(ERR_FSAL_DQUOT, EDQUOT);
	case 16: return fsalstat(ERR_FSAL_IO, EIO);
	case 17: return fsalstat(ERR_FSAL_DELAY, EAGAIN);
	case 18: return fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
	case 19: return fsalstat(ERR_FSAL_DELAY, EAGAIN);
	default: return fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
	}
}
