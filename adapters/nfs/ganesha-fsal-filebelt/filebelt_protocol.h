/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef FILEBELT_PROTOCOL_H
#define FILEBELT_PROTOCOL_H

#include "filebelt_internal.h"

struct filebelt_slice {
	const uint8_t *data;
	size_t length;
};

struct filebelt_node_attributes {
	uint32_t kind;
	uint64_t size_bytes;
	uint64_t namespace_generation;
	uint64_t acl_generation;
	int64_t modified_at;
	bool read_only;
	uint32_t mode;
	uint64_t uid;
	uint64_t gid;
	uint32_t link_count;
	bool sparse;
	int64_t accessed_at;
	int64_t created_at;
	int64_t changed_at;
	struct filebelt_slice head_version_id;
	struct filebelt_slice owner_name;
	struct filebelt_slice group_name;
};

struct filebelt_response {
	uint32_t error;
	uint64_t fencing_token;
	uint64_t export_id;
	uint64_t sparse_offset;
	bool end_of_file;
	struct filebelt_slice handle_id;
	struct filebelt_slice write_session_id;
	struct filebelt_slice lock_id;
	struct filebelt_slice version_id;
	struct filebelt_slice data;
	struct filebelt_slice attributes;
	struct filebelt_slice next_cursor;
	struct filebelt_slice xattr_value;
	struct filebelt_slice symlink_target;
	struct filebelt_slice state_id;
	struct filebelt_slice resource_id;
	struct filebelt_slice persistent_handle;
	struct filebelt_slice filesystem_info;
	struct filebelt_slice acl;
	struct filebelt_slice lock_conflict;
	const uint8_t *encoded;
	size_t encoded_length;
};

struct filebelt_lock_conflict {
	uint64_t offset;
	uint64_t length;
	bool exclusive;
	bool to_eof;
};

struct filebelt_directory_entry {
	struct filebelt_slice resource_id;
	struct filebelt_slice display_name;
	struct filebelt_slice persistent_handle;
	struct filebelt_node_attributes attributes;
};

struct filebelt_filesystem_info {
	uint64_t total_bytes;
	uint64_t free_bytes;
	uint64_t available_bytes;
	uint64_t total_files;
	uint64_t free_files;
	uint64_t maximum_file_size;
	uint32_t maximum_name_bytes;
	uint32_t preferred_io_bytes;
	bool supports_sparse_files;
	bool supports_acl;
	bool supports_xattr;
};

struct filebelt_acl_entry {
	uint32_t principal_kind;
	uint32_t inheritance;
	bool inherited;
	struct filebelt_slice principal;
	uint32_t actions[12];
	size_t action_count;
};

struct filebelt_acl {
	uint32_t representation;
	uint64_t generation;
	const uint8_t *encoded;
	size_t encoded_length;
};

bool filebelt_response_parse(const uint8_t *encoded, size_t encoded_length,
			     struct filebelt_response *response);
bool filebelt_attributes_parse(const struct filebelt_slice *encoded,
			       struct filebelt_node_attributes *attributes);
bool filebelt_response_entry(const struct filebelt_response *response,
			     size_t wanted,
			     struct filebelt_directory_entry *entry);
size_t filebelt_response_entry_count(const struct filebelt_response *response);
bool filebelt_filesystem_info_parse(const struct filebelt_slice *encoded,
				    struct filebelt_filesystem_info *info);
bool filebelt_acl_parse(const struct filebelt_slice *encoded,
			struct filebelt_acl *acl);
size_t filebelt_acl_entry_count(const struct filebelt_acl *acl);
bool filebelt_acl_entry(const struct filebelt_acl *acl, size_t wanted,
			struct filebelt_acl_entry *entry);
bool filebelt_lock_conflict_parse(const struct filebelt_slice *encoded,
				  struct filebelt_lock_conflict *conflict);
size_t filebelt_response_xattr_count(const struct filebelt_response *response);
bool filebelt_response_xattr_name(const struct filebelt_response *response,
				   size_t wanted,
				   struct filebelt_slice *name);
bool filebelt_response_allows(const struct filebelt_response *response,
			      uint32_t action);
bool filebelt_copy_slice(const struct filebelt_slice *slice, char *output,
			 size_t capacity);
fsal_status_t filebelt_vfs_status(uint32_t error);

#endif /* FILEBELT_PROTOCOL_H */
