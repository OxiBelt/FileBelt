/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef FILEBELT_INTERNAL_H
#define FILEBELT_INTERNAL_H

#include "config.h"
#include "fsal.h"
#include "FSAL/fsal_commonlib.h"
#include "sal_data.h"
#include "filebelt_projection.h"
#include "filebelt_wire.h"

#include <pthread.h>
#include <stdatomic.h>

#define FILEBELT_MAX_EXPORTS 1000U
#define FILEBELT_HANDLE_BYTES 101U
#define FILEBELT_UUID_BYTES 37U
#define FILEBELT_EXPORT_PATH_BYTES 47U
#define FILEBELT_WIRE_HANDLE_BYTES 110U
#define FILEBELT_READDIR_SLOTS 64U
#define FILEBELT_CURSOR_BYTES 1025U
#define FILEBELT_LOCK_SLOTS 64U

struct filebelt_readdir_slot {
	fsal_cookie_t cookie;
	uint32_t skip;
	char cursor[FILEBELT_CURSOR_BYTES];
};

struct filebelt_lock_slot {
	uint64_t offset;
	uint64_t length;
	bool to_eof;
	char lock_id[FILEBELT_UUID_BYTES];
	char owner_key[256];
};

struct filebelt_manifest_entry {
	uint64_t export_id;
	uint64_t generation;
	char drive_id[FILEBELT_UUID_BYTES];
	char export_path[FILEBELT_EXPORT_PATH_BYTES];
	uint8_t root_handle[FILEBELT_HANDLE_BYTES];
	bool read_only;
};

struct filebelt_fsal_export {
	struct fsal_export export;
	pthread_rwlock_t manifest_lock;
	struct filebelt_manifest_entry *manifest;
	size_t manifest_count;
	uint64_t feature_generation;
	uint64_t export_generation;
	char boot_id[FILEBELT_UUID_BYTES];
	int control_listener;
	pthread_t control_thread;
	atomic_bool control_stopping;
	bool control_started;
	struct fsal_obj_handle *root;
};

struct filebelt_obj_handle {
	struct fsal_obj_handle obj;
	struct filebelt_fsal_export *export;
	uint64_t export_id;
	char drive_id[FILEBELT_UUID_BYTES];
	char resource_id[FILEBELT_UUID_BYTES];
	char head_version_id[FILEBELT_UUID_BYTES];
	struct filebelt_identity_projection projection;
	uint8_t persistent_handle[FILEBELT_HANDLE_BYTES];
	uint64_t namespace_generation;
	uint64_t acl_generation;
	bool virtual_root;
	bool unlinked;
	pthread_mutex_t state_lock;
	char commit_handle_id[FILEBELT_UUID_BYTES];
	char commit_write_session_id[FILEBELT_UUID_BYTES];
	char commit_expected_head_version_id[FILEBELT_UUID_BYTES];
	uint64_t commit_fencing_token;
	pthread_mutex_t readdir_lock;
	struct filebelt_readdir_slot readdir_slots[FILEBELT_READDIR_SLOTS];
	size_t next_readdir_slot;
};

struct filebelt_state {
	struct state_t state;
	pthread_mutex_t lock_lock;
	fsal_openflags_t openflags;
	char handle_id[FILEBELT_UUID_BYTES];
	char write_session_id[FILEBELT_UUID_BYTES];
	char expected_head_version_id[FILEBELT_UUID_BYTES];
	char state_id[FILEBELT_UUID_BYTES];
	uint64_t fencing_token;
	struct filebelt_lock_slot locks[FILEBELT_LOCK_SLOTS];
	size_t lock_count;
};

int filebelt_control_start(struct filebelt_fsal_export *export);
void filebelt_control_stop(struct filebelt_fsal_export *export);
bool filebelt_manifest_by_name(struct filebelt_fsal_export *export,
			      const char *name,
			      struct filebelt_manifest_entry *entry);
bool filebelt_manifest_by_export_id(struct filebelt_fsal_export *export,
				   uint64_t export_id,
				   struct filebelt_manifest_entry *entry);
size_t filebelt_manifest_snapshot(struct filebelt_fsal_export *export,
				 struct filebelt_manifest_entry *entries,
				 size_t capacity);
void filebelt_handle_ops_init(struct fsal_obj_ops *ops);
struct fsal_obj_ops *filebelt_module_handle_ops(void);
struct fsal_obj_handle *filebelt_allocate_root(
	struct filebelt_fsal_export *export);
fsal_status_t filebelt_resolve_handle(
	struct filebelt_fsal_export *export, uint64_t export_id,
	const uint8_t persistent_handle[FILEBELT_HANDLE_BYTES],
	struct fsal_obj_handle **handle, struct fsal_attrlist *attrs_out);
fsal_status_t filebelt_dynamic_info(struct filebelt_fsal_export *export,
				    struct fsal_obj_handle *obj_hdl,
				    fsal_dynamicfsinfo_t *info);
struct state_t *filebelt_alloc_state(struct fsal_export *exp_hdl,
				      enum state_type state_type,
				      struct state_t *related_state);

#endif /* FILEBELT_INTERNAL_H */
