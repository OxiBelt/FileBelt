/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * FSAL 13.0 object callbacks for the protocol-neutral FileBelt VFS.
 *
 * This translation unit deliberately knows only persistent VFS handles,
 * resource identifiers, generic operations, and the minimal verified GSS
 * context captured by fsal_filebelt.c.  It never receives a payload path,
 * database credential, capability key, Kerberos ticket, or AUTH_SYS identity.
 */

#include "filebelt_protocol.h"

#include "nfs4_acls.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FILEBELT_OPERATION_BYTES (FILEBELT_MAX_DATA_BYTES + 4096U)
#define FILEBELT_LIST_LIMIT 256U
#define FILEBELT_ROOT_FILEID UINT64_C(1)

enum filebelt_operation_tag {
	FILEBELT_OP_LIST = 21,
	FILEBELT_OP_STAT = 22,
	FILEBELT_OP_OPEN = 23,
	FILEBELT_OP_READ = 24,
	FILEBELT_OP_WRITE = 25,
	FILEBELT_OP_FLUSH = 26,
	FILEBELT_OP_COMMIT = 27,
	FILEBELT_OP_CLOSE = 28,
	FILEBELT_OP_CREATE = 29,
	FILEBELT_OP_MKDIR = 30,
	FILEBELT_OP_RENAME = 31,
	FILEBELT_OP_REMOVE = 32,
	FILEBELT_OP_SETATTR = 33,
	FILEBELT_OP_LOCK = 34,
	FILEBELT_OP_UNLOCK = 35,
	FILEBELT_OP_GET_XATTR = 42,
	FILEBELT_OP_SET_XATTR = 43,
	FILEBELT_OP_LIST_XATTR = 44,
	FILEBELT_OP_REMOVE_XATTR = 45,
	FILEBELT_OP_READLINK = 46,
	FILEBELT_OP_SYMLINK = 47,
	FILEBELT_OP_SPARSE_WRITE = 48,
	FILEBELT_OP_RECLAIM = 49,
	FILEBELT_OP_OPEN_UNLINKED = 50,
	FILEBELT_OP_RESOLVE_HANDLE = 51,
	FILEBELT_OP_EXPORT_ROOT = 52,
	FILEBELT_OP_LOOKUP = 53,
	FILEBELT_OP_ACCESS = 54,
	FILEBELT_OP_FILESYSTEM_INFO = 55,
	FILEBELT_OP_GET_ACL = 56,
	FILEBELT_OP_SET_ACL = 57,
	FILEBELT_OP_SPARSE_CONTROL = 58,
	FILEBELT_OP_TEST_LOCK = 61,
};

enum filebelt_vfs_action {
	FILEBELT_ACTION_READ_METADATA = 1,
	FILEBELT_ACTION_READ_CONTENT = 2,
	FILEBELT_ACTION_CREATE_CHILD = 3,
	FILEBELT_ACTION_WRITE_CONTENT = 4,
	FILEBELT_ACTION_DELETE = 5,
	FILEBELT_ACTION_RENAME = 6,
	FILEBELT_ACTION_MOVE = 7,
	FILEBELT_ACTION_WRITE_METADATA = 8,
	FILEBELT_ACTION_MANAGE_LOCK = 9,
	FILEBELT_ACTION_LIST_CHILDREN = 10,
	FILEBELT_ACTION_TRAVERSE = 11,
	FILEBELT_ACTION_MANAGE_ACL = 12,
};

struct filebelt_call_result {
	uint8_t *storage;
	struct filebelt_response response;
};

static fsal_status_t filebelt_get_acl_attributes(
	struct filebelt_obj_handle *object, struct fsal_attrlist *attrs);

static struct filebelt_obj_handle *filebelt_obj(struct fsal_obj_handle *obj)
{
	return container_of(obj, struct filebelt_obj_handle, obj);
}

static const struct filebelt_obj_handle *
filebelt_const_obj(const struct fsal_obj_handle *obj)
{
	return container_of(obj, const struct filebelt_obj_handle, obj);
}

static struct filebelt_state *filebelt_fsal_state(struct state_t *state)
{
	return state == NULL ? NULL :
		container_of(state, struct filebelt_state, state);
}

static void call_result_release(struct filebelt_call_result *result)
{
	if (result->storage != NULL) {
		memset(result->storage, 0, FILEBELT_MAX_FRAME_BYTES);
		gsh_free(result->storage);
	}
	memset(result, 0, sizeof(*result));
}

static fsal_status_t call_vfs(uint32_t operation_tag,
			      const struct filebelt_pb_buffer *operation,
			      struct filebelt_call_result *result)
{
	struct filebelt_fsal_request_context context;
	size_t response_length = 0;

	memset(result, 0, sizeof(*result));
	if (operation == NULL || operation->failed || operation->length == 0 ||
	    !filebelt_fsal_capture_request(&context))
		return fsalstat(ERR_FSAL_ACCESS, EACCES);
	result->storage = gsh_malloc(FILEBELT_MAX_FRAME_BYTES);
	if (result->storage == NULL)
		return fsalstat(ERR_FSAL_NOMEM, ENOMEM);
	if (filebelt_bridge_call(&context, operation_tag, operation->data,
				 operation->length, result->storage,
				 FILEBELT_MAX_FRAME_BYTES, &response_length) != 0 ||
	    !filebelt_response_parse(result->storage, response_length,
				     &result->response)) {
		call_result_release(result);
		return fsalstat(ERR_FSAL_IO, EIO);
	}
	return filebelt_vfs_status(result->response.error);
}

static bool append_actions(struct filebelt_pb_buffer *operation,
			   uint32_t field, const uint8_t *actions,
			   size_t action_count)
{
	/* Every VfsAction value is a one-byte canonical protobuf varint. */
	if (action_count == 0 || action_count > 12)
		return false;
	for (size_t index = 0; index < action_count; index++)
		if (actions[index] == 0 || actions[index] > 12 ||
		    (index != 0 && actions[index - 1] >= actions[index]))
			return false;
	return filebelt_pb_bytes(operation, field, actions, action_count);
}

static uint64_t fileid_from_handle(const uint8_t *handle, size_t length)
{
	uint64_t hash = UINT64_C(1469598103934665603);

	for (size_t index = 0; index < length; index++) {
		hash ^= handle[index];
		hash *= UINT64_C(1099511628211);
	}
	return hash == 0 || hash == FILEBELT_ROOT_FILEID ? hash + 2 : hash;
}

static object_file_type_t node_type(uint32_t kind)
{
	switch (kind) {
	case 1: return REGULAR_FILE;
	case 2: return DIRECTORY;
	case 3: return SYMBOLIC_LINK;
	default: return NO_FILE_TYPE;
	}
}

static bool projected_name(const struct filebelt_slice *name)
{
	if (name == NULL || name->data == NULL || name->length == 0 ||
	    name->length > 255 ||
	    !(name->data[0] == '_' ||
	      (name->data[0] >= 'a' && name->data[0] <= 'z')))
		return false;
	for (size_t index = 1; index < name->length; index++) {
		uint8_t byte = name->data[index];

		if (!((byte >= 'a' && byte <= 'z') ||
		      (byte >= '0' && byte <= '9') || byte == '_' ||
		      byte == '.' || byte == '-'))
			return false;
	}
	return true;
}

static bool projected_identity_valid(
	const struct filebelt_node_attributes *source)
{
	return source != NULL && source->uid != 0 && source->gid != 0 &&
	       source->uid != 65534 && source->gid != 65534 &&
	       source->uid <= UINT32_MAX && source->gid <= UINT32_MAX &&
	       projected_name(&source->owner_name) &&
	       projected_name(&source->group_name);
}

static void fill_root_attributes(struct fsal_attrlist *attrs)
{
	attrmask_t request = attrs->request_mask;

	memset(attrs, 0, sizeof(*attrs));
	attrs->request_mask = request;
	attrs->valid_mask = ATTRS_POSIX | ATTR_CREATION;
	attrs->supported = ATTRS_POSIX | ATTR_CREATION | ATTR_ACL;
	attrs->type = DIRECTORY;
	attrs->fsid.major = 0;
	attrs->fsid.minor = 1;
	attrs->fileid = FILEBELT_ROOT_FILEID;
	attrs->mode = 0555;
	attrs->numlinks = 2;
	attrs->owner = 65534;
	attrs->group = 65534;
	attrs->change = 1;
	attrs->expire_time_attr = 0;
}

static bool fill_attributes(struct filebelt_obj_handle *object,
			    const struct filebelt_node_attributes *source,
			    struct fsal_attrlist *attrs)
{
	attrmask_t request;
	object_file_type_t type = node_type(source->kind);

	if (type == NO_FILE_TYPE || !projected_identity_valid(source) ||
	    !filebelt_projection_matches(
		    &object->projection, (uint32_t)source->uid,
		    (uint32_t)source->gid, source->owner_name.data,
		    source->owner_name.length, source->group_name.data,
		    source->group_name.length))
		return false;
	request = attrs->request_mask;
	memset(attrs, 0, sizeof(*attrs));
	attrs->request_mask = request;
	attrs->valid_mask = ATTRS_POSIX | ATTR_CREATION;
	attrs->supported = ATTRS_POSIX | ATTR_CREATION | ATTR_ACL;
	attrs->type = type;
	attrs->filesize = source->size_bytes;
	attrs->spaceused = source->size_bytes;
	attrs->fsid.major = object->export_id;
	attrs->fsid.minor = 0;
	attrs->fileid = fileid_from_handle(object->persistent_handle,
					 FILEBELT_HANDLE_BYTES);
	attrs->mode = source->mode;
	attrs->numlinks = source->link_count == 0 ? 1 : source->link_count;
	attrs->owner = source->uid;
	attrs->group = source->gid;
	attrs->mtime.tv_sec = source->modified_at;
	attrs->atime.tv_sec = source->accessed_at;
	attrs->creation.tv_sec = source->created_at;
	attrs->ctime.tv_sec = source->changed_at;
	attrs->change = source->namespace_generation ^
			(source->acl_generation << 1);
	attrs->expire_time_attr = 0;
	object->namespace_generation = source->namespace_generation;
	object->acl_generation = source->acl_generation;
	if (source->head_version_id.length != 0) {
		if (source->head_version_id.length != FILEBELT_UUID_BYTES - 1)
			return false;
		memcpy(object->head_version_id, source->head_version_id.data,
		       source->head_version_id.length);
		object->head_version_id[source->head_version_id.length] = '\0';
	} else {
		object->head_version_id[0] = '\0';
	}
	object->obj.type = type;
	object->obj.fsid = attrs->fsid;
	object->obj.fileid = attrs->fileid;
	return true;
}

static struct filebelt_obj_handle *allocate_object(
	struct filebelt_fsal_export *export, uint64_t export_id,
	const char *drive_id, const struct filebelt_slice *resource_id,
	const struct filebelt_slice *persistent_handle,
	const struct filebelt_node_attributes *attributes)
{
	struct filebelt_obj_handle *object;
	struct fsal_attrlist attrs = { 0 };

	if (drive_id == NULL || resource_id == NULL ||
	    resource_id->length != FILEBELT_UUID_BYTES - 1 ||
	    persistent_handle == NULL ||
	    persistent_handle->length != FILEBELT_HANDLE_BYTES ||
	    !projected_identity_valid(attributes))
		return NULL;
	object = gsh_calloc(1, sizeof(*object));
	object->export = export;
	object->export_id = export_id;
	memcpy(object->drive_id, drive_id, FILEBELT_UUID_BYTES);
	memcpy(object->resource_id, resource_id->data, resource_id->length);
	memcpy(object->persistent_handle, persistent_handle->data,
	       persistent_handle->length);
	object->resource_id[resource_id->length] = '\0';
	if (!filebelt_projection_initialize(
		    &object->projection, (uint32_t)attributes->uid,
		    (uint32_t)attributes->gid, attributes->owner_name.data,
		    attributes->owner_name.length, attributes->group_name.data,
		    attributes->group_name.length)) {
		gsh_free(object);
		return NULL;
	}
	if (pthread_mutex_init(&object->readdir_lock, NULL) != 0) {
		gsh_free(object);
		return NULL;
	}
	if (pthread_mutex_init(&object->state_lock, NULL) != 0) {
		pthread_mutex_destroy(&object->readdir_lock);
		gsh_free(object);
		return NULL;
	}
	fsal_obj_handle_init(&object->obj, &export->export,
			     node_type(attributes->kind), true);
	object->obj.obj_ops = filebelt_module_handle_ops();
	if (!fill_attributes(object, attributes, &attrs)) {
		fsal_obj_handle_fini(&object->obj, true);
		pthread_mutex_destroy(&object->state_lock);
		pthread_mutex_destroy(&object->readdir_lock);
		gsh_free(object);
		return NULL;
	}
	return object;
}

static struct filebelt_obj_handle *allocate_virtual_root(
	struct filebelt_fsal_export *export)
{
	struct filebelt_obj_handle *root = gsh_calloc(1, sizeof(*root));

	root->export = export;
	root->virtual_root = true;
	if (pthread_mutex_init(&root->readdir_lock, NULL) != 0) {
		gsh_free(root);
		return NULL;
	}
	if (pthread_mutex_init(&root->state_lock, NULL) != 0) {
		pthread_mutex_destroy(&root->readdir_lock);
		gsh_free(root);
		return NULL;
	}
	fsal_obj_handle_init(&root->obj, &export->export, DIRECTORY, true);
	root->obj.obj_ops = filebelt_module_handle_ops();
	root->obj.fsid.major = 0;
	root->obj.fsid.minor = 1;
	root->obj.fileid = FILEBELT_ROOT_FILEID;
	return root;
}

static fsal_status_t object_from_response(
	struct filebelt_fsal_export *export, uint64_t export_id,
	const char *drive_id, const struct filebelt_response *response,
	struct fsal_obj_handle **handle, struct fsal_attrlist *attrs_out)
{
	struct filebelt_node_attributes attributes;
	struct filebelt_obj_handle *object;

	if (!filebelt_attributes_parse(&response->attributes, &attributes) ||
	    response->resource_id.length != FILEBELT_UUID_BYTES - 1 ||
	    response->persistent_handle.length != FILEBELT_HANDLE_BYTES)
		return fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
	object = allocate_object(export, export_id, drive_id,
				 &response->resource_id,
				 &response->persistent_handle, &attributes);
	if (object == NULL)
		return fsalstat(ERR_FSAL_NOMEM, ENOMEM);
	*handle = &object->obj;
	if (attrs_out != NULL && !fill_attributes(object, &attributes, attrs_out)) {
		object->obj.obj_ops->release(&object->obj);
		*handle = NULL;
		return fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
	}
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static void filebelt_release(struct fsal_obj_handle *obj_hdl)
{
	struct filebelt_obj_handle *object = filebelt_obj(obj_hdl);

	fsal_obj_handle_fini(obj_hdl, true);
	pthread_mutex_destroy(&object->state_lock);
	pthread_mutex_destroy(&object->readdir_lock);
	memset(object, 0, sizeof(*object));
	gsh_free(object);
}

static fsal_status_t filebelt_handle_to_wire(
	const struct fsal_obj_handle *obj_hdl, fsal_digesttype_t output_type,
	struct gsh_buffdesc *fh_desc)
{
	const struct filebelt_obj_handle *object = filebelt_const_obj(obj_hdl);
	uint8_t *wire = fh_desc->addr;

	(void)output_type;
	if (fh_desc->len < FILEBELT_WIRE_HANDLE_BYTES)
		return fsalstat(ERR_FSAL_TOOSMALL, ERANGE);
	memset(wire, 0, FILEBELT_WIRE_HANDLE_BYTES);
	if (object->virtual_root) {
		wire[0] = 1;
	} else {
		wire[0] = 2;
		for (size_t index = 0; index < 8; index++)
			wire[1 + index] =
				(uint8_t)(object->export_id >> (56U - 8U * index));
		memcpy(wire + 9, object->persistent_handle,
		       FILEBELT_HANDLE_BYTES);
	}
	fh_desc->len = FILEBELT_WIRE_HANDLE_BYTES;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static void filebelt_handle_to_key(struct fsal_obj_handle *obj_hdl,
				   struct gsh_buffdesc *fh_desc)
{
	struct filebelt_obj_handle *object = filebelt_obj(obj_hdl);

	if (object->virtual_root) {
		fh_desc->addr = &object->virtual_root;
		fh_desc->len = sizeof(object->virtual_root);
	} else {
		fh_desc->addr = object->persistent_handle;
		fh_desc->len = FILEBELT_HANDLE_BYTES;
	}
}

static bool filebelt_handle_cmp(struct fsal_obj_handle *first,
				struct fsal_obj_handle *second)
{
	struct filebelt_obj_handle *a = filebelt_obj(first);
	struct filebelt_obj_handle *b = filebelt_obj(second);

	return a->virtual_root == b->virtual_root &&
	       (a->virtual_root ||
		(a->export_id == b->export_id &&
		 memcmp(a->persistent_handle, b->persistent_handle,
			FILEBELT_HANDLE_BYTES) == 0));
}

static fsal_status_t export_root_object(
	struct filebelt_fsal_export *export,
	const struct filebelt_manifest_entry *manifest,
	struct fsal_obj_handle **handle, struct fsal_attrlist *attrs_out)
{
	uint8_t encoded[32];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;

	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_uint64(&operation, 1, manifest->export_id);
	status = call_vfs(FILEBELT_OP_EXPORT_ROOT, &operation, &result);
	if (FSAL_IS_ERROR(status)) {
		call_result_release(&result);
		return status;
	}
	if (result.response.export_id != manifest->export_id ||
	    result.response.persistent_handle.length != FILEBELT_HANDLE_BYTES ||
	    memcmp(result.response.persistent_handle.data, manifest->root_handle,
		   FILEBELT_HANDLE_BYTES) != 0) {
		status = fsalstat(ERR_FSAL_STALE, ESTALE);
	} else {
		status = object_from_response(export, manifest->export_id,
					      manifest->drive_id,
					      &result.response, handle,
					      attrs_out);
	}
	call_result_release(&result);
	return status;
}

static fsal_status_t filebelt_lookup(struct fsal_obj_handle *dir_hdl,
				     const char *path,
				     struct fsal_obj_handle **handle,
				     struct fsal_attrlist *attrs_out)
{
	struct filebelt_obj_handle *parent = filebelt_obj(dir_hdl);
	struct filebelt_manifest_entry manifest;
	uint8_t encoded[1400];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;

	if (dir_hdl->type != DIRECTORY)
		return fsalstat(ERR_FSAL_NOTDIR, ENOTDIR);
	if (path == NULL || path[0] == '\0' || strlen(path) > 255)
		return fsalstat(ERR_FSAL_INVAL, EINVAL);
	if (parent->virtual_root) {
		if (!filebelt_manifest_by_name(parent->export, path, &manifest))
			return fsalstat(ERR_FSAL_NOENT, ENOENT);
		return export_root_object(parent->export, &manifest, handle,
					  attrs_out);
	}
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_bytes(&operation, 1, parent->persistent_handle,
				FILEBELT_HANDLE_BYTES);
	(void)filebelt_pb_string(&operation, 2, path);
	status = call_vfs(FILEBELT_OP_LOOKUP, &operation, &result);
	if (!FSAL_IS_ERROR(status))
		status = object_from_response(parent->export, parent->export_id,
					      parent->drive_id,
					      &result.response, handle,
					      attrs_out);
	call_result_release(&result);
	return status;
}

static fsal_status_t filebelt_stat(struct filebelt_obj_handle *object,
				   struct filebelt_node_attributes *attributes)
{
	uint8_t encoded[512];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;

	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, object->drive_id);
	(void)filebelt_pb_string(&operation, 2, object->resource_id);
	(void)filebelt_pb_bytes(&operation, 3, object->persistent_handle,
				FILEBELT_HANDLE_BYTES);
	status = call_vfs(FILEBELT_OP_STAT, &operation, &result);
	if (!FSAL_IS_ERROR(status) &&
	    !filebelt_attributes_parse(&result.response.attributes, attributes))
		status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
	call_result_release(&result);
	return status;
}

static fsal_status_t filebelt_getattrs(struct fsal_obj_handle *obj_hdl,
				       struct fsal_attrlist *attrs_out)
{
	struct filebelt_obj_handle *object = filebelt_obj(obj_hdl);
	struct filebelt_node_attributes attributes;
	fsal_status_t status;

	if (object->virtual_root) {
		fill_root_attributes(attrs_out);
		return fsalstat(ERR_FSAL_NO_ERROR, 0);
	}
	status = filebelt_stat(object, &attributes);
	if (!FSAL_IS_ERROR(status) &&
	    !fill_attributes(object, &attributes, attrs_out))
		status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
	if (!FSAL_IS_ERROR(status) &&
	    FSAL_TEST_MASK(attrs_out->request_mask, ATTR_ACL))
		status = filebelt_get_acl_attributes(object, attrs_out);
	if (FSAL_IS_ERROR(status) &&
	    FSAL_TEST_MASK(attrs_out->request_mask, ATTR_RDATTR_ERR)) {
		attrs_out->valid_mask = ATTR_RDATTR_ERR;
		return fsalstat(ERR_FSAL_NO_ERROR, 0);
	}
	return status;
}

static fsal_status_t root_readdir(struct filebelt_obj_handle *directory,
				  fsal_cookie_t *whence, void *dir_state,
				  fsal_readdir_cb callback,
				  attrmask_t attrmask, bool *eof)
{
	struct filebelt_manifest_entry *entries;
	size_t count;
	size_t start;

	if (whence == NULL || *whence == 0) {
		start = 0;
	} else if (*whence < FIRST_COOKIE) {
		return fsalstat(ERR_FSAL_BADCOOKIE, EINVAL);
	} else {
		start = (size_t)(*whence - FIRST_COOKIE);
	}

	entries = gsh_calloc(FILEBELT_MAX_EXPORTS, sizeof(*entries));
	count = filebelt_manifest_snapshot(directory->export, entries,
					 FILEBELT_MAX_EXPORTS);
	if (count > FILEBELT_MAX_EXPORTS || start > count) {
		gsh_free(entries);
		return fsalstat(ERR_FSAL_BADCOOKIE, EINVAL);
	}
	*eof = true;
	for (size_t index = start; index < count; index++) {
		struct fsal_obj_handle *child = NULL;
		struct fsal_attrlist attrs;
		enum fsal_dir_result callback_result;
		fsal_status_t status;

		fsal_prepare_attrs(&attrs, attrmask);
		status = export_root_object(directory->export, &entries[index],
					    &child, &attrs);
		if (FSAL_IS_ERROR(status)) {
			fsal_release_attrs(&attrs);
			if (status.major == ERR_FSAL_ACCESS ||
			    status.major == ERR_FSAL_NOENT)
				continue;
			gsh_free(entries);
			return status;
		}
		callback_result = callback(entries[index].drive_id, child, &attrs,
					   dir_state, FIRST_COOKIE + index + 1);
		fsal_release_attrs(&attrs);
		if (callback_result >= DIR_TERMINATE) {
			*eof = false;
			break;
		}
	}
	gsh_free(entries);
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static bool remember_readdir(struct filebelt_obj_handle *directory,
			     fsal_cookie_t cookie, const char *cursor,
			     uint32_t skip)
{
	struct filebelt_readdir_slot *slot =
		&directory->readdir_slots[directory->next_readdir_slot];

	if (strlen(cursor) >= sizeof(slot->cursor))
		return false;
	slot->cookie = cookie;
	slot->skip = skip;
	memcpy(slot->cursor, cursor, strlen(cursor) + 1);
	directory->next_readdir_slot =
		(directory->next_readdir_slot + 1) % FILEBELT_READDIR_SLOTS;
	return true;
}

static bool resume_readdir(struct filebelt_obj_handle *directory,
			   fsal_cookie_t cookie, char *cursor, uint32_t *skip)
{
	for (size_t index = 0; index < FILEBELT_READDIR_SLOTS; index++) {
		if (directory->readdir_slots[index].cookie == cookie) {
			memcpy(cursor, directory->readdir_slots[index].cursor,
			       sizeof(directory->readdir_slots[index].cursor));
			*skip = directory->readdir_slots[index].skip;
			return true;
		}
	}
	return false;
}

static fsal_status_t filebelt_readdir(struct fsal_obj_handle *dir_hdl,
				      fsal_cookie_t *whence, void *dir_state,
				      fsal_readdir_cb callback,
				      attrmask_t attrmask, bool *eof)
{
	struct filebelt_obj_handle *directory = filebelt_obj(dir_hdl);
	char cursor[FILEBELT_CURSOR_BYTES] = { 0 };
	uint32_t skip = 0;
	uint8_t encoded[1600];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_cookie_t base_cookie =
		whence == NULL || *whence == 0 ? FIRST_COOKIE - 1 : *whence;
	fsal_status_t status;
	size_t entry_count;

	if (dir_hdl->type != DIRECTORY)
		return fsalstat(ERR_FSAL_NOTDIR, ENOTDIR);
	if (directory->virtual_root)
		return root_readdir(directory, whence, dir_state, callback,
				    attrmask, eof);
	pthread_mutex_lock(&directory->readdir_lock);
	if (whence != NULL && *whence != 0 &&
	    !resume_readdir(directory, base_cookie, cursor, &skip)) {
		pthread_mutex_unlock(&directory->readdir_lock);
		return fsalstat(ERR_FSAL_BADCOOKIE, EINVAL);
	}
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, directory->drive_id);
	(void)filebelt_pb_string(&operation, 2, directory->resource_id);
	if (cursor[0] != '\0')
		(void)filebelt_pb_string(&operation, 3, cursor);
	(void)filebelt_pb_uint64(&operation, 4, FILEBELT_LIST_LIMIT);
	(void)filebelt_pb_bytes(&operation, 5, directory->persistent_handle,
				FILEBELT_HANDLE_BYTES);
	status = call_vfs(FILEBELT_OP_LIST, &operation, &result);
	if (FSAL_IS_ERROR(status)) {
		pthread_mutex_unlock(&directory->readdir_lock);
		return status;
	}
	entry_count = filebelt_response_entry_count(&result.response);
	if (skip > entry_count) {
		status = fsalstat(ERR_FSAL_BADCOOKIE, EINVAL);
		goto out;
	}
	*eof = result.response.end_of_file;
	for (size_t index = skip; index < entry_count; index++) {
		struct filebelt_directory_entry entry;
		struct filebelt_obj_handle *child;
		struct fsal_attrlist attrs;
		char name[256];
		fsal_cookie_t next_cookie = base_cookie + 1;
		enum fsal_dir_result callback_result;

		if (!filebelt_response_entry(&result.response, index, &entry) ||
		    !filebelt_copy_slice(&entry.display_name, name, sizeof(name))) {
			status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
			goto out;
		}
		child = allocate_object(directory->export, directory->export_id,
					directory->drive_id, &entry.resource_id,
					&entry.persistent_handle,
					&entry.attributes);
		if (child == NULL) {
			status = fsalstat(ERR_FSAL_NOMEM, ENOMEM);
			goto out;
		}
		fsal_prepare_attrs(&attrs, attrmask);
		if (!fill_attributes(child, &entry.attributes, &attrs) ||
		    !remember_readdir(directory, next_cookie, cursor,
				      (uint32_t)index + 1)) {
			child->obj.obj_ops->release(&child->obj);
			fsal_release_attrs(&attrs);
			status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
			goto out;
		}
		callback_result = callback(name, &child->obj, &attrs, dir_state,
					   next_cookie);
		fsal_release_attrs(&attrs);
		base_cookie = next_cookie;
		if (callback_result >= DIR_TERMINATE) {
			*eof = false;
			goto out;
		}
	}
	if (!*eof) {
		char next_cursor[FILEBELT_CURSOR_BYTES];

		if (!filebelt_copy_slice(&result.response.next_cursor,
					 &next_cursor[0], sizeof(next_cursor)) ||
		    !remember_readdir(directory, base_cookie, next_cursor, 0))
			status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
	}
out:
	call_result_release(&result);
	pthread_mutex_unlock(&directory->readdir_lock);
	return status;
}

static void add_requested_action(bool selected[13], uint32_t action)
{
	if (action >= 1 && action <= 12)
		selected[action] = true;
}

static size_t actions_for_access(fsal_accessflags_t access,
				 uint8_t actions[12])
{
	bool selected[13] = { false };
	fsal_accessflags_t mode = FSAL_MODE_MASK(access);
	fsal_accessflags_t ace = FSAL_ACE4_MASK(access);
	size_t count = 0;

	if ((mode & FSAL_R_OK) != 0 ||
	    (ace & (FSAL_ACE_PERM_READ_ATTR | FSAL_ACE_PERM_READ_ACL)) != 0)
		add_requested_action(selected, FILEBELT_ACTION_READ_METADATA);
	if ((ace & (FSAL_ACE_PERM_READ_DATA |
		    FSAL_ACE_PERM_READ_NAMED_ATTR)) != 0)
		add_requested_action(selected, FILEBELT_ACTION_READ_CONTENT);
	if ((ace & (FSAL_ACE_PERM_ADD_FILE |
		    FSAL_ACE_PERM_ADD_SUBDIRECTORY)) != 0)
		add_requested_action(selected, FILEBELT_ACTION_CREATE_CHILD);
	if ((mode & FSAL_W_OK) != 0 ||
	    (ace & (FSAL_ACE_PERM_WRITE_DATA | FSAL_ACE_PERM_APPEND_DATA)) != 0)
		add_requested_action(selected, FILEBELT_ACTION_WRITE_CONTENT);
	if ((ace & (FSAL_ACE_PERM_DELETE | FSAL_ACE_PERM_DELETE_CHILD)) != 0)
		add_requested_action(selected, FILEBELT_ACTION_DELETE);
	if ((ace & (FSAL_ACE_PERM_WRITE_ATTR |
		    FSAL_ACE_PERM_WRITE_NAMED_ATTR | FSAL_ACE_PERM_WRITE_OWNER)) != 0)
		add_requested_action(selected, FILEBELT_ACTION_WRITE_METADATA);
	if ((ace & FSAL_ACE_PERM_SYNCHRONIZE) != 0)
		add_requested_action(selected, FILEBELT_ACTION_MANAGE_LOCK);
	if ((ace & FSAL_ACE_PERM_LIST_DIR) != 0)
		add_requested_action(selected, FILEBELT_ACTION_LIST_CHILDREN);
	if ((mode & FSAL_X_OK) != 0 || (ace & FSAL_ACE_PERM_EXECUTE) != 0)
		add_requested_action(selected, FILEBELT_ACTION_TRAVERSE);
	if ((ace & FSAL_ACE_PERM_WRITE_ACL) != 0)
		add_requested_action(selected, FILEBELT_ACTION_MANAGE_ACL);
	for (uint32_t action = 1; action <= 12; action++)
		if (selected[action])
			actions[count++] = (uint8_t)action;
	return count;
}

static fsal_status_t filebelt_test_access(struct fsal_obj_handle *obj_hdl,
					  fsal_accessflags_t access_type,
					  fsal_accessflags_t *allowed,
					  fsal_accessflags_t *denied,
					  bool owner_skip)
{
	struct filebelt_obj_handle *object = filebelt_obj(obj_hdl);
	uint8_t actions[12];
	size_t action_count = actions_for_access(access_type, actions);
	uint8_t encoded[256];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;
	bool all_allowed = true;

	(void)owner_skip;
	if (action_count == 0) {
		if (allowed != NULL) *allowed = access_type;
		if (denied != NULL) *denied = 0;
		return fsalstat(ERR_FSAL_NO_ERROR, 0);
	}
	if (object->virtual_root) {
		for (size_t index = 0; index < action_count; index++)
			if (actions[index] != FILEBELT_ACTION_READ_METADATA &&
			    actions[index] != FILEBELT_ACTION_LIST_CHILDREN &&
			    actions[index] != FILEBELT_ACTION_TRAVERSE)
				all_allowed = false;
		status = all_allowed ? fsalstat(ERR_FSAL_NO_ERROR, 0) :
			fsalstat(ERR_FSAL_ACCESS, EACCES);
	} else {
		filebelt_pb_init(&operation, encoded, sizeof(encoded));
		(void)filebelt_pb_bytes(&operation, 1,
					object->persistent_handle,
					FILEBELT_HANDLE_BYTES);
		(void)append_actions(&operation, 2, actions, action_count);
		status = call_vfs(FILEBELT_OP_ACCESS, &operation, &result);
		if (!FSAL_IS_ERROR(status)) {
			for (size_t index = 0; index < action_count; index++)
				if (!filebelt_response_allows(&result.response,
							 actions[index]))
					all_allowed = false;
			if (!all_allowed)
				status = fsalstat(ERR_FSAL_ACCESS, EACCES);
		}
		call_result_release(&result);
	}
	if (allowed != NULL) *allowed = all_allowed ? access_type : 0;
	if (denied != NULL) *denied = all_allowed ? 0 : access_type;
	return status;
}

static fsal_status_t filebelt_get_owner_group_names(
	struct fsal_obj_handle *obj_hdl, uid_t owner, gid_t group,
	struct gsh_buffdesc *owner_name, struct gsh_buffdesc *group_name)
{
	struct filebelt_obj_handle *object = filebelt_obj(obj_hdl);
	struct filebelt_identity_projection *projection = &object->projection;

	if (object->virtual_root || owner_name == NULL || group_name == NULL ||
	    !projection->initialized || (uint64_t)owner != projection->uid ||
	    (uint64_t)group != projection->gid)
		return fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
	owner_name->addr = projection->owner_name;
	owner_name->len = projection->owner_length;
	group_name->addr = projection->group_name;
	group_name->len = projection->group_length;
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static fsal_status_t create_child(struct filebelt_obj_handle *parent,
				  uint32_t operation_tag, const char *name,
				  const char *symlink_target, uint32_t mode,
				  struct fsal_obj_handle **new_obj,
				  struct fsal_attrlist *attrs_out)
{
	uint8_t encoded[2048];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;

	if (parent->virtual_root || parent->obj.type != DIRECTORY || name == NULL ||
	    name[0] == '\0' || strlen(name) > 255 ||
	    parent->namespace_generation == 0)
		return fsalstat(ERR_FSAL_INVAL, EINVAL);
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, parent->drive_id);
	(void)filebelt_pb_string(&operation, 2, parent->resource_id);
	(void)filebelt_pb_string(&operation, 3, name);
	if (operation_tag == FILEBELT_OP_SYMLINK) {
		if (symlink_target == NULL || symlink_target[0] == '\0' ||
		    symlink_target[0] == '/' || strlen(symlink_target) > 4096)
			return fsalstat(ERR_FSAL_INVAL, EINVAL);
		(void)filebelt_pb_string(&operation, 4, symlink_target);
		(void)filebelt_pb_uint64(&operation, 5,
					  parent->namespace_generation);
		(void)filebelt_pb_bytes(&operation, 6,
					parent->persistent_handle,
					FILEBELT_HANDLE_BYTES);
		(void)filebelt_pb_uint64(&operation, 7, mode);
	} else {
		(void)filebelt_pb_uint64(&operation, 4,
					  parent->namespace_generation);
		if (operation_tag == FILEBELT_OP_CREATE) {
			static const uint8_t actions[] = {
				FILEBELT_ACTION_READ_METADATA,
				FILEBELT_ACTION_READ_CONTENT,
				FILEBELT_ACTION_WRITE_CONTENT,
			};

			(void)append_actions(&operation, 5, actions,
					     sizeof(actions));
			(void)filebelt_pb_bytes(&operation, 6,
						parent->persistent_handle,
						FILEBELT_HANDLE_BYTES);
			(void)filebelt_pb_uint64(&operation, 7, mode);
		} else {
			(void)filebelt_pb_bytes(&operation, 5,
						parent->persistent_handle,
						FILEBELT_HANDLE_BYTES);
			(void)filebelt_pb_uint64(&operation, 6, mode);
		}
	}
	status = call_vfs(operation_tag, &operation, &result);
	if (!FSAL_IS_ERROR(status))
		status = object_from_response(parent->export, parent->export_id,
					      parent->drive_id,
					      &result.response, new_obj,
					      attrs_out);
	call_result_release(&result);
	return status;
}

static fsal_status_t initial_create_mode(const struct fsal_attrlist *attrs,
					 uint32_t default_mode,
					 uint32_t *mode)
{
	if (mode == NULL)
		return fsalstat(ERR_FSAL_INVAL, EINVAL);
	*mode = default_mode;
	if (attrs == NULL)
		return fsalstat(ERR_FSAL_NO_ERROR, 0);
	/* Core selects ownership from the authenticated session projection. Never
	 * accept, translate, or silently discard client UID/GID fields. */
	if ((attrs->valid_mask & (ATTR_OWNER | ATTR_GROUP)) != 0)
		return fsalstat(ERR_FSAL_INVAL, EINVAL);
	if ((attrs->valid_mask & ~(attrmask_t)ATTR_MODE) != 0)
		return fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
	if (FSAL_TEST_MASK(attrs->valid_mask, ATTR_MODE)) {
		if ((attrs->mode & ~0777U) != 0)
			return fsalstat(ERR_FSAL_INVAL, EINVAL);
		*mode = attrs->mode;
	}
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static fsal_status_t filebelt_mkdir(
	struct fsal_obj_handle *dir_hdl, const char *name,
	struct fsal_attrlist *attrs_in, struct fsal_obj_handle **new_obj,
	struct fsal_attrlist *attrs_out,
	struct fsal_attrlist *parent_pre_attrs_out,
	struct fsal_attrlist *parent_post_attrs_out)
{
	uint32_t mode;
	fsal_status_t status = initial_create_mode(attrs_in, 0755U, &mode);

	(void)parent_pre_attrs_out;
	(void)parent_post_attrs_out;
	if (FSAL_IS_ERROR(status))
		return status;
	return create_child(filebelt_obj(dir_hdl), FILEBELT_OP_MKDIR, name,
			    NULL, mode, new_obj, attrs_out);
}

static fsal_status_t filebelt_symlink(
	struct fsal_obj_handle *dir_hdl, const char *name, const char *link_path,
	struct fsal_attrlist *attrs_in, struct fsal_obj_handle **new_obj,
	struct fsal_attrlist *attrs_out,
	struct fsal_attrlist *parent_pre_attrs_out,
	struct fsal_attrlist *parent_post_attrs_out)
{
	uint32_t mode;
	fsal_status_t status = initial_create_mode(attrs_in, 0777U, &mode);

	(void)parent_pre_attrs_out;
	(void)parent_post_attrs_out;
	if (FSAL_IS_ERROR(status))
		return status;
	return create_child(filebelt_obj(dir_hdl), FILEBELT_OP_SYMLINK, name,
			    link_path, mode, new_obj, attrs_out);
}

static fsal_status_t filebelt_readlink(struct fsal_obj_handle *obj_hdl,
				       struct gsh_buffdesc *link_content,
				       bool refresh)
{
	struct filebelt_obj_handle *object = filebelt_obj(obj_hdl);
	uint8_t encoded[512];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;

	(void)refresh;
	if (obj_hdl->type != SYMBOLIC_LINK || object->virtual_root)
		return fsalstat(ERR_FSAL_INVAL, EINVAL);
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, object->drive_id);
	(void)filebelt_pb_string(&operation, 2, object->resource_id);
	(void)filebelt_pb_bytes(&operation, 3, object->persistent_handle,
				FILEBELT_HANDLE_BYTES);
	status = call_vfs(FILEBELT_OP_READLINK, &operation, &result);
	if (!FSAL_IS_ERROR(status)) {
		if (result.response.symlink_target.data == NULL ||
		    result.response.symlink_target.length > 4096) {
			status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
		} else {
			link_content->len = result.response.symlink_target.length + 1;
			link_content->addr = gsh_malloc(link_content->len);
			memcpy(link_content->addr,
			       result.response.symlink_target.data,
			       result.response.symlink_target.length);
			((char *)link_content->addr)[link_content->len - 1] = '\0';
		}
	}
	call_result_release(&result);
	return status;
}

static fsal_status_t filebelt_rename(
	struct fsal_obj_handle *obj_hdl, struct fsal_obj_handle *olddir_hdl,
	const char *old_name, struct fsal_obj_handle *newdir_hdl,
	const char *new_name, struct fsal_attrlist *olddir_pre_attrs_out,
	struct fsal_attrlist *olddir_post_attrs_out,
	struct fsal_attrlist *newdir_pre_attrs_out,
	struct fsal_attrlist *newdir_post_attrs_out)
{
	struct filebelt_obj_handle *object = filebelt_obj(obj_hdl);
	struct filebelt_obj_handle *target = filebelt_obj(newdir_hdl);
	uint8_t encoded[1600];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;

	(void)olddir_hdl;
	(void)old_name;
	(void)olddir_pre_attrs_out;
	(void)olddir_post_attrs_out;
	(void)newdir_pre_attrs_out;
	(void)newdir_post_attrs_out;
	if (object->virtual_root || target->virtual_root || new_name == NULL ||
	    new_name[0] == '\0' || strlen(new_name) > 255 ||
	    object->export_id != target->export_id ||
	    object->namespace_generation == 0)
		return fsalstat(ERR_FSAL_XDEV, EXDEV);
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, object->drive_id);
	(void)filebelt_pb_string(&operation, 2, object->resource_id);
	(void)filebelt_pb_string(&operation, 3, target->resource_id);
	(void)filebelt_pb_string(&operation, 4, new_name);
	(void)filebelt_pb_uint64(&operation, 5,
				  object->namespace_generation);
	(void)filebelt_pb_bytes(&operation, 6, object->persistent_handle,
				FILEBELT_HANDLE_BYTES);
	(void)filebelt_pb_bytes(&operation, 7, target->persistent_handle,
				FILEBELT_HANDLE_BYTES);
	status = call_vfs(FILEBELT_OP_RENAME, &operation, &result);
	call_result_release(&result);
	return status;
}

static fsal_status_t filebelt_unlink(
	struct fsal_obj_handle *dir_hdl, struct fsal_obj_handle *obj_hdl,
	const char *name, struct fsal_attrlist *parent_pre_attrs_out,
	struct fsal_attrlist *parent_post_attrs_out)
{
	struct filebelt_obj_handle *object = filebelt_obj(obj_hdl);
	uint8_t encoded[512];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;

	(void)dir_hdl;
	(void)name;
	(void)parent_pre_attrs_out;
	(void)parent_post_attrs_out;
	if (object->virtual_root || object->namespace_generation == 0)
		return fsalstat(ERR_FSAL_ACCESS, EACCES);
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, object->drive_id);
	(void)filebelt_pb_string(&operation, 2, object->resource_id);
	(void)filebelt_pb_uint64(&operation, 3,
				  object->namespace_generation);
	(void)filebelt_pb_bytes(&operation, 5, object->persistent_handle,
				FILEBELT_HANDLE_BYTES);
	status = call_vfs(FILEBELT_OP_REMOVE, &operation, &result);
	if (!FSAL_IS_ERROR(status))
		object->unlinked = true;
	call_result_release(&result);
	return status;
}

static bool copy_uuid_slice(const struct filebelt_slice *slice,
			    char output[FILEBELT_UUID_BYTES], bool optional)
{
	if (optional && slice->length == 0) {
		output[0] = '\0';
		return true;
	}
	if (slice->data == NULL || slice->length != FILEBELT_UUID_BYTES - 1 ||
	    memchr(slice->data, '\0', slice->length) != NULL)
		return false;
	memcpy(output, slice->data, slice->length);
	output[slice->length] = '\0';
	return true;
}

static fsal_status_t open_existing(struct filebelt_obj_handle *object,
				   struct filebelt_state *state,
				   fsal_openflags_t openflags)
{
	uint8_t encoded[768];
	uint8_t actions[2];
	size_t action_count = 0;
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;

	if (object->virtual_root || object->obj.type != REGULAR_FILE)
		return fsalstat(object->obj.type == DIRECTORY ? ERR_FSAL_ISDIR :
							 ERR_FSAL_INVAL,
			object->obj.type == DIRECTORY ? EISDIR : EINVAL);
	if ((openflags & FSAL_O_READ) != 0)
		actions[action_count++] = FILEBELT_ACTION_READ_CONTENT;
	if ((openflags & FSAL_O_WRITE) != 0)
		actions[action_count++] = FILEBELT_ACTION_WRITE_CONTENT;
	if (action_count == 0)
		return fsalstat(ERR_FSAL_INVAL, EINVAL);
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, object->drive_id);
	(void)filebelt_pb_string(&operation, 2, object->resource_id);
	if (object->head_version_id[0] != '\0')
		(void)filebelt_pb_string(&operation, 3,
					object->head_version_id);
	(void)append_actions(&operation, 4, actions, action_count);
	if ((openflags & FSAL_O_DENY_READ) == 0)
		(void)filebelt_pb_bool(&operation, 5, true);
	if ((openflags & (FSAL_O_DENY_WRITE | FSAL_O_DENY_WRITE_MAND)) == 0)
		(void)filebelt_pb_bool(&operation, 6, true);
	(void)filebelt_pb_bool(&operation, 7, true);
	(void)filebelt_pb_bytes(&operation, 8, object->persistent_handle,
				FILEBELT_HANDLE_BYTES);
	status = call_vfs(FILEBELT_OP_OPEN, &operation, &result);
	/* PostgreSQL admits at most one active staged writer for a node. Surface
	 * that stable NFS share conflict instead of the generic VFS conflict. */
	if (result.response.error == 11)
		status = fsalstat(ERR_FSAL_SHARE_DENIED, 0);
	if (!FSAL_IS_ERROR(status) &&
	    (!copy_uuid_slice(&result.response.handle_id, state->handle_id,
			      false) ||
	     !copy_uuid_slice(&result.response.write_session_id,
			      state->write_session_id,
			      (openflags & FSAL_O_WRITE) == 0) ||
	     !copy_uuid_slice(&result.response.state_id, state->state_id, true) ||
	     ((openflags & FSAL_O_WRITE) != 0 &&
	      result.response.fencing_token == 0))) {
		status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
	}
	if (!FSAL_IS_ERROR(status)) {
		state->fencing_token = result.response.fencing_token;
		state->openflags = FSAL_O_NFS_FLAGS(openflags);
		memcpy(state->expected_head_version_id, object->head_version_id,
		       sizeof(state->expected_head_version_id));
		if ((openflags & FSAL_O_WRITE) != 0) {
			pthread_mutex_lock(&object->state_lock);
			if (object->commit_handle_id[0] != '\0' &&
			    (strcmp(object->commit_handle_id, state->handle_id) != 0 ||
			     strcmp(object->commit_write_session_id,
				    state->write_session_id) != 0 ||
			     object->commit_fencing_token != state->fencing_token)) {
				/* A second successful writer contradicts the authoritative
				 * database invariant. Never replace the sole commit tuple. */
				status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
			} else {
				memcpy(object->commit_handle_id, state->handle_id,
				       sizeof(object->commit_handle_id));
				memcpy(object->commit_write_session_id,
				       state->write_session_id,
				       sizeof(object->commit_write_session_id));
				memcpy(object->commit_expected_head_version_id,
				       state->expected_head_version_id,
				       sizeof(object->commit_expected_head_version_id));
				object->commit_fencing_token = state->fencing_token;
			}
			pthread_mutex_unlock(&object->state_lock);
		}
	}
	call_result_release(&result);
	return status;
}

static fsal_status_t reclaim_state(struct filebelt_state *state)
{
	struct filebelt_fsal_request_context context;
	uint8_t encoded[256];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;

	if (state->state_id[0] == '\0' ||
	    !filebelt_fsal_capture_request(&context))
		return fsalstat(ERR_FSAL_STALE, ESTALE);
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, context.client_id);
	(void)filebelt_pb_string(&operation, 2, state->state_id);
	/* The trusted bridge overwrites both recovery-authority fields from the
	 * verified callback context and admitted gateway fence. */
	status = call_vfs(FILEBELT_OP_RECLAIM, &operation, &result);
	call_result_release(&result);
	return status;
}

static fsal_status_t filebelt_open2(
	struct fsal_obj_handle *obj_hdl, struct state_t *state_hdl,
	fsal_openflags_t openflags, enum fsal_create_mode createmode,
	const char *name, struct fsal_attrlist *attrs_in,
	fsal_verifier_t verifier, struct fsal_obj_handle **new_obj,
	struct fsal_attrlist *attrs_out, bool *caller_perm_check,
	struct fsal_attrlist *parent_pre_attrs_out,
	struct fsal_attrlist *parent_post_attrs_out)
{
	struct filebelt_state *state = filebelt_fsal_state(state_hdl);
	struct fsal_obj_handle *opened = obj_hdl;
	fsal_status_t status;
	uint32_t mode;

	(void)verifier;
	(void)parent_pre_attrs_out;
	(void)parent_post_attrs_out;
	if (state == NULL)
		return fsalstat(ERR_FSAL_NOT_OPENED, EBADF);
	if (name != NULL && createmode != FSAL_NO_CREATE) {
		status = initial_create_mode(attrs_in, 0644U, &mode);
		if (FSAL_IS_ERROR(status))
			return status;
		/* NFS OPEN(CREATE) requires one atomic create-and-open replay outcome.
		 * The VFS currently has separate Create and Open operations, so do not
		 * emit either mutation or silently discard the validated mode. */
		(void)mode;
		return fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
	}
	if ((openflags & FSAL_O_RECLAIM) != 0 && state->state_id[0] != '\0') {
		status = reclaim_state(state);
		if (!FSAL_IS_ERROR(status))
			state->openflags = FSAL_O_NFS_FLAGS(openflags);
		return status;
	}
	if (name != NULL) {
		status = filebelt_lookup(obj_hdl, name, &opened, attrs_out);
		if (FSAL_IS_ERROR(status))
			return status;
		*new_obj = opened;
	}
	status = open_existing(filebelt_obj(opened), state, openflags);
	if (FSAL_IS_ERROR(status) && name != NULL) {
		opened->obj_ops->release(opened);
		*new_obj = NULL;
	}
	if (!FSAL_IS_ERROR(status) && caller_perm_check != NULL)
		*caller_perm_check = false;
	return status;
}

static fsal_openflags_t filebelt_status2(struct fsal_obj_handle *obj_hdl,
					 struct state_t *state_hdl)
{
	(void)obj_hdl;
	return filebelt_fsal_state(state_hdl)->openflags;
}

static fsal_status_t filebelt_open_unlinked(struct filebelt_state *state)
{
	uint8_t encoded[256];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;

	if (state->handle_id[0] == '\0' || state->write_session_id[0] == '\0' ||
	    state->fencing_token == 0)
		return fsalstat(ERR_FSAL_NOT_OPENED, EBADF);
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, state->handle_id);
	(void)filebelt_pb_string(&operation, 2, state->write_session_id);
	(void)filebelt_pb_uint64(&operation, 3, state->fencing_token);
	status = call_vfs(FILEBELT_OP_OPEN_UNLINKED, &operation, &result);
	call_result_release(&result);
	return status;
}

static fsal_status_t filebelt_reopen2(struct fsal_obj_handle *obj_hdl,
				      struct state_t *state_hdl,
				      fsal_openflags_t openflags)
{
	struct filebelt_obj_handle *object = filebelt_obj(obj_hdl);
	struct filebelt_state *state = filebelt_fsal_state(state_hdl);

	if (object->unlinked)
		return filebelt_open_unlinked(state);
	if ((openflags & FSAL_O_RECLAIM) != 0)
		return reclaim_state(state);
	if (state == NULL || state->handle_id[0] == '\0')
		return fsalstat(ERR_FSAL_NOT_OPENED, EBADF);
	if (state->openflags == FSAL_O_NFS_FLAGS(openflags))
		return fsalstat(ERR_FSAL_NO_ERROR, 0);
	/* Close+Open would emit two different mutations with one NFS replay
	 * coordinate and lose the old handle if reopening failed. A dedicated
	 * atomic generic reopen operation is required before changing flags. */
	return fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
}

static fsal_status_t require_io_state(struct state_t *state_hdl,
				      fsal_openflags_t required,
				      struct filebelt_state **state)
{
	*state = filebelt_fsal_state(state_hdl);
	if (*state == NULL || (*state)->handle_id[0] == '\0' ||
	    (((*state)->openflags & required) == 0))
		return fsalstat(ERR_FSAL_NOT_OPENED, EBADF);
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static bool scatter_data(struct fsal_io_arg *argument, const uint8_t *data,
			 size_t length)
{
	size_t offset = 0;

	if (argument->iov_count < 0)
		return false;
	for (int index = 0; index < argument->iov_count && offset < length;
	     index++) {
		size_t amount = MIN(argument->iov[index].iov_len, length - offset);

		memcpy(argument->iov[index].iov_base, data + offset, amount);
		offset += amount;
	}
	return offset == length;
}

static bool gather_data(const struct fsal_io_arg *argument, uint8_t *data,
			 size_t capacity, size_t *length)
{
	size_t offset = 0;

	if (argument->iov_count < 0)
		return false;
	for (int index = 0; index < argument->iov_count; index++) {
		if (argument->iov[index].iov_len > capacity - offset)
			return false;
		memcpy(data + offset, argument->iov[index].iov_base,
		       argument->iov[index].iov_len);
		offset += argument->iov[index].iov_len;
	}
	*length = offset;
	return offset != 0;
}

static void filebelt_read2(struct fsal_obj_handle *obj_hdl, bool bypass,
			   fsal_async_cb done_cb,
			   struct fsal_io_arg *read_arg, void *caller_arg)
{
	struct filebelt_state *state;
	uint8_t encoded[256];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status = require_io_state(read_arg->state, FSAL_O_READ,
						&state);

	(void)bypass;
	read_arg->io_amount = 0;
	read_arg->end_of_file = false;
	if (read_arg->io_request > FILEBELT_MAX_DATA_BYTES ||
	    (read_arg->info != NULL && read_arg->iov_count != 1))
		status = fsalstat(ERR_FSAL_FBIG, EFBIG);
	if (!FSAL_IS_ERROR(status)) {
		filebelt_pb_init(&operation, encoded, sizeof(encoded));
		(void)filebelt_pb_string(&operation, 1, state->handle_id);
		if (read_arg->offset != 0)
			(void)filebelt_pb_uint64(&operation, 2, read_arg->offset);
		(void)filebelt_pb_uint64(&operation, 3, read_arg->io_request);
		status = call_vfs(FILEBELT_OP_READ, &operation, &result);
		if (!FSAL_IS_ERROR(status)) {
			if (result.response.data.length > read_arg->io_request ||
			    !scatter_data(read_arg, result.response.data.data,
					  result.response.data.length)) {
				status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
			} else {
				read_arg->io_amount = result.response.data.length;
				read_arg->end_of_file = result.response.end_of_file;
				if (read_arg->info != NULL) {
					read_arg->info->io_content.what =
						NFS4_CONTENT_DATA;
					read_arg->info->io_content.data.d_offset =
						read_arg->offset;
					read_arg->info->io_content.data.d_data.data_len =
						(uint32_t)read_arg->io_amount;
					read_arg->info->io_content.data.d_data.data_val =
						read_arg->iov[0].iov_base;
				}
			}
		}
		call_result_release(&result);
	}
	done_cb(obj_hdl, status, read_arg, caller_arg);
}

static void filebelt_write2(struct fsal_obj_handle *obj_hdl, bool bypass,
			    fsal_async_cb done_cb,
			    struct fsal_io_arg *write_arg, void *caller_arg)
{
	struct filebelt_state *state;
	uint8_t *encoded = NULL;
	uint8_t *data = NULL;
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	size_t data_length = 0;
	fsal_status_t status = require_io_state(write_arg->state, FSAL_O_WRITE,
						&state);
	uint32_t operation_tag = FILEBELT_OP_WRITE;
	bool sparse = write_arg->info != NULL;
	bool hole = sparse &&
		write_arg->info->io_content.what == NFS4_CONTENT_HOLE;
	uint64_t sparse_length = hole ?
		write_arg->info->io_content.hole.di_length : 0;

	(void)bypass;
	write_arg->io_amount = 0;
	if (sparse && write_arg->info->io_content.what != NFS4_CONTENT_DATA &&
	    !hole)
		status = fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
	if (hole && (sparse_length == 0 ||
		     sparse_length > FILEBELT_MAX_DATA_BYTES))
		status = fsalstat(ERR_FSAL_FBIG, EFBIG);
	if (!FSAL_IS_ERROR(status)) {
		encoded = gsh_malloc(FILEBELT_OPERATION_BYTES);
		if (!hole)
			data = gsh_malloc(FILEBELT_MAX_DATA_BYTES);
		if (encoded == NULL || (!hole &&
		    (data == NULL ||
		     !gather_data(write_arg, data, FILEBELT_MAX_DATA_BYTES,
				  &data_length))))
			status = fsalstat(ERR_FSAL_FBIG, EFBIG);
	}
	if (!FSAL_IS_ERROR(status)) {
		if (!hole)
			sparse_length = data_length;
		filebelt_pb_init(&operation, encoded, FILEBELT_OPERATION_BYTES);
		(void)filebelt_pb_string(&operation, 1, state->handle_id);
		(void)filebelt_pb_string(&operation, 2, state->write_session_id);
		(void)filebelt_pb_uint64(&operation, 3, state->fencing_token);
		if (write_arg->offset != 0)
			(void)filebelt_pb_uint64(&operation, 4, write_arg->offset);
		if (sparse) {
			operation_tag = FILEBELT_OP_SPARSE_WRITE;
			(void)filebelt_pb_uint64(&operation, 5, sparse_length);
			if (!hole)
				(void)filebelt_pb_bytes(&operation, 6, data,
						data_length);
			else
				(void)filebelt_pb_bool(&operation, 7, true);
		} else {
			(void)filebelt_pb_bytes(&operation, 5, data, data_length);
		}
		status = call_vfs(operation_tag, &operation, &result);
		if (!FSAL_IS_ERROR(status)) {
			write_arg->io_amount = hole ? (size_t)sparse_length : data_length;
			write_arg->fsal_stable = false;
		}
		call_result_release(&result);
	}
	if (data != NULL) {
		memset(data, 0, FILEBELT_MAX_DATA_BYTES);
		gsh_free(data);
	}
	if (encoded != NULL) {
		memset(encoded, 0, FILEBELT_OPERATION_BYTES);
		gsh_free(encoded);
	}
	done_cb(obj_hdl, status, write_arg, caller_arg);
}

static fsal_status_t filebelt_commit2(struct fsal_obj_handle *obj_hdl,
				      off_t offset, size_t length)
{
	struct filebelt_obj_handle *object = filebelt_obj(obj_hdl);
	char handle_id[FILEBELT_UUID_BYTES];
	char write_session_id[FILEBELT_UUID_BYTES];
	char expected_head_version_id[FILEBELT_UUID_BYTES];
	uint64_t fencing_token;
	uint8_t encoded[384];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;

	(void)offset;
	(void)length;
	if (object->virtual_root)
		return fsalstat(ERR_FSAL_INVAL, EINVAL);
	pthread_mutex_lock(&object->state_lock);
	memcpy(handle_id, object->commit_handle_id, sizeof(handle_id));
	memcpy(write_session_id, object->commit_write_session_id,
	       sizeof(write_session_id));
	memcpy(expected_head_version_id,
	       object->commit_expected_head_version_id,
	       sizeof(expected_head_version_id));
	fencing_token = object->commit_fencing_token;
	pthread_mutex_unlock(&object->state_lock);
	if (handle_id[0] == '\0' || write_session_id[0] == '\0' ||
	    fencing_token == 0)
		return fsalstat(ERR_FSAL_NOT_OPENED, EBADF);
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, handle_id);
	(void)filebelt_pb_string(&operation, 2, write_session_id);
	(void)filebelt_pb_uint64(&operation, 3, fencing_token);
	if (expected_head_version_id[0] != '\0')
		(void)filebelt_pb_string(&operation, 4,
					expected_head_version_id);
	status = call_vfs(FILEBELT_OP_COMMIT, &operation, &result);
	if (!FSAL_IS_ERROR(status) && result.response.version_id.length != 0 &&
	    !copy_uuid_slice(&result.response.version_id,
			     expected_head_version_id, false))
		status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
	if (!FSAL_IS_ERROR(status)) {
		pthread_mutex_lock(&object->state_lock);
		memcpy(object->commit_expected_head_version_id,
		       expected_head_version_id,
		       sizeof(object->commit_expected_head_version_id));
		pthread_mutex_unlock(&object->state_lock);
	}
	call_result_release(&result);
	return status;
}

static fsal_status_t close_state(struct filebelt_state *state)
{
	uint8_t encoded[128];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;

	if (state == NULL || state->handle_id[0] == '\0')
		return fsalstat(ERR_FSAL_NOT_OPENED, EBADF);
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, state->handle_id);
	status = call_vfs(FILEBELT_OP_CLOSE, &operation, &result);
	if (!FSAL_IS_ERROR(status)) {
		state->openflags = FSAL_O_CLOSED;
		state->handle_id[0] = '\0';
		state->write_session_id[0] = '\0';
		state->fencing_token = 0;
	}
	call_result_release(&result);
	return status;
}

static fsal_status_t filebelt_close2(struct fsal_obj_handle *obj_hdl,
				     struct state_t *state_hdl)
{
	struct filebelt_obj_handle *object = filebelt_obj(obj_hdl);
	struct filebelt_state *state = filebelt_fsal_state(state_hdl);
	char closing_handle[FILEBELT_UUID_BYTES];
	fsal_status_t status;

	if (state == NULL)
		return fsalstat(ERR_FSAL_NOT_OPENED, EBADF);
	memcpy(closing_handle, state->handle_id, sizeof(closing_handle));
	status = close_state(state);
	if (!FSAL_IS_ERROR(status)) {
		pthread_mutex_lock(&object->state_lock);
		if (strcmp(object->commit_handle_id, closing_handle) == 0) {
			memset(object->commit_handle_id, 0,
			       sizeof(object->commit_handle_id));
			memset(object->commit_write_session_id, 0,
			       sizeof(object->commit_write_session_id));
			memset(object->commit_expected_head_version_id, 0,
			       sizeof(object->commit_expected_head_version_id));
			object->commit_fencing_token = 0;
		}
		pthread_mutex_unlock(&object->state_lock);
	}
	return status;
}

static fsal_status_t filebelt_close(struct fsal_obj_handle *obj_hdl)
{
	(void)obj_hdl;
	return fsalstat(ERR_FSAL_NOT_OPENED, EBADF);
}

static fsal_aceperm_t permissions_for_actions(
	const struct filebelt_acl_entry *entry)
{
	fsal_aceperm_t permissions = 0;

	for (size_t index = 0; index < entry->action_count; index++) {
		switch (entry->actions[index]) {
		case FILEBELT_ACTION_READ_METADATA:
			permissions |= FSAL_ACE_PERM_READ_ATTR |
				       FSAL_ACE_PERM_READ_ACL;
			break;
		case FILEBELT_ACTION_READ_CONTENT:
			permissions |= FSAL_ACE_PERM_READ_DATA |
				       FSAL_ACE_PERM_READ_NAMED_ATTR;
			break;
		case FILEBELT_ACTION_CREATE_CHILD:
			permissions |= FSAL_ACE_PERM_ADD_FILE |
				       FSAL_ACE_PERM_ADD_SUBDIRECTORY;
			break;
		case FILEBELT_ACTION_WRITE_CONTENT:
			permissions |= FSAL_ACE_PERM_WRITE_DATA |
				       FSAL_ACE_PERM_APPEND_DATA;
			break;
		case FILEBELT_ACTION_DELETE:
			permissions |= FSAL_ACE_PERM_DELETE |
				       FSAL_ACE_PERM_DELETE_CHILD;
			break;
		case FILEBELT_ACTION_RENAME:
		case FILEBELT_ACTION_MOVE:
			permissions |= FSAL_ACE_PERM_DELETE |
				       FSAL_ACE_PERM_DELETE_CHILD |
				       FSAL_ACE_PERM_ADD_FILE |
				       FSAL_ACE_PERM_ADD_SUBDIRECTORY;
			break;
		case FILEBELT_ACTION_WRITE_METADATA:
			permissions |= FSAL_ACE_PERM_WRITE_ATTR |
				       FSAL_ACE_PERM_WRITE_NAMED_ATTR |
				       FSAL_ACE_PERM_WRITE_OWNER;
			break;
		case FILEBELT_ACTION_MANAGE_LOCK:
			permissions |= FSAL_ACE_PERM_SYNCHRONIZE;
			break;
		case FILEBELT_ACTION_LIST_CHILDREN:
			permissions |= FSAL_ACE_PERM_LIST_DIR;
			break;
		case FILEBELT_ACTION_TRAVERSE:
			permissions |= FSAL_ACE_PERM_EXECUTE;
			break;
		case FILEBELT_ACTION_MANAGE_ACL:
			permissions |= FSAL_ACE_PERM_WRITE_ACL;
			break;
		default: break;
		}
	}
	return permissions;
}

static bool map_acl_principal(const struct filebelt_acl_entry *entry,
			      fsal_ace_t *ace)
{
	switch (entry->principal_kind) {
	case 1:
		ace->iflag = FSAL_ACE_IFLAG_SPECIAL_ID;
		ace->who.uid = FSAL_ACE_SPECIAL_OWNER;
		return true;
	case 2:
		ace->iflag = FSAL_ACE_IFLAG_SPECIAL_ID;
		ace->who.uid = FSAL_ACE_SPECIAL_GROUP;
		return true;
	case 3:
		ace->iflag = FSAL_ACE_IFLAG_SPECIAL_ID;
		ace->who.uid = FSAL_ACE_SPECIAL_EVERYONE;
		return true;
	case 4:
	case 5:
		/* The generic ACL wire does not yet carry Core-selected numeric
		 * projections for named principals. Host idmapper is not authority. */
		return false;
	default: return false;
	}
}

static fsal_status_t filebelt_get_acl_attributes(
	struct filebelt_obj_handle *object, struct fsal_attrlist *attrs)
{
	uint8_t encoded[256];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	struct filebelt_acl acl;
	fsal_acl_data_t acl_data = { 0 };
	fsal_acl_status_t acl_status = NFS_V4_ACL_SUCCESS;
	fsal_status_t status;
	size_t count;

	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_bytes(&operation, 1, object->persistent_handle,
				FILEBELT_HANDLE_BYTES);
	status = call_vfs(FILEBELT_OP_GET_ACL, &operation, &result);
	if (FSAL_IS_ERROR(status)) {
		call_result_release(&result);
		return status;
	}
	if (!filebelt_acl_parse(&result.response.acl, &acl)) {
		status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
		goto out;
	}
	count = filebelt_acl_entry_count(&acl);
	if (count == 0 || count > UINT32_MAX) {
		status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
		goto out;
	}
	acl_data.naces = (uint32_t)count;
	acl_data.aces = nfs4_ace_alloc((int)count);
	if (acl_data.aces == NULL) {
		status = fsalstat(ERR_FSAL_NOMEM, ENOMEM);
		goto out;
	}
	for (size_t index = 0; index < count; index++) {
		struct filebelt_acl_entry entry;
		fsal_ace_t *ace = &acl_data.aces[index];

		if (!filebelt_acl_entry(&acl, index, &entry)) {
			nfs4_ace_free(acl_data.aces);
			status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
			goto out;
		}
		if (entry.principal_kind >= 4) {
			nfs4_ace_free(acl_data.aces);
			status = fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
			goto out;
		}
		if (!map_acl_principal(&entry, ace)) {
			nfs4_ace_free(acl_data.aces);
			status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
			goto out;
		}
		ace->type = FSAL_ACE_TYPE_ALLOW;
		ace->perm = permissions_for_actions(&entry);
		if (entry.inheritance >= 2)
			ace->flag |= FSAL_ACE_FLAG_FILE_INHERIT |
				     FSAL_ACE_FLAG_DIR_INHERIT;
		if (entry.inheritance == 2)
			ace->flag |= FSAL_ACE_FLAG_INHERIT_ONLY;
		if (entry.inherited)
			ace->flag |= FSAL_ACE_FLAG_INHERITED;
	}
	attrs->acl = nfs4_acl_new_entry(&acl_data, &acl_status);
	if (attrs->acl == NULL || acl_status != NFS_V4_ACL_SUCCESS) {
		status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
		goto out;
	}
	attrs->valid_mask |= ATTR_ACL;
	object->acl_generation = acl.generation;
out:
	call_result_release(&result);
	return status;
}

static size_t actions_for_permissions(fsal_aceperm_t permissions,
				      uint8_t actions[12])
{
	bool selected[13] = { false };
	size_t count = 0;

	if ((permissions & (FSAL_ACE_PERM_READ_ATTR |
			    FSAL_ACE_PERM_READ_ACL)) != 0)
		selected[FILEBELT_ACTION_READ_METADATA] = true;
	if ((permissions & (FSAL_ACE_PERM_READ_DATA |
			    FSAL_ACE_PERM_READ_NAMED_ATTR)) != 0)
		selected[FILEBELT_ACTION_READ_CONTENT] = true;
	if ((permissions & (FSAL_ACE_PERM_ADD_FILE |
			    FSAL_ACE_PERM_ADD_SUBDIRECTORY)) != 0)
		selected[FILEBELT_ACTION_CREATE_CHILD] = true;
	if ((permissions & (FSAL_ACE_PERM_WRITE_DATA |
			    FSAL_ACE_PERM_APPEND_DATA)) != 0)
		selected[FILEBELT_ACTION_WRITE_CONTENT] = true;
	if ((permissions & (FSAL_ACE_PERM_DELETE |
			    FSAL_ACE_PERM_DELETE_CHILD)) != 0)
		selected[FILEBELT_ACTION_DELETE] = true;
	if ((permissions & (FSAL_ACE_PERM_WRITE_ATTR |
			    FSAL_ACE_PERM_WRITE_NAMED_ATTR |
			    FSAL_ACE_PERM_WRITE_OWNER)) != 0)
		selected[FILEBELT_ACTION_WRITE_METADATA] = true;
	if ((permissions & FSAL_ACE_PERM_SYNCHRONIZE) != 0)
		selected[FILEBELT_ACTION_MANAGE_LOCK] = true;
	if ((permissions & FSAL_ACE_PERM_LIST_DIR) != 0)
		selected[FILEBELT_ACTION_LIST_CHILDREN] = true;
	if ((permissions & FSAL_ACE_PERM_EXECUTE) != 0)
		selected[FILEBELT_ACTION_TRAVERSE] = true;
	if ((permissions & FSAL_ACE_PERM_WRITE_ACL) != 0)
		selected[FILEBELT_ACTION_MANAGE_ACL] = true;
	for (uint32_t action = 1; action <= 12; action++)
		if (selected[action])
			actions[count++] = (uint8_t)action;
	return count;
}

static bool encode_acl_principal(struct filebelt_pb_buffer *entry,
				 const fsal_ace_t *ace)
{
	uint32_t principal_kind;

	if (IS_FSAL_ACE_SPECIAL_ID(*ace)) {
		switch (ace->who.uid) {
		case FSAL_ACE_SPECIAL_OWNER: principal_kind = 1; break;
		case FSAL_ACE_SPECIAL_GROUP: principal_kind = 2; break;
		case FSAL_ACE_SPECIAL_EVERYONE: principal_kind = 3; break;
		default: return false;
		}
	} else {
		/* Named users/groups need an authoritative Core name/ID projection;
		 * never reverse-map a host uid/gid. */
		return false;
	}
	if (!filebelt_pb_uint64(entry, 2, principal_kind))
		return false;
	return true;
}

static fsal_status_t filebelt_set_acl(struct filebelt_obj_handle *object,
				      const fsal_acl_t *acl)
{
	uint8_t *encoded = gsh_malloc(FILEBELT_OPERATION_BYTES);
	uint8_t acl_storage[65536];
	uint8_t entry_storage[4096];
	struct filebelt_pb_buffer operation;
	struct filebelt_pb_buffer wire_acl;
	struct filebelt_call_result result;
	fsal_status_t status;

	if (encoded == NULL)
		return fsalstat(ERR_FSAL_NOMEM, ENOMEM);
	if (acl == NULL || acl->naces == 0 || object->acl_generation == 0) {
		status = fsalstat(ERR_FSAL_INVAL, EINVAL);
		goto out;
	}
	filebelt_pb_init(&wire_acl, acl_storage, sizeof(acl_storage));
	(void)filebelt_pb_uint64(&wire_acl, 1, 1);
	(void)filebelt_pb_uint64(&wire_acl, 2, object->acl_generation);
	for (uint32_t index = 0; index < acl->naces; index++) {
		const fsal_ace_t *ace = &acl->aces[index];
		uint8_t actions[12];
		size_t action_count;
		struct filebelt_pb_buffer entry;
		uint32_t inheritance = 1;

		/* The selected tagged ACL contract is ALLOW-only. */
		if (!IS_FSAL_ACE_ALLOW(*ace)) {
			status = fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
			goto out;
		}
		if (!IS_FSAL_ACE_SPECIAL_ID(*ace)) {
			status = fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
			goto out;
		}
		action_count = actions_for_permissions(ace->perm, actions);
		if (action_count == 0) {
			status = fsalstat(ERR_FSAL_INVAL, EINVAL);
			goto out;
		}
		if ((ace->flag & (FSAL_ACE_FLAG_FILE_INHERIT |
				  FSAL_ACE_FLAG_DIR_INHERIT)) != 0)
			inheritance = (ace->flag & FSAL_ACE_FLAG_INHERIT_ONLY) != 0 ?
				2 : 3;
		filebelt_pb_init(&entry, entry_storage, sizeof(entry_storage));
		if (!filebelt_pb_uint64(&entry, 1, 1) ||
		    !encode_acl_principal(&entry, ace) ||
		    !append_actions(&entry, 4, actions, action_count) ||
		    !filebelt_pb_uint64(&entry, 5, inheritance) ||
		    ((ace->flag & FSAL_ACE_FLAG_INHERITED) != 0 &&
		     !filebelt_pb_bool(&entry, 6, true)) ||
		    !filebelt_pb_bytes(&wire_acl, 3, entry.data, entry.length)) {
			status = fsalstat(ERR_FSAL_INVAL, EINVAL);
			goto out;
		}
	}
	filebelt_pb_init(&operation, encoded, FILEBELT_OPERATION_BYTES);
	(void)filebelt_pb_bytes(&operation, 1, object->persistent_handle,
				FILEBELT_HANDLE_BYTES);
	(void)filebelt_pb_bytes(&operation, 2, wire_acl.data, wire_acl.length);
	(void)filebelt_pb_uint64(&operation, 3, object->acl_generation);
	status = call_vfs(FILEBELT_OP_SET_ACL, &operation, &result);
	if (!FSAL_IS_ERROR(status) && result.response.attributes.data != NULL) {
		struct filebelt_node_attributes attributes;

		if (!filebelt_attributes_parse(&result.response.attributes,
					       &attributes))
			status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
		else
			object->acl_generation = attributes.acl_generation;
	}
	call_result_release(&result);
out:
	memset(encoded, 0, FILEBELT_OPERATION_BYTES);
	gsh_free(encoded);
	return status;
}

static fsal_status_t filebelt_setattr2(struct fsal_obj_handle *obj_hdl,
				       bool bypass,
				       struct state_t *state_hdl,
				       struct fsal_attrlist *attrib_set)
{
	struct filebelt_obj_handle *object = filebelt_obj(obj_hdl);
	const attrmask_t supported = ATTR_MTIME | ATTR_MTIME_SERVER | ATTR_ATIME |
		ATTR_ATIME_SERVER | ATTR_SIZE | ATTR_MODE | ATTR_ACL;
	uint8_t encoded[1024];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;
	time_t current = time(NULL);

	(void)bypass;
	(void)state_hdl;
	if (object->virtual_root || (attrib_set->valid_mask & ~supported) != 0)
		return fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_ACL)) {
		if ((attrib_set->valid_mask & ~(attrmask_t)ATTR_ACL) != 0)
			return fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
		return filebelt_set_acl(object, attrib_set->acl);
	}
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, object->drive_id);
	(void)filebelt_pb_string(&operation, 2, object->resource_id);
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_MTIME))
		(void)filebelt_pb_uint64(&operation, 3,
					  (uint64_t)attrib_set->mtime.tv_sec);
	else if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_MTIME_SERVER))
		(void)filebelt_pb_uint64(&operation, 3, (uint64_t)current);
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_ATIME))
		(void)filebelt_pb_uint64(&operation, 4,
					  (uint64_t)attrib_set->atime.tv_sec);
	else if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_ATIME_SERVER))
		(void)filebelt_pb_uint64(&operation, 4, (uint64_t)current);
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_SIZE))
		(void)filebelt_pb_uint64(&operation, 6, attrib_set->filesize);
	if (FSAL_TEST_MASK(attrib_set->valid_mask, ATTR_MODE))
		(void)filebelt_pb_uint64(&operation, 7, attrib_set->mode & 0777U);
	(void)filebelt_pb_bytes(&operation, 12, object->persistent_handle,
				FILEBELT_HANDLE_BYTES);
	status = call_vfs(FILEBELT_OP_SETATTR, &operation, &result);
	if (!FSAL_IS_ERROR(status) && result.response.attributes.data != NULL) {
		struct filebelt_node_attributes attributes;
		struct fsal_attrlist ignored = { 0 };

		if (!filebelt_attributes_parse(&result.response.attributes,
					       &attributes) ||
		    !fill_attributes(object, &attributes, &ignored))
			status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
	}
	call_result_release(&result);
	return status;
}

static bool filebelt_xattr_name(const xattrkey4 *wire_name,
				char name[256])
{
	static const char prefix[] = "user.";
	size_t length;

	if (wire_name == NULL || wire_name->utf8string_val == NULL ||
	    wire_name->utf8string_len == 0)
		return false;
	length = wire_name->utf8string_len;
	if (length > sizeof(name[0]) * 250U ||
	    sizeof(prefix) - 1U + length >= 256U ||
	    memchr(wire_name->utf8string_val, '\0', length) != NULL)
		return false;
	memcpy(name, prefix, sizeof(prefix) - 1U);
	memcpy(name + sizeof(prefix) - 1U, wire_name->utf8string_val, length);
	name[sizeof(prefix) - 1U + length] = '\0';
	return true;
}

static fsal_status_t filebelt_getxattrs(struct fsal_obj_handle *obj_hdl,
					xattrkey4 *xa_name,
					xattrvalue4 *xa_value)
{
	struct filebelt_obj_handle *object = filebelt_obj(obj_hdl);
	char name[256];
	uint8_t encoded[1024];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;

	if (object->virtual_root || xa_value == NULL ||
	    !filebelt_xattr_name(xa_name, name))
		return fsalstat(ERR_FSAL_INVAL, EINVAL);
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, object->drive_id);
	(void)filebelt_pb_string(&operation, 2, object->resource_id);
	(void)filebelt_pb_string(&operation, 3, name);
	(void)filebelt_pb_bytes(&operation, 4, object->persistent_handle,
				FILEBELT_HANDLE_BYTES);
	status = call_vfs(FILEBELT_OP_GET_XATTR, &operation, &result);
	if (status.major == ERR_FSAL_NOENT)
		status = fsalstat(ERR_FSAL_NOXATTR, ENODATA);
	if (!FSAL_IS_ERROR(status)) {
		if (result.response.xattr_value.length > 65536U) {
			status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
		} else {
			xa_value->utf8string_len =
				(uint32_t)result.response.xattr_value.length;
			xa_value->utf8string_val = result.response.xattr_value.length == 0 ?
				NULL : gsh_memdup(result.response.xattr_value.data,
						  result.response.xattr_value.length);
		}
	}
	call_result_release(&result);
	return status;
}

static fsal_status_t filebelt_setxattrs(struct fsal_obj_handle *obj_hdl,
					setxattr_option4 option,
					xattrkey4 *xa_name,
					xattrvalue4 *xa_value)
{
	struct filebelt_obj_handle *object = filebelt_obj(obj_hdl);
	char name[256];
	uint8_t *encoded;
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;

	if (object->virtual_root || xa_value == NULL ||
	    xa_value->utf8string_len > 65536U ||
	    (xa_value->utf8string_len != 0 &&
	     xa_value->utf8string_val == NULL) ||
	    !filebelt_xattr_name(xa_name, name) ||
	    (option != SETXATTR4_EITHER && option != SETXATTR4_CREATE &&
	     option != SETXATTR4_REPLACE))
		return fsalstat(ERR_FSAL_INVAL, EINVAL);
	encoded = gsh_malloc(FILEBELT_OPERATION_BYTES);
	if (encoded == NULL)
		return fsalstat(ERR_FSAL_NOMEM, ENOMEM);
	filebelt_pb_init(&operation, encoded, FILEBELT_OPERATION_BYTES);
	(void)filebelt_pb_string(&operation, 1, object->drive_id);
	(void)filebelt_pb_string(&operation, 2, object->resource_id);
	(void)filebelt_pb_string(&operation, 3, name);
	if (xa_value->utf8string_len != 0)
		(void)filebelt_pb_bytes(&operation, 4,
					xa_value->utf8string_val,
					xa_value->utf8string_len);
	if (option == SETXATTR4_CREATE)
		(void)filebelt_pb_bool(&operation, 5, true);
	else if (option == SETXATTR4_REPLACE)
		(void)filebelt_pb_bool(&operation, 6, true);
	(void)filebelt_pb_bytes(&operation, 7, object->persistent_handle,
				FILEBELT_HANDLE_BYTES);
	status = call_vfs(FILEBELT_OP_SET_XATTR, &operation, &result);
	if (status.major == ERR_FSAL_NOENT)
		status = fsalstat(ERR_FSAL_NOXATTR, ENODATA);
	call_result_release(&result);
	memset(encoded, 0, FILEBELT_OPERATION_BYTES);
	gsh_free(encoded);
	return status;
}

static fsal_status_t filebelt_removexattrs(struct fsal_obj_handle *obj_hdl,
					   xattrkey4 *xa_name)
{
	struct filebelt_obj_handle *object = filebelt_obj(obj_hdl);
	char name[256];
	uint8_t encoded[1024];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;

	if (object->virtual_root || !filebelt_xattr_name(xa_name, name))
		return fsalstat(ERR_FSAL_INVAL, EINVAL);
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, object->drive_id);
	(void)filebelt_pb_string(&operation, 2, object->resource_id);
	(void)filebelt_pb_string(&operation, 3, name);
	(void)filebelt_pb_bytes(&operation, 4, object->persistent_handle,
				FILEBELT_HANDLE_BYTES);
	status = call_vfs(FILEBELT_OP_REMOVE_XATTR, &operation, &result);
	if (status.major == ERR_FSAL_NOENT)
		status = fsalstat(ERR_FSAL_NOXATTR, ENODATA);
	call_result_release(&result);
	return status;
}

static fsal_status_t filebelt_listxattrs(struct fsal_obj_handle *obj_hdl,
					 count4 maximum_bytes,
					 nfs_cookie4 *cookie, bool_t *eof,
					 xattrlist4 *names)
{
	struct filebelt_obj_handle *object = filebelt_obj(obj_hdl);
	uint8_t encoded[512];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	char *flat = NULL;
	size_t count;
	size_t flat_length = 0;
	fsal_status_t status;

	if (object->virtual_root || cookie == NULL || eof == NULL || names == NULL)
		return fsalstat(ERR_FSAL_INVAL, EINVAL);
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, object->drive_id);
	(void)filebelt_pb_string(&operation, 2, object->resource_id);
	(void)filebelt_pb_bytes(&operation, 3, object->persistent_handle,
				FILEBELT_HANDLE_BYTES);
	status = call_vfs(FILEBELT_OP_LIST_XATTR, &operation, &result);
	if (FSAL_IS_ERROR(status)) {
		call_result_release(&result);
		return status;
	}
	count = filebelt_response_xattr_count(&result.response);
	for (size_t index = 0; index < count; index++) {
		struct filebelt_slice name;

		if (!filebelt_response_xattr_name(&result.response, index, &name) ||
		    name.length < 6U || name.length > 255U ||
		    memcmp(name.data, "user.", 5U) != 0 ||
		    memchr(name.data, '\0', name.length) != NULL ||
		    flat_length > SIZE_MAX - name.length - 1U) {
			status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
			goto out;
		}
		flat_length += name.length + 1U;
	}
	flat = gsh_malloc(flat_length == 0 ? 1U : flat_length);
	flat_length = 0;
	for (size_t index = 0; index < count; index++) {
		struct filebelt_slice name;

		(void)filebelt_response_xattr_name(&result.response, index, &name);
		memcpy(flat + flat_length, name.data, name.length);
		flat_length += name.length;
		flat[flat_length++] = '\0';
	}
	status = fsal_listxattr_helper(flat, flat_length, maximum_bytes, cookie,
				      eof, names);
out:
	gsh_free(flat);
	call_result_release(&result);
	return status;
}

static bool filebelt_lock_owner_key(void *opaque, char output[256])
{
	struct filebelt_fsal_request_context context;
	state_owner_t *owner = opaque;
	static const char hexadecimal[] = "0123456789abcdef";
	size_t prefix;

	if (owner == NULL || owner->so_owner_len <= 0 ||
	    owner->so_owner_len > 100 || owner->so_owner_val == NULL ||
	    !filebelt_fsal_capture_request(&context))
		return false;
	prefix = strlen(context.client_id);
	if (prefix + 1U + (size_t)owner->so_owner_len * 2U >= 256U)
		return false;
	memcpy(output, context.client_id, prefix);
	output[prefix++] = ':';
	for (int index = 0; index < owner->so_owner_len; index++) {
		uint8_t byte = (uint8_t)owner->so_owner_val[index];

		output[prefix++] = hexadecimal[byte >> 4];
		output[prefix++] = hexadecimal[byte & 0x0fU];
	}
	output[prefix] = '\0';
	return true;
}

static fsal_status_t filebelt_lock_op2(
	struct fsal_obj_handle *obj_hdl, struct state_t *state_hdl, void *owner,
	fsal_lock_op_t lock_op, fsal_lock_param_t *request_lock,
	fsal_lock_param_t *conflicting_lock)
{
	struct filebelt_state *state = filebelt_fsal_state(state_hdl);
	char owner_key[256];
	uint8_t encoded[768];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;
	size_t slot = SIZE_MAX;
	bool to_eof;

	(void)obj_hdl;
	if (state == NULL || state->handle_id[0] == '\0' ||
	    request_lock == NULL || request_lock->lock_sle_type != FSAL_POSIX_LOCK ||
	    (request_lock->lock_length != 0 &&
	     request_lock->lock_start > UINT64_MAX - request_lock->lock_length))
		return fsalstat(ERR_FSAL_INVAL, EINVAL);
	to_eof = request_lock->lock_length == 0;
	if (conflicting_lock != NULL)
		memset(conflicting_lock, 0, sizeof(*conflicting_lock));
	if (lock_op == FSAL_OP_LOCKT) {
		struct filebelt_lock_conflict conflict;

		if ((request_lock->lock_type != FSAL_LOCK_R &&
		     request_lock->lock_type != FSAL_LOCK_W) ||
		    conflicting_lock == NULL ||
		    !filebelt_lock_owner_key(owner, owner_key))
			return fsalstat(ERR_FSAL_INVAL, EINVAL);
		filebelt_pb_init(&operation, encoded, sizeof(encoded));
		(void)filebelt_pb_string(&operation, 1, state->handle_id);
		(void)filebelt_pb_string(&operation, 2, owner_key);
		if (request_lock->lock_start != 0)
			(void)filebelt_pb_uint64(&operation, 3,
						  request_lock->lock_start);
		if (!to_eof)
			(void)filebelt_pb_uint64(&operation, 4,
						  request_lock->lock_length);
		if (request_lock->lock_type == FSAL_LOCK_W)
			(void)filebelt_pb_bool(&operation, 5, true);
		if (to_eof)
			(void)filebelt_pb_bool(&operation, 6, true);
		status = call_vfs(FILEBELT_OP_TEST_LOCK, &operation, &result);
		if (!FSAL_IS_ERROR(status)) {
			conflicting_lock->lock_sle_type = FSAL_POSIX_LOCK;
			if (result.response.lock_conflict.data == NULL) {
				conflicting_lock->lock_type = FSAL_NO_LOCK;
			} else if (!filebelt_lock_conflict_parse(
					   &result.response.lock_conflict, &conflict)) {
				status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
			} else {
				conflicting_lock->lock_start = conflict.offset;
				conflicting_lock->lock_length = conflict.to_eof ?
					0 : conflict.length;
				conflicting_lock->lock_type = conflict.exclusive ?
					FSAL_LOCK_W : FSAL_LOCK_R;
			}
		}
		call_result_release(&result);
		return status;
	}
	if (lock_op == FSAL_OP_LOCK) {
		if ((request_lock->lock_type != FSAL_LOCK_R &&
		     request_lock->lock_type != FSAL_LOCK_W) ||
		    !filebelt_lock_owner_key(owner, owner_key))
			return fsalstat(ERR_FSAL_INVAL, EINVAL);
		pthread_mutex_lock(&state->lock_lock);
		if (state->lock_count >= FILEBELT_LOCK_SLOTS) {
			pthread_mutex_unlock(&state->lock_lock);
			return fsalstat(ERR_FSAL_INVAL, EINVAL);
		}
		filebelt_pb_init(&operation, encoded, sizeof(encoded));
		(void)filebelt_pb_string(&operation, 1, state->handle_id);
		(void)filebelt_pb_string(&operation, 2, owner_key);
		if (request_lock->lock_start != 0)
			(void)filebelt_pb_uint64(&operation, 3,
						  request_lock->lock_start);
		if (!to_eof)
			(void)filebelt_pb_uint64(&operation, 4,
						  request_lock->lock_length);
		if (request_lock->lock_type == FSAL_LOCK_W)
			(void)filebelt_pb_bool(&operation, 5, true);
		if (to_eof)
			(void)filebelt_pb_bool(&operation, 6, true);
		status = call_vfs(FILEBELT_OP_LOCK, &operation, &result);
		if (!FSAL_IS_ERROR(status)) {
			struct filebelt_lock_slot *lock =
				&state->locks[state->lock_count];

			if (!copy_uuid_slice(&result.response.lock_id, lock->lock_id,
					     false)) {
				status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
			} else {
				lock->offset = request_lock->lock_start;
				lock->length = request_lock->lock_length;
				lock->to_eof = to_eof;
				memcpy(lock->owner_key, owner_key,
				       strlen(owner_key) + 1U);
				state->lock_count++;
			}
		}
		call_result_release(&result);
		pthread_mutex_unlock(&state->lock_lock);
		return status;
	}
	if (lock_op != FSAL_OP_UNLOCK)
		return fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
	if (!filebelt_lock_owner_key(owner, owner_key))
		return fsalstat(ERR_FSAL_INVAL, EINVAL);
	pthread_mutex_lock(&state->lock_lock);
	for (size_t index = 0; index < state->lock_count; index++)
		if (state->locks[index].offset == request_lock->lock_start &&
		    state->locks[index].length == request_lock->lock_length &&
		    state->locks[index].to_eof == to_eof &&
		    strcmp(state->locks[index].owner_key, owner_key) == 0) {
			slot = index;
			break;
		}
	if (slot == SIZE_MAX) {
		pthread_mutex_unlock(&state->lock_lock);
		return fsalstat(ERR_FSAL_STALE, ESTALE);
	}
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, state->handle_id);
	(void)filebelt_pb_string(&operation, 2, state->locks[slot].lock_id);
	status = call_vfs(FILEBELT_OP_UNLOCK, &operation, &result);
	if (!FSAL_IS_ERROR(status)) {
		state->lock_count--;
		if (slot != state->lock_count)
			state->locks[slot] = state->locks[state->lock_count];
		memset(&state->locks[state->lock_count], 0,
		       sizeof(state->locks[state->lock_count]));
	}
	call_result_release(&result);
	pthread_mutex_unlock(&state->lock_lock);
	return status;
}

static fsal_status_t filebelt_seek2(struct fsal_obj_handle *obj_hdl,
				    struct state_t *state_hdl,
				    struct io_info *info)
{
	struct filebelt_state *state;
	uint8_t encoded[256];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status = require_io_state(state_hdl, FSAL_O_ANY, &state);
	uint32_t kind;

	(void)obj_hdl;
	if (FSAL_IS_ERROR(status))
		return status;
	if (info == NULL)
		return fsalstat(ERR_FSAL_INVAL, EINVAL);
	if (info->io_content.what == NFS4_CONTENT_DATA)
		kind = 1;
	else if (info->io_content.what == NFS4_CONTENT_HOLE)
		kind = 2;
	else
		return fsalstat(ERR_FSAL_UNION_NOTSUPP, ENOTSUP);
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, state->handle_id);
	(void)filebelt_pb_uint64(&operation, 2, kind);
	if (info->io_content.hole.di_offset != 0)
		(void)filebelt_pb_uint64(&operation, 3,
					  info->io_content.hole.di_offset);
	status = call_vfs(FILEBELT_OP_SPARSE_CONTROL, &operation, &result);
	if (!FSAL_IS_ERROR(status)) {
		info->io_content.hole.di_offset = result.response.sparse_offset;
		info->io_eof = result.response.end_of_file;
	}
	call_result_release(&result);
	return status;
}

static fsal_status_t filebelt_fallocate(struct fsal_obj_handle *obj_hdl,
					struct state_t *state_hdl,
					uint64_t offset, uint64_t length,
					bool allocate)
{
	struct filebelt_state *state;
	uint8_t encoded[256];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status = require_io_state(state_hdl, FSAL_O_WRITE, &state);

	(void)obj_hdl;
	if (FSAL_IS_ERROR(status))
		return status;
	if (length == 0 || offset > UINT64_MAX - length)
		return fsalstat(ERR_FSAL_FBIG, EFBIG);
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_string(&operation, 1, state->handle_id);
	(void)filebelt_pb_uint64(&operation, 2, allocate ? 3U : 4U);
	if (offset != 0)
		(void)filebelt_pb_uint64(&operation, 3, offset);
	(void)filebelt_pb_uint64(&operation, 4, length);
	status = call_vfs(FILEBELT_OP_SPARSE_CONTROL, &operation, &result);
	call_result_release(&result);
	return status;
}

static void filebelt_free_state(struct state_t *state_hdl)
{
	struct filebelt_state *state = filebelt_fsal_state(state_hdl);

	pthread_mutex_destroy(&state->lock_lock);
	memset(state, 0, sizeof(*state));
	gsh_free(state);
}

struct state_t *filebelt_alloc_state(struct fsal_export *exp_hdl,
				      enum state_type state_type,
				      struct state_t *related_state)
{
	struct filebelt_state *state;

	(void)exp_hdl;
	state = gsh_calloc(1, sizeof(*state));
	if (pthread_mutex_init(&state->lock_lock, NULL) != 0) {
		gsh_free(state);
		return NULL;
	}
	return init_state(&state->state, filebelt_free_state, state_type,
			  related_state);
}

struct fsal_obj_handle *filebelt_allocate_root(
	struct filebelt_fsal_export *export)
{
	struct filebelt_obj_handle *root = allocate_virtual_root(export);

	return root == NULL ? NULL : &root->obj;
}

fsal_status_t filebelt_resolve_handle(
	struct filebelt_fsal_export *export, uint64_t export_id,
	const uint8_t persistent_handle[FILEBELT_HANDLE_BYTES],
	struct fsal_obj_handle **handle, struct fsal_attrlist *attrs_out)
{
	struct filebelt_manifest_entry manifest;
	uint8_t encoded[256];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	fsal_status_t status;

	if (!filebelt_manifest_by_export_id(export, export_id, &manifest))
		return fsalstat(ERR_FSAL_STALE, ESTALE);
	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_bytes(&operation, 1, persistent_handle,
				FILEBELT_HANDLE_BYTES);
	status = call_vfs(FILEBELT_OP_RESOLVE_HANDLE, &operation, &result);
	if (!FSAL_IS_ERROR(status) &&
	    (result.response.export_id != export_id ||
	     result.response.persistent_handle.length != FILEBELT_HANDLE_BYTES ||
	     memcmp(result.response.persistent_handle.data, persistent_handle,
		    FILEBELT_HANDLE_BYTES) != 0))
		status = fsalstat(ERR_FSAL_STALE, ESTALE);
	if (!FSAL_IS_ERROR(status))
		status = object_from_response(export, export_id, manifest.drive_id,
					      &result.response, handle, attrs_out);
	call_result_release(&result);
	return status;
}

static uint64_t saturating_add(uint64_t left, uint64_t right)
{
	return left > UINT64_MAX - right ? UINT64_MAX : left + right;
}

static fsal_status_t filesystem_info_one(uint64_t export_id,
					 fsal_dynamicfsinfo_t *aggregate)
{
	uint8_t encoded[32];
	struct filebelt_pb_buffer operation;
	struct filebelt_call_result result;
	struct filebelt_filesystem_info info;
	fsal_status_t status;

	filebelt_pb_init(&operation, encoded, sizeof(encoded));
	(void)filebelt_pb_uint64(&operation, 1, export_id);
	status = call_vfs(FILEBELT_OP_FILESYSTEM_INFO, &operation, &result);
	if (!FSAL_IS_ERROR(status) &&
	    !filebelt_filesystem_info_parse(&result.response.filesystem_info,
					    &info))
		status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
	if (!FSAL_IS_ERROR(status)) {
		aggregate->total_bytes = saturating_add(aggregate->total_bytes,
						       info.total_bytes);
		aggregate->free_bytes = saturating_add(aggregate->free_bytes,
						      info.free_bytes);
		aggregate->avail_bytes = saturating_add(aggregate->avail_bytes,
						       info.available_bytes);
		aggregate->total_files = saturating_add(aggregate->total_files,
						       info.total_files);
		aggregate->free_files = saturating_add(aggregate->free_files,
						      info.free_files);
		aggregate->avail_files = saturating_add(aggregate->avail_files,
						       info.free_files);
	}
	call_result_release(&result);
	return status;
}

fsal_status_t filebelt_dynamic_info(struct filebelt_fsal_export *export,
				    struct fsal_obj_handle *obj_hdl,
				    fsal_dynamicfsinfo_t *info)
{
	struct filebelt_obj_handle *object = filebelt_obj(obj_hdl);
	struct filebelt_manifest_entry *entries = NULL;
	size_t count = 0;
	fsal_status_t status = fsalstat(ERR_FSAL_NO_ERROR, 0);
	bool any = false;

	memset(info, 0, sizeof(*info));
	info->maxread = FILEBELT_MAX_DATA_BYTES;
	info->maxwrite = FILEBELT_MAX_DATA_BYTES;
	info->time_delta.tv_nsec = FSAL_DEFAULT_TIME_DELTA_NSEC;
	if (!object->virtual_root)
		return filesystem_info_one(object->export_id, info);
	entries = gsh_calloc(FILEBELT_MAX_EXPORTS, sizeof(*entries));
	count = filebelt_manifest_snapshot(export, entries,
					   FILEBELT_MAX_EXPORTS);
	if (count > FILEBELT_MAX_EXPORTS) {
		status = fsalstat(ERR_FSAL_SERVERFAULT, EPROTO);
		goto out;
	}
	for (size_t index = 0; index < count; index++) {
		fsal_status_t current = filesystem_info_one(entries[index].export_id,
							   info);

		if (!FSAL_IS_ERROR(current))
			any = true;
		else if (current.major != ERR_FSAL_ACCESS &&
			 current.major != ERR_FSAL_NOENT) {
			status = current;
			goto out;
		}
	}
	if (count != 0 && !any)
		status = fsalstat(ERR_FSAL_ACCESS, EACCES);
out:
	gsh_free(entries);
	return status;
}

void filebelt_handle_ops_init(struct fsal_obj_ops *ops)
{
	fsal_default_obj_ops_init(ops);
	ops->release = filebelt_release;
	ops->lookup = filebelt_lookup;
	ops->readdir = filebelt_readdir;
	ops->mkdir = filebelt_mkdir;
	ops->symlink = filebelt_symlink;
	ops->readlink = filebelt_readlink;
	ops->test_access = filebelt_test_access;
	ops->get_owner_group_names = filebelt_get_owner_group_names;
	ops->getattrs = filebelt_getattrs;
	ops->setattr2 = filebelt_setattr2;
	ops->rename = filebelt_rename;
	ops->unlink = filebelt_unlink;
	ops->close = filebelt_close;
	ops->fallocate = filebelt_fallocate;
	ops->getxattrs = filebelt_getxattrs;
	ops->setxattrs = filebelt_setxattrs;
	ops->removexattrs = filebelt_removexattrs;
	ops->listxattrs = filebelt_listxattrs;
	ops->open2 = filebelt_open2;
	ops->status2 = filebelt_status2;
	ops->reopen2 = filebelt_reopen2;
	ops->read2 = filebelt_read2;
	ops->write2 = filebelt_write2;
	ops->seek2 = filebelt_seek2;
	ops->commit2 = filebelt_commit2;
	ops->lock_op2 = filebelt_lock_op2;
	ops->close2 = filebelt_close2;
	ops->handle_to_wire = filebelt_handle_to_wire;
	ops->handle_to_key = filebelt_handle_to_key;
	ops->handle_cmp = filebelt_handle_cmp;
}
