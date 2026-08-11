/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * One static /filebelt Ganesha export. Reconciled drive exports are internal
 * children selected from the atomically installed manifest; this module never
 * mutates Ganesha's export manager while requests are live.
 */

#include "filebelt_internal.h"
#include "fsal_convert.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef FILEBELT_CALLBACKS_QUALIFIED

static struct filebelt_fsal_export *filebelt_export(
	struct fsal_export *export_hdl)
{
	return container_of(export_hdl, struct filebelt_fsal_export, export);
}

static uint64_t decode_be64(const uint8_t bytes[8])
{
	uint64_t value = 0;

	for (size_t index = 0; index < 8; index++)
		value = (value << 8) | bytes[index];
	return value;
}

static bool zero_bytes(const uint8_t *bytes, size_t length)
{
	for (size_t index = 0; index < length; index++)
		if (bytes[index] != 0)
			return false;
	return true;
}

static fsal_status_t validate_wire_handle(
	struct filebelt_fsal_export *export, struct gsh_buffdesc *descriptor)
{
	const uint8_t *wire = descriptor->addr;
	struct filebelt_manifest_entry ignored;
	uint64_t export_id;

	if (wire == NULL || descriptor->len != FILEBELT_WIRE_HANDLE_BYTES)
		return fsalstat(ERR_FSAL_BADHANDLE, EINVAL);
	if (wire[0] == 1) {
		if (!zero_bytes(wire + 1, FILEBELT_WIRE_HANDLE_BYTES - 1U))
			return fsalstat(ERR_FSAL_BADHANDLE, EINVAL);
		return fsalstat(ERR_FSAL_NO_ERROR, 0);
	}
	if (wire[0] != 2)
		return fsalstat(ERR_FSAL_BADHANDLE, EINVAL);
	export_id = decode_be64(wire + 1);
	if (export_id == 0 ||
	    !filebelt_manifest_by_export_id(export, export_id, &ignored))
		return fsalstat(ERR_FSAL_STALE, ESTALE);
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static void filebelt_release_export(struct fsal_export *export_hdl)
{
	struct filebelt_fsal_export *export = filebelt_export(export_hdl);
	struct filebelt_manifest_entry *manifest;

	filebelt_control_stop(export);
	if (export->root != NULL) {
		export->root->obj_ops->release(export->root);
		export->root = NULL;
	}
	pthread_rwlock_wrlock(&export->manifest_lock);
	manifest = export->manifest;
	export->manifest = NULL;
	export->manifest_count = 0;
	pthread_rwlock_unlock(&export->manifest_lock);
	free(manifest);
	fsal_detach_export(export_hdl->fsal, &export_hdl->exports);
	free_export_ops(export_hdl);
	pthread_rwlock_destroy(&export->manifest_lock);
	memset(export, 0, sizeof(*export));
	gsh_free(export);
}

static fsal_status_t filebelt_lookup_path(
	struct fsal_export *export_hdl, const char *path,
	struct fsal_obj_handle **handle, struct fsal_attrlist *attrs_out)
{
	struct filebelt_fsal_export *export = filebelt_export(export_hdl);

	if (path == NULL || strcmp(path, "/filebelt") != 0 ||
	    export->root == NULL)
		return fsalstat(ERR_FSAL_NOENT, ENOENT);
	*handle = export->root;
	if (attrs_out != NULL)
		return export->root->obj_ops->getattrs(export->root, attrs_out);
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

static fsal_status_t filebelt_wire_to_host(
	struct fsal_export *export_hdl, fsal_digesttype_t input_type,
	struct gsh_buffdesc *descriptor, int flags)
{
	(void)flags;
	if (input_type != FSAL_DIGEST_NFSV4)
		return fsalstat(ERR_FSAL_BADHANDLE, EINVAL);
	return validate_wire_handle(filebelt_export(export_hdl), descriptor);
}

static fsal_status_t filebelt_host_to_key(
	struct fsal_export *export_hdl, struct gsh_buffdesc *descriptor)
{
	return validate_wire_handle(filebelt_export(export_hdl), descriptor);
}

static fsal_status_t filebelt_create_handle(
	struct fsal_export *export_hdl, struct gsh_buffdesc *descriptor,
	struct fsal_obj_handle **handle, struct fsal_attrlist *attrs_out)
{
	struct filebelt_fsal_export *export = filebelt_export(export_hdl);
	const uint8_t *wire = descriptor->addr;
	fsal_status_t status = validate_wire_handle(export, descriptor);

	*handle = NULL;
	if (FSAL_IS_ERROR(status))
		return status;
	if (wire[0] == 1) {
		*handle = export->root;
		if (attrs_out != NULL)
			return export->root->obj_ops->getattrs(export->root,
							 attrs_out);
		return fsalstat(ERR_FSAL_NO_ERROR, 0);
	}
	return filebelt_resolve_handle(export, decode_be64(wire + 1), wire + 9,
				       handle, attrs_out);
}

static fsal_status_t filebelt_get_dynamic_info(
	struct fsal_export *export_hdl, struct fsal_obj_handle *obj_hdl,
	fsal_dynamicfsinfo_t *info)
{
	if (obj_hdl == NULL || info == NULL)
		return fsalstat(ERR_FSAL_INVAL, EINVAL);
	return filebelt_dynamic_info(filebelt_export(export_hdl), obj_hdl, info);
}

static void filebelt_export_ops_init(struct export_ops *ops)
{
	ops->release = filebelt_release_export;
	ops->lookup_path = filebelt_lookup_path;
	ops->wire_to_host = filebelt_wire_to_host;
	ops->host_to_key = filebelt_host_to_key;
	ops->create_handle = filebelt_create_handle;
	ops->get_fs_dynamic_info = filebelt_get_dynamic_info;
	ops->alloc_state = filebelt_alloc_state;
}

#endif /* FILEBELT_CALLBACKS_QUALIFIED */

fsal_status_t filebelt_create_export(
	struct fsal_module *fsal_hdl, void *parse_node,
	struct config_error_type *err_type,
	const struct fsal_up_vector *up_ops)
{
#ifndef FILEBELT_CALLBACKS_QUALIFIED
	(void)fsal_hdl;
	(void)parse_node;
	(void)err_type;
	(void)up_ops;
	LogCrit(COMPONENT_FSAL,
		"FILEBELT callback ABI is not qualified; refusing export");
	return fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
#else
	struct filebelt_fsal_export *export;
	int error;

	(void)parse_node;
	(void)err_type;
	export = gsh_calloc(1, sizeof(*export));
	export->control_listener = -1;
	error = pthread_rwlock_init(&export->manifest_lock, NULL);
	if (error != 0) {
		gsh_free(export);
		return posix2fsal_status(error);
	}
	fsal_export_init(&export->export);
	filebelt_export_ops_init(&export->export.exp_ops);
	error = fsal_attach_export(fsal_hdl, &export->export.exports);
	if (error != 0)
		goto free_export;
	export->export.fsal = fsal_hdl;
	export->export.up_ops = up_ops;
	op_ctx->fsal_export = &export->export;
	export->root = filebelt_allocate_root(export);
	if (export->root == NULL) {
		error = ENOMEM;
		goto detach_export;
	}
	if (filebelt_control_start(export) != 0) {
		error = EIO;
		goto release_root;
	}
	LogInfo(COMPONENT_FSAL,
		"FILEBELT /filebelt export created with fail-closed control plane");
	return fsalstat(ERR_FSAL_NO_ERROR, 0);

release_root:
	export->root->obj_ops->release(export->root);
	export->root = NULL;
detach_export:
	fsal_detach_export(fsal_hdl, &export->export.exports);
free_export:
	free_export_ops(&export->export);
	pthread_rwlock_destroy(&export->manifest_lock);
	gsh_free(export);
	return posix2fsal_status(error);
#endif
}
