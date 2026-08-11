/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * Exact NFS-Ganesha 6.5 / FSAL API 13 request boundary.
 *
 * The portable frame helper is compiled by local contract tests. Defining
 * FILEBELT_GANESHA_ABI compiles the loader-facing module and the extraction of
 * the already-verified RPCSEC_GSS/NFSv4.1 context from Ganesha's request.
 * No ticket, keytab, context handle, PAC, AUTH_SYS value, or mapped host
 * credential crosses this boundary.
 */

#include "filebelt_fsal.h"

#include <stdint.h>
#include <string.h>

enum {
	FILEBELT_BRIDGE_PREFIX_BYTES = 4,
	FILEBELT_BRIDGE_MAX_FRAME_BYTES = 1114112
};

int filebelt_fsal_frame_length(
	const uint8_t prefix[FILEBELT_BRIDGE_PREFIX_BYTES], uint32_t *length)
{
	uint32_t value;

	if (prefix == NULL || length == NULL)
		return -1;
	value = ((uint32_t)prefix[0] << 24) |
		((uint32_t)prefix[1] << 16) |
		((uint32_t)prefix[2] << 8) | (uint32_t)prefix[3];
	if (value > FILEBELT_BRIDGE_MAX_FRAME_BYTES)
		return -1;
	*length = value;
	return 0;
}

#ifdef FILEBELT_GANESHA_ABI

#include "config.h"
#include "fsal.h"
#include "FSAL/fsal_init.h"
#include "nfs_creds.h"
#include "nfs_proto_data.h"
#include "sal_data.h"

#include <inttypes.h>
#include <stdio.h>

#if FSAL_MAJOR_VERSION != 13 || FSAL_MINOR_VERSION != 0
#error "FileBelt FSAL requires the NFS-Ganesha V6.5 FSAL 13.0 ABI"
#endif

static const char filebelt_fsal_name[] = "FILEBELT";

struct filebelt_fsal_module {
	struct fsal_module module;
};

static struct filebelt_fsal_module FILEBELT = {
	.module = {
		.fs_info = {
			.maxfilesize = INT64_MAX,
			.maxlink = 1,
			.maxnamelen = 255,
			.maxpathlen = 4096,
			.no_trunc = true,
			.chown_restricted = true,
			.case_insensitive = false,
			.case_preserving = true,
			.link_support = false,
			.symlink_support = true,
			.lock_support = true,
			.lock_support_async_block = false,
			.named_attr = true,
			.unique_handles = true,
			.acl_support = FSAL_ACLSUPPORT_ALLOW,
			.cansettime = true,
			.homogenous = true,
			.supported_attrs = ATTRS_POSIX,
			.maxread = 1048576,
			.maxwrite = 1048576,
			.umask = 0,
			.auth_exportpath_xdev = false,
			.link_supports_permission_checks = true,
			.expire_time_parent = 0,
		}
	}
};

static bool hex_encode(const void *raw, size_t raw_length, char *output,
		       size_t output_length)
{
	static const char alphabet[] = "0123456789abcdef";
	const uint8_t *bytes = raw;

	if (output_length != raw_length * 2 + 1)
		return false;
	for (size_t index = 0; index < raw_length; index++) {
		output[index * 2] = alphabet[bytes[index] >> 4];
		output[index * 2 + 1] = alphabet[bytes[index] & 0x0f];
	}
	output[raw_length * 2] = '\0';
	return true;
}

bool filebelt_fsal_capture_request(struct filebelt_fsal_request_context *output)
{
	compound_data_t *compound;
	struct filebelt_rpcsec_gss_identity identity;

	if (output == NULL || op_ctx == NULL || op_ctx->nfs_reqdata == NULL ||
	    op_ctx->nfs_minorvers < 1)
		return false;
	compound = op_ctx->nfs_reqdata->proc_data;
	if (compound == NULL || compound->req == NULL || compound->session == NULL ||
	    compound->sequence == 0 || compound->slotid > 1023 ||
	    compound->oppos > 63 ||
	    !nfs_req_filebelt_rpcsec_gss_identity(compound->req, &identity))
		return false;
	memset(output, 0, sizeof(*output));
	memcpy(output->principal, identity.principal, sizeof(output->principal));
	memcpy(output->gss_binding, identity.context_binding,
	       sizeof(output->gss_binding));
	memcpy(output->source_address, identity.source_address,
	       sizeof(output->source_address));
	output->context_expires_at_unix_seconds =
		identity.expires_at_unix_seconds;
	if (snprintf(output->client_id, sizeof(output->client_id), "%016" PRIx64,
		     (uint64_t)compound->session->clientid) !=
	    sizeof(output->client_id) - 1 ||
	    !hex_encode(compound->session->session_id,
			NFS4_SESSIONID_SIZE, output->nfs_session_id,
			sizeof(output->nfs_session_id))) {
		memset(output, 0, sizeof(*output));
		return false;
	}
	output->slot_id = compound->slotid;
	output->sequence_id = compound->sequence;
	output->operation_index = compound->oppos;
	return true;
}

/* Export creation is installed by filebelt_export.c. Keeping registration in
 * this small translation unit makes the ABI probe and loader boundary easy to
 * audit independently of callback marshalling. */
extern fsal_status_t filebelt_create_export(
	struct fsal_module *fsal_hdl, void *parse_node,
	struct config_error_type *err_type,
	const struct fsal_up_vector *up_ops);

static fsal_status_t filebelt_init_config(
	struct fsal_module *fsal_hdl, config_file_t config_struct,
	struct config_error_type *err_type)
{
	(void)config_struct;
	(void)err_type;
	display_fsinfo(fsal_hdl);
	return fsalstat(ERR_FSAL_NO_ERROR, 0);
}

MODULE_INIT void filebelt_fsal_init(void)
{
	struct fsal_module *module = &FILEBELT.module;

	if (register_fsal(module, filebelt_fsal_name, FSAL_MAJOR_VERSION,
			  FSAL_MINOR_VERSION, FSAL_ID_NO_PNFS) != 0) {
		LogCrit(COMPONENT_FSAL, "FILEBELT module failed to register");
		return;
	}
	module->m_ops.create_export = filebelt_create_export;
	module->m_ops.init_config = filebelt_init_config;
}

MODULE_FINI void filebelt_fsal_unload(void)
{
	if (unregister_fsal(&FILEBELT.module) != 0)
		LogCrit(COMPONENT_FSAL, "FILEBELT module failed to unregister");
}

#endif /* FILEBELT_GANESHA_ABI */
