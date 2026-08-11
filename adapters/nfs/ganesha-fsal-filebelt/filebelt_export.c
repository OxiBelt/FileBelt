/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * The loader must fail closed until the callback translation unit and atomic
 * export-control server have been compiled into the module.  This function is
 * intentionally retained as the link-time sentinel used by the ABI probe; a
 * publishable image build replaces it by compiling the complete callback
 * source selected in CMakeLists.txt and defines FILEBELT_CALLBACKS_QUALIFIED.
 */

#include "config.h"
#include "fsal.h"

#include <errno.h>

fsal_status_t filebelt_create_export(
	struct fsal_module *fsal_hdl, void *parse_node,
	struct config_error_type *err_type,
	const struct fsal_up_vector *up_ops)
{
	(void)fsal_hdl;
	(void)parse_node;
	(void)err_type;
	(void)up_ops;
	LogCrit(COMPONENT_FSAL,
		"FILEBELT callback set is not qualified; refusing export");
	return fsalstat(ERR_FSAL_NOTSUPP, ENOTSUP);
}
