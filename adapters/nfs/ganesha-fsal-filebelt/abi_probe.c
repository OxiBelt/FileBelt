/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "config.h"
#include "fsal.h"
#include "nfs_creds.h"
#include "nfs_proto_data.h"
#include "sal_data.h"

#include <stddef.h>

_Static_assert(FSAL_MAJOR_VERSION == 13, "unexpected FSAL major ABI");
_Static_assert(FSAL_MINOR_VERSION == 0, "unexpected FSAL minor ABI");
_Static_assert(RPCSEC_GSS_SVC_PRIVACY == 3,
	       "unexpected RPCSEC_GSS privacy value");
_Static_assert(FILEBELT_GSS_BINDING_BYTES == 32,
	       "unexpected FileBelt GSS binding size");
_Static_assert(sizeof(((struct req_op_context *)0)->nfs_reqdata) ==
	       sizeof(nfs_request_t *), "request ABI changed");
_Static_assert(sizeof(((compound_data_t *)0)->slotid) == sizeof(slotid4),
	       "slot ABI changed");
_Static_assert(sizeof(((compound_data_t *)0)->sequence) == sizeof(sequenceid4),
	       "sequence ABI changed");
_Static_assert(sizeof(((nfs41_session_t *)0)->session_id) == NFS4_SESSIONID_SIZE,
	       "session identity ABI changed");

int main(void)
{
	return 0;
}
