/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "filebelt_projection.h"

#include <string.h>

static bool valid_names(const uint8_t *owner_name, size_t owner_length,
			const uint8_t *group_name, size_t group_length)
{
	return owner_name != NULL && owner_length != 0 &&
	       owner_length < FILEBELT_PROJECTED_NAME_BYTES &&
	       group_name != NULL && group_length != 0 &&
	       group_length < FILEBELT_PROJECTED_NAME_BYTES;
}

bool filebelt_projection_initialize(
	struct filebelt_identity_projection *projection, uint32_t uid,
	uint32_t gid, const uint8_t *owner_name, size_t owner_length,
	const uint8_t *group_name, size_t group_length)
{
	if (projection == NULL || projection->initialized ||
	    !valid_names(owner_name, owner_length, group_name, group_length))
		return false;
	projection->uid = uid;
	projection->gid = gid;
	projection->owner_length = owner_length;
	projection->group_length = group_length;
	memcpy(projection->owner_name, owner_name, owner_length);
	projection->owner_name[owner_length] = '\0';
	memcpy(projection->group_name, group_name, group_length);
	projection->group_name[group_length] = '\0';
	/* Initialization is complete before the containing object is published. */
	projection->initialized = true;
	return true;
}

bool filebelt_projection_matches(
	const struct filebelt_identity_projection *projection, uint32_t uid,
	uint32_t gid, const uint8_t *owner_name, size_t owner_length,
	const uint8_t *group_name, size_t group_length)
{
	return projection != NULL && projection->initialized &&
	       valid_names(owner_name, owner_length, group_name, group_length) &&
	       projection->uid == uid && projection->gid == gid &&
	       projection->owner_length == owner_length &&
	       projection->group_length == group_length &&
	       memcmp(projection->owner_name, owner_name, owner_length) == 0 &&
	       memcmp(projection->group_name, group_name, group_length) == 0;
}
