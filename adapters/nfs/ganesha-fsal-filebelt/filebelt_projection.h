/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef FILEBELT_PROJECTION_H
#define FILEBELT_PROJECTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FILEBELT_PROJECTED_NAME_BYTES 256U

struct filebelt_identity_projection {
	uint32_t uid;
	uint32_t gid;
	size_t owner_length;
	size_t group_length;
	char owner_name[FILEBELT_PROJECTED_NAME_BYTES];
	char group_name[FILEBELT_PROJECTED_NAME_BYTES];
	bool initialized;
};

bool filebelt_projection_initialize(
	struct filebelt_identity_projection *projection, uint32_t uid,
	uint32_t gid, const uint8_t *owner_name, size_t owner_length,
	const uint8_t *group_name, size_t group_length);

bool filebelt_projection_matches(
	const struct filebelt_identity_projection *projection, uint32_t uid,
	uint32_t gid, const uint8_t *owner_name, size_t owner_length,
	const uint8_t *group_name, size_t group_length);

#endif
