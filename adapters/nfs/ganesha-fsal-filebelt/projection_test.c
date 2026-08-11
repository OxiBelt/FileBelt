/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "filebelt_projection.h"

#include <assert.h>
#include <string.h>

int main(void)
{
	static const uint8_t owner[] = "owner.example";
	static const uint8_t group[] = "group.example";
	static const uint8_t changed_owner[] = "other.example";
	struct filebelt_identity_projection projection = { 0 };
	struct filebelt_identity_projection snapshot;

	assert(filebelt_projection_initialize(
		&projection, 1001U, 1002U, owner, sizeof(owner) - 1U, group,
		sizeof(group) - 1U));
	snapshot = projection;
	assert(filebelt_projection_matches(
		&projection, 1001U, 1002U, owner, sizeof(owner) - 1U, group,
		sizeof(group) - 1U));
	assert(!filebelt_projection_matches(
		&projection, 2001U, 1002U, owner, sizeof(owner) - 1U, group,
		sizeof(group) - 1U));
	assert(!filebelt_projection_matches(
		&projection, 1001U, 1002U, changed_owner,
		sizeof(changed_owner) - 1U, group, sizeof(group) - 1U));
	assert(!filebelt_projection_initialize(
		&projection, 2001U, 2002U, changed_owner,
		sizeof(changed_owner) - 1U, group, sizeof(group) - 1U));
	assert(memcmp(&projection, &snapshot, sizeof(projection)) == 0);
	return 0;
}
