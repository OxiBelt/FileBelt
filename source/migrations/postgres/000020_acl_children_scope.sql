-- SPDX-License-Identifier: Apache-2.0

-- Admit the stable immediate-children ACL scope without rewriting the Phase 2
-- baseline.  The policy evaluator treats an entry on its owning resource as
-- direct evidence, `children` reaches exactly depth one, and `descendants`
-- reaches every positive depth.  `self_and_descendants` remains the legacy
-- direct-share spelling for the union of the direct and descendant scopes.

ALTER TABLE public.acl_entries
  DROP CONSTRAINT acl_entries_inheritance_check,
  ADD CONSTRAINT acl_entries_inheritance_check CHECK (
    inheritance IN ('self','children','descendants','self_and_descendants')
  );

-- Rebuild the live NFS traversal projection so the newly admitted scope is
-- evaluated at exactly one ancestry edge and never reaches grandchildren.
CREATE OR REPLACE VIEW filebelt_mount.nfs_managed_traversal AS
SELECT DISTINCT
  acl.tenant_id,
  acl.drive_id,
  path.ancestor_id,
  acl.principal_id,
  acl.id AS source_acl_entry_id,
  acl.generation AS source_acl_generation,
  feature.generation AS feature_generation
FROM filebelt_mount.nfs_feature_state AS feature
JOIN public.acl_entries AS acl
  ON acl.tenant_id=feature.tenant_id AND acl.effect='allow'
JOIN public.node_ancestry AS covered
  ON covered.tenant_id=acl.tenant_id AND covered.drive_id=acl.drive_id
 AND covered.ancestor_id=acl.resource_id
 AND (
   covered.depth=0
   OR (covered.depth=1 AND acl.inheritance IN (
     'children','descendants','self_and_descendants'
   ))
   OR (covered.depth>1 AND acl.inheritance IN (
     'descendants','self_and_descendants'
   ))
 )
JOIN public.node_ancestry AS path
  ON path.tenant_id=covered.tenant_id AND path.drive_id=covered.drive_id
 AND path.descendant_id=covered.descendant_id AND path.depth>0
WHERE feature.state IN ('preflight','active','draining');
