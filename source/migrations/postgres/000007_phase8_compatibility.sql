-- SPDX-License-Identifier: Apache-2.0

-- Phase 8 expands the schema without activating NFS, media, or WebTransport.
-- Activation is an explicit audited operator transaction after every required
-- role has advertised compatibility with configuration format 6 and schema 9.

REVOKE ALL ON SCHEMA filebelt_phase8 FROM PUBLIC;

CREATE TABLE filebelt_phase8.activation_state (
  tenant_id uuid PRIMARY KEY REFERENCES tenants(id),
  state text NOT NULL DEFAULT 'dormant'
    CHECK (state IN ('dormant','active','disabled')),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  activated_by uuid,
  activated_at timestamptz,
  disabled_by uuid,
  disabled_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (tenant_id,activated_by) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,disabled_by) REFERENCES principals(tenant_id,id),
  CHECK ((state='dormant') OR activated_at IS NOT NULL),
  CHECK ((state='disabled') = (disabled_at IS NOT NULL))
);

INSERT INTO filebelt_phase8.activation_state (tenant_id)
SELECT id FROM tenants;

CREATE FUNCTION filebelt_phase8.initialize_tenant_activation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_phase8
AS $$
BEGIN
  INSERT INTO filebelt_phase8.activation_state (tenant_id) VALUES (NEW.id)
    ON CONFLICT (tenant_id) DO NOTHING;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION filebelt_phase8.initialize_tenant_activation() FROM PUBLIC;
CREATE TRIGGER initialize_phase8_tenant_activation
AFTER INSERT ON tenants
FOR EACH ROW EXECUTE FUNCTION filebelt_phase8.initialize_tenant_activation();

CREATE TABLE filebelt_phase8.role_compatibility (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  role text NOT NULL CHECK (length(role) BETWEEN 1 AND 64),
  instance_id uuid NOT NULL,
  source_revision text NOT NULL CHECK (length(source_revision) BETWEEN 7 AND 64),
  config_version integer NOT NULL CHECK (config_version > 0),
  schema_max integer NOT NULL CHECK (schema_max > 0),
  compatible boolean NOT NULL,
  advertised_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,role,instance_id)
);
CREATE INDEX phase8_role_compatibility_fresh_index
  ON filebelt_phase8.role_compatibility (tenant_id,role,advertised_at DESC)
  WHERE compatible;

-- These rows are derived compatibility projections, not ACL entries. NFS path
-- traversal consults them together with the source ACL and current deny rows.
-- Deleting and rebuilding the table is safe while admission is disabled.
CREATE TABLE filebelt_phase8.managed_traversal (
  tenant_id uuid NOT NULL,
  drive_id uuid NOT NULL,
  ancestor_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  source_acl_entry_id uuid NOT NULL,
  activation_generation bigint NOT NULL CHECK (activation_generation > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,ancestor_id,principal_id,source_acl_entry_id),
  FOREIGN KEY (tenant_id,drive_id,ancestor_id)
    REFERENCES nodes(tenant_id,drive_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,source_acl_entry_id)
    REFERENCES acl_entries(tenant_id,id) ON DELETE CASCADE
);
CREATE INDEX phase8_managed_traversal_lookup_index
  ON filebelt_phase8.managed_traversal
    (tenant_id,drive_id,ancestor_id,principal_id);

-- This is a rebuildable, activation-generation-fenced snapshot of flat local
-- groups for mapped NFS users. It is never an identity or ACL authority.
CREATE TABLE filebelt_phase8.managed_group_memberships (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  group_id uuid NOT NULL,
  user_principal_id uuid NOT NULL,
  source_membership_generation bigint NOT NULL CHECK (source_membership_generation > 0),
  activation_generation bigint NOT NULL CHECK (activation_generation > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,group_id,user_principal_id),
  FOREIGN KEY (tenant_id,group_id) REFERENCES groups(tenant_id,id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,user_principal_id) REFERENCES principals(tenant_id,id)
);

CREATE TABLE filebelt_phase8.activation_events (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  id uuid NOT NULL,
  actor_principal_id uuid NOT NULL,
  previous_state text NOT NULL
    CHECK (previous_state IN ('dormant','active','disabled')),
  new_state text NOT NULL CHECK (new_state IN ('active','disabled')),
  generation bigint NOT NULL CHECK (generation > 0),
  compatible_roles jsonb NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id,actor_principal_id)
    REFERENCES principals(tenant_id,id)
);

CREATE FUNCTION filebelt_phase8.advertise_role(
  p_tenant_id uuid,
  p_role text,
  p_instance_id uuid,
  p_source_revision text,
  p_config_version integer,
  p_schema_max integer,
  p_compatible boolean
) RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path=pg_catalog,public,filebelt_phase8
AS $$
  INSERT INTO filebelt_phase8.role_compatibility
    (tenant_id,role,instance_id,source_revision,config_version,schema_max,compatible,advertised_at)
  VALUES
    (p_tenant_id,p_role,p_instance_id,p_source_revision,p_config_version,p_schema_max,p_compatible,clock_timestamp())
  ON CONFLICT (tenant_id,role,instance_id) DO UPDATE SET
    source_revision=EXCLUDED.source_revision,
    config_version=EXCLUDED.config_version,
    schema_max=EXCLUDED.schema_max,
    compatible=EXCLUDED.compatible,
    advertised_at=EXCLUDED.advertised_at;
$$;
REVOKE ALL ON FUNCTION filebelt_phase8.advertise_role(uuid,text,uuid,text,integer,integer,boolean)
  FROM PUBLIC;
