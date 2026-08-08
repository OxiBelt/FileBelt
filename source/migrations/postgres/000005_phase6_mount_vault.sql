-- SPDX-License-Identifier: Apache-2.0

-- Complete the per-credential envelope shape before any Phase 6 runtime can
-- write mount secrets. Refuse to reinterpret an envelope from an intermediate
-- development build because wrapped-key metadata cannot be reconstructed.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM filebelt_mount_vault.secret_envelopes) THEN
    RAISE EXCEPTION 'mount vault envelope upgrade requires an empty pre-release table';
  END IF;
END
$$;

ALTER TABLE filebelt_mount_vault.secret_envelopes
  ADD COLUMN owner_principal_id uuid NOT NULL,
  ADD COLUMN credential_generation bigint NOT NULL CHECK (credential_generation > 0),
  ADD COLUMN namespace text NOT NULL CHECK (namespace IN ('smb','ftps')),
  ADD COLUMN wrapped_dek bytea NOT NULL CHECK (octet_length(wrapped_dek)=48),
  ADD COLUMN wrap_nonce bytea NOT NULL CHECK (octet_length(wrap_nonce)=12),
  ADD COLUMN aad_version integer NOT NULL DEFAULT 1 CHECK (aad_version=1),
  ADD CONSTRAINT mount_secret_owner_fk
    FOREIGN KEY (tenant_id,owner_principal_id) REFERENCES principals(tenant_id,id),
  ADD CONSTRAINT mount_secret_nonce_unique UNIQUE (tenant_id,nonce),
  ADD CONSTRAINT mount_secret_wrap_nonce_unique UNIQUE (tenant_id,wrap_nonce);

ALTER TABLE filebelt_mount.authentication_throttles
  ADD CONSTRAINT mount_authentication_throttle_tenant_fk
    FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE filebelt_mount.credentials
  ADD CONSTRAINT mount_credential_maximum_lifetime
    CHECK (expires_at <= created_at + interval '7 days');
