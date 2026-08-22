-- SPDX-License-Identifier: Apache-2.0

-- Broker-mediated HTTP mutations use the existing signed MCP request identity
-- as a durable retry boundary. Only digests and safe replay metadata are
-- stored here: credential bytes, OAuth state/verifier values, authorization
-- URLs, and tokens are forbidden from the receipt payload.
CREATE TABLE filebelt_mcp.broker_operation_receipts (
  tenant_id uuid NOT NULL REFERENCES public.tenants(id),
  principal_id uuid NOT NULL,
  registration_id uuid NOT NULL,
  operation text NOT NULL CHECK (operation IN (
    'registration_configure','credential_replace','credential_erase',
    'oauth_begin','test','discover'
  )),
  operation_id uuid NOT NULL,
  request_fingerprint bytea NOT NULL CHECK (octet_length(request_fingerprint)=32),
  result jsonb CHECK (result IS NULL OR jsonb_typeof(result)='object'),
  api_completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '24 hours'
    CHECK (expires_at > created_at),
  PRIMARY KEY (tenant_id,principal_id,operation_id),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES public.principals(tenant_id,id)
);

CREATE INDEX broker_operation_receipts_expiry
  ON filebelt_mcp.broker_operation_receipts (tenant_id,expires_at)
  WHERE result IS NOT NULL AND api_completed_at IS NOT NULL;
