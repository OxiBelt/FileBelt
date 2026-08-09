-- SPDX-License-Identifier: Apache-2.0

-- The original Phase 7 browser handoff served provider JavaScript from the
-- FileBelt public origin. Document admission must be quiesced before applying
-- this forward-only cutover so no old binary can mint another vulnerable
-- launch after the snapshot below.

WITH affected_sessions AS MATERIALIZED (
  SELECT DISTINCT s.tenant_id,s.id,s.principal_id
  FROM api_sessions s
  JOIN filebelt_document.participants p
    ON p.tenant_id=s.tenant_id AND p.api_session_id=s.id
  WHERE s.revoked_at IS NULL
    AND s.idle_expires_at>statement_timestamp()
    AND s.absolute_expires_at>statement_timestamp()
), revoked_sessions AS (
  UPDATE api_sessions s
  SET revoked_at=clock_timestamp()
  FROM affected_sessions affected
  WHERE s.tenant_id=affected.tenant_id AND s.id=affected.id
    AND s.revoked_at IS NULL
  RETURNING s.tenant_id,s.id,s.principal_id
)
INSERT INTO audit_events (
  tenant_id,id,actor_principal_id,target_principal_id,resource_id,action,
  outcome,reason_code,privacy_visible,details
)
SELECT tenant_id,uuidv7(),NULL,principal_id,NULL,'session.revoke','allowed',
  'onlyoffice_origin_isolation_cutover',true,
  jsonb_build_object('session_id',id)
FROM revoked_sessions;

UPDATE filebelt_document.launch_grants grants
SET consumed_at=clock_timestamp()
WHERE grants.consumed_at IS NULL;

UPDATE filebelt_document.participants participants
SET state='closed',disconnected_until=NULL,closed_at=clock_timestamp(),
  close_reason='onlyoffice_origin_isolation_cutover'
WHERE participants.state IN ('active','disconnected');

WITH closed_sessions AS MATERIALIZED (
  UPDATE filebelt_document.sessions sessions
  SET state='revoked',fencing_token=fencing_token+1,
    closed_at=clock_timestamp(),
    close_reason='onlyoffice_origin_isolation_cutover'
  WHERE sessions.state IN ('active','draining')
  RETURNING sessions.tenant_id,sessions.id
), audited_sessions AS (
  INSERT INTO audit_events (
    tenant_id,id,actor_principal_id,target_principal_id,resource_id,action,
    outcome,reason_code,privacy_visible,details
  )
  SELECT tenant_id,uuidv7(),NULL,NULL,NULL,'document.session.force_close',
    'allowed','onlyoffice_origin_isolation_cutover',true,
    jsonb_build_object('document_session_id',id)
  FROM closed_sessions
  RETURNING id
)
INSERT INTO filebelt_document.data_migrations (name,affected_resources)
SELECT 'onlyoffice_origin_isolation_v1',count(*) FROM closed_sessions;
