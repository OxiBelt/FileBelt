-- SPDX-License-Identifier: Apache-2.0

-- Extend the coordinator-owned operation receipt allowlist for the two
-- document close mutations. The application records each receipt in the same
-- transaction as the participant/session mutation so response-loss retries
-- replay the committed result instead of reapplying ownership checks.

ALTER TABLE filebelt_document.operation_receipts
  DROP CONSTRAINT operation_receipts_command_kind_check,
  ADD CONSTRAINT operation_receipts_command_kind_check CHECK (
    command_kind IN (
      'create_session',
      'conflict_copy',
      'revoke_session',
      'force_close_session'
    )
  );
