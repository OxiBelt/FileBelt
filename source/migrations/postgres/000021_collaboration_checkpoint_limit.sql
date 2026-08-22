-- SPDX-License-Identifier: Apache-2.0

-- Keep the durable checkpoint contract aligned with the tenant-configurable
-- maximum Markdown edit size. The application has enforced the same 16 MiB
-- ceiling before reaching PostgreSQL since the text-limit contract landed.

ALTER TABLE filebelt_collaboration.checkpoints
  DROP CONSTRAINT checkpoints_source_size_bytes_check,
  ADD CONSTRAINT checkpoints_source_size_bytes_check
    CHECK (source_size_bytes BETWEEN 0 AND 16777216);
