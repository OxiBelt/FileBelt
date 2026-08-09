/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * NFS-Ganesha 6.5-8 dynamic-FSAL integration boundary.
 *
 * This source intentionally contains no FileBelt Core, PostgreSQL, payload,
 * or Kerberos implementation. The reviewed Ganesha build supplies the FSAL
 * callback ABI through its installed headers; callbacks marshal only opaque
 * FileBelt VFS protobuf bytes to the local Rust bridge over SOCK_SEQPACKET.
 *
 * The exact header symbols and callback table are verified in the adapter
 * image build against the selected Ubuntu 26.04 package source. Keeping that
 * ABI-dependent translation unit here prevents Apache packages from importing
 * Ganesha headers or treating the bridge framing as an NFS implementation.
 */

#include <stdint.h>

enum { FILEBELT_BRIDGE_PREFIX_BYTES = 4, FILEBELT_BRIDGE_MAX_FRAME_BYTES = 1114112 };

/* The loader-facing module entry is supplied by the version-pinned Ganesha
 * integration translation unit during the adapter image build. This portable
 * bounded helper is independently testable without Ganesha headers. */
int filebelt_fsal_frame_length(const uint8_t prefix[FILEBELT_BRIDGE_PREFIX_BYTES],
                               uint32_t *length) {
  uint32_t value = ((uint32_t)prefix[0] << 24) | ((uint32_t)prefix[1] << 16) |
                   ((uint32_t)prefix[2] << 8) | (uint32_t)prefix[3];
  if (value > FILEBELT_BRIDGE_MAX_FRAME_BYTES) return -1;
  *length = value;
  return 0;
}
