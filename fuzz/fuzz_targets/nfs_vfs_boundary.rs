// SPDX-License-Identifier: Apache-2.0

#![no_main]
#![deny(unsafe_code)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| filebelt_fuzz::nfs_vfs_boundary(input));
