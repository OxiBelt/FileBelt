// SPDX-License-Identifier: Apache-2.0

#![no_main]
#![deny(unsafe_code)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(
    init: filebelt_fuzz::install_collaboration_panic_hook(),
    |input: &[u8]| filebelt_fuzz::collaboration_wire(input)
);
