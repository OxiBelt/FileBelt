// SPDX-License-Identifier: Apache-2.0

//! Yjs v1 decoding with FileBelt's structural admission checks.

use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use std::sync::Once;

use yrs::any::Any;
use yrs::block::BLOCK_GC_REF_NUMBER;
use yrs::encoding::read::{Error, Read};
use yrs::updates::decoder::{Decode as _, Decoder, DecoderV1};
use yrs::{ClientID, ID, Update};

use crate::RoomDocumentError;

thread_local! {
    static CONTAINING_UNTRUSTED_PANIC: Cell<bool> = const { Cell::new(false) };
}

struct PanicContainmentGuard {
    previous: bool,
}

impl PanicContainmentGuard {
    fn enter() -> Self {
        let previous = CONTAINING_UNTRUSTED_PANIC.replace(true);
        Self { previous }
    }
}

impl Drop for PanicContainmentGuard {
    fn drop(&mut self) {
        CONTAINING_UNTRUSTED_PANIC.set(self.previous);
    }
}

fn is_containing_untrusted_panic() -> bool {
    CONTAINING_UNTRUSTED_PANIC.get()
}

pub(super) fn contain_untrusted_panic<T>(
    malformed: RoomDocumentError,
    operation: impl FnOnce() -> Result<T, RoomDocumentError>,
) -> Result<T, RoomDocumentError> {
    // The caller must restrict `operation` to untrusted Yrs work on disposable
    // in-memory state. This is the safety argument for AssertUnwindSafe: no
    // acknowledged state or external side effect may survive a caught unwind.
    let guard = PanicContainmentGuard::enter();
    let result = catch_unwind(AssertUnwindSafe(operation));
    drop(guard);
    match result {
        Ok(result) => result,
        Err(_) => Err(malformed),
    }
}

pub(super) fn install_containment_aware_panic_hook() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            if !is_containing_untrusted_panic() {
                previous_hook(panic_info);
            }
        }));
    });
}

struct CheckedDecoderV1<'a> {
    inner: DecoderV1<'a>,
    pending_gc_length: bool,
}

impl<'a> CheckedDecoderV1<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            inner: DecoderV1::from(input),
            pending_gc_length: false,
        }
    }
}

impl Read for CheckedDecoderV1<'_> {
    fn read_exact(&mut self, len: usize) -> Result<&[u8], Error> {
        self.inner.read_exact(len)
    }
}

impl Decoder for CheckedDecoderV1<'_> {
    fn reset_ds_cur_val(&mut self) {
        self.inner.reset_ds_cur_val();
    }

    fn read_ds_clock(&mut self) -> Result<u32, Error> {
        self.inner.read_ds_clock()
    }

    fn read_ds_len(&mut self) -> Result<u32, Error> {
        self.inner.read_ds_len()
    }

    fn read_left_id(&mut self) -> Result<ID, Error> {
        self.inner.read_left_id()
    }

    fn read_right_id(&mut self) -> Result<ID, Error> {
        self.inner.read_right_id()
    }

    fn read_client(&mut self) -> Result<ClientID, Error> {
        self.inner.read_client()
    }

    fn read_info(&mut self) -> Result<u8, Error> {
        let info = self.inner.read_info()?;
        self.pending_gc_length = info == BLOCK_GC_REF_NUMBER;
        Ok(info)
    }

    fn read_parent_info(&mut self) -> Result<bool, Error> {
        self.inner.read_parent_info()
    }

    fn read_type_ref(&mut self) -> Result<u8, Error> {
        self.inner.read_type_ref()
    }

    fn read_len(&mut self) -> Result<u32, Error> {
        let pending_gc_length = std::mem::take(&mut self.pending_gc_length);
        let len = self.inner.read_len()?;
        if pending_gc_length && len == 0 {
            Err(zero_length_block_error())
        } else {
            Ok(len)
        }
    }

    fn read_any(&mut self) -> Result<Any, Error> {
        self.inner.read_any()
    }

    fn read_json(&mut self) -> Result<Any, Error> {
        self.inner.read_json()
    }

    fn read_key(&mut self) -> Result<Arc<str>, Error> {
        self.inner.read_key()
    }

    fn read_to_end(&mut self) -> Result<&[u8], Error> {
        self.inner.read_to_end()
    }
}

fn zero_length_block_error() -> Error {
    Error::Custom("zero-length Yjs blocks are not admissible".to_owned())
}

pub(crate) fn decode_update_v1(input: &[u8]) -> Result<Update, Error> {
    let mut decoder = CheckedDecoderV1::new(input);
    Update::decode(&mut decoder)
}

#[cfg(test)]
mod tests {
    use yrs::encoding::write::Write as _;
    use yrs::updates::encoder::{Encoder as _, EncoderV1};

    use super::*;

    fn gc_update(len: u32) -> Vec<u8> {
        let mut encoder = EncoderV1::new();
        encoder.write_var(1u32);
        encoder.write_var(1u32);
        encoder.write_client(ClientID::new(42));
        encoder.write_var(1u32);
        encoder.write_info(BLOCK_GC_REF_NUMBER);
        encoder.write_len(len);
        encoder.write_var(0u32);
        encoder.to_vec()
    }

    #[test]
    fn rejects_zero_length_gc_blocks() {
        assert!(decode_update_v1(&gc_update(0)).is_err());
    }

    #[test]
    fn accepts_positive_length_gc_blocks() {
        decode_update_v1(&gc_update(1)).unwrap();
    }

    #[test]
    fn panic_containment_is_nested_and_thread_local() {
        assert!(!is_containing_untrusted_panic());
        let result = contain_untrusted_panic(RoomDocumentError::InvalidUpdate, || {
            assert!(is_containing_untrusted_panic());
            assert!(
                !std::thread::spawn(is_containing_untrusted_panic)
                    .join()
                    .unwrap()
            );
            assert_eq!(
                contain_untrusted_panic(
                    RoomDocumentError::InvalidSnapshot,
                    || -> Result<(), RoomDocumentError> {
                        panic!("repository-constructed containment regression")
                    },
                ),
                Err(RoomDocumentError::InvalidSnapshot)
            );
            assert!(is_containing_untrusted_panic());
            Ok(())
        });
        assert_eq!(result, Ok(()));
        assert!(!is_containing_untrusted_panic());
    }
}
