// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! Statically linked C++ witness converter (zilk_core/dev/witness_converter):
//! witness JSON in, MFBD envelope (16-byte header + FBND FlatBundle) out.
//! Replaces spawning the json_witness_to_flat_bundle CLI.

use std::ffi::{c_char, c_void, CStr};
use std::ptr;

use eyre::{eyre, Result};

extern "C" {
    fn z6m_json_witness_to_mfbd(
        json: *const u8,
        json_len: usize,
        out_data: *mut *mut u8,
        out_len: *mut usize,
        out_err: *mut *mut c_char,
    ) -> i32;
    fn z6m_mfbd_free(p: *mut c_void);
}

/// The converter was tuned for a large stack (the CLI linked with
/// `-z stack-size=0x1000000`); run it on a dedicated 64 MiB-stack thread.
const STACK_SIZE: usize = 64 * 1024 * 1024;

/// Convert a witness JSON document (object with `block`, `headers` and
/// optional `state`/`codes`/`keys`/`fork`/`expect_invalid`) into MFBD bytes.
pub fn json_witness_to_flat_bundle(json: &[u8]) -> Result<Vec<u8>> {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("witness-to-mfbd".to_string())
            .stack_size(STACK_SIZE)
            .spawn_scoped(scope, || convert(json))
            .map_err(|e| eyre!("failed to spawn converter thread: {e}"))?
            .join()
            .map_err(|_| eyre!("witness converter thread panicked"))?
    })
}

fn convert(json: &[u8]) -> Result<Vec<u8>> {
    let mut data: *mut u8 = ptr::null_mut();
    let mut len: usize = 0;
    let mut err: *mut c_char = ptr::null_mut();

    // SAFETY: json is a live slice for the duration of the call; the out
    // pointers are valid locals. The C side never throws across the boundary
    // and returns malloc'd buffers we free below.
    let rc = unsafe {
        z6m_json_witness_to_mfbd(json.as_ptr(), json.len(), &mut data, &mut len, &mut err)
    };

    if rc == 0 {
        // SAFETY: on success data/len describe a valid malloc'd buffer.
        let bytes = if data.is_null() {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
        };
        unsafe { z6m_mfbd_free(data.cast()) };
        Ok(bytes)
    } else {
        let message = if err.is_null() {
            format!("converter failed with code {rc}")
        } else {
            // SAFETY: on failure err is a malloc'd NUL-terminated string.
            let message = unsafe { CStr::from_ptr(err) }
                .to_string_lossy()
                .into_owned();
            unsafe { z6m_mfbd_free(err.cast()) };
            message
        };
        Err(eyre!("{message}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_json_is_a_clean_error() {
        let err = json_witness_to_flat_bundle(b"garbage{").unwrap_err();
        assert!(err.to_string().contains("JSON parse failed"), "{err}");
    }

    #[test]
    fn empty_input_is_a_clean_error() {
        assert!(json_witness_to_flat_bundle(b"").is_err());
    }

    #[test]
    fn missing_block_field_is_reported() {
        let err = json_witness_to_flat_bundle(br#"{"headers": []}"#).unwrap_err();
        assert!(
            err.to_string().contains("missing/invalid field 'block'"),
            "{err}"
        );
    }

    #[test]
    fn missing_headers_is_reported() {
        let err = json_witness_to_flat_bundle(br#"{"block": "0x00"}"#).unwrap_err();
        assert!(
            err.to_string().contains("missing/invalid 'headers' array"),
            "{err}"
        );
    }
}
