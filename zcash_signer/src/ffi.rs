//! C ABI for consumption over `dart:ffi`.
//!
//! Conventions:
//! - Byte inputs are passed as (pointer, length).
//! - Every function returns a heap-allocated, NUL-terminated UTF-8 JSON string:
//!   `{"ok": <payload>}` on success or `{"error": "<message>"}` on failure.
//!   Binary payloads (signed PCZTs) are hex-encoded inside the JSON.
//! - The caller must release every returned string with `zsig_free_string`.
//! - `network`: 0 = mainnet, 1 = testnet.

use std::ffi::{c_char, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::keys::{self, Network};

fn network_from(raw: u32) -> Result<Network, String> {
    match raw {
        0 => Ok(Network::Main),
        1 => Ok(Network::Test),
        other => Err(format!("unknown network {other}")),
    }
}

/// Wraps a fallible operation into the JSON envelope, catching panics so they
/// never unwind across the FFI boundary.
fn envelope<F>(f: F) -> *mut c_char
where
    F: FnOnce() -> Result<serde_json::Value, String>,
{
    let payload = match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(value)) => serde_json::json!({ "ok": value }),
        Ok(Err(message)) => serde_json::json!({ "error": message }),
        Err(_) => serde_json::json!({ "error": "internal panic in zcash_signer" }),
    };
    let json = serde_json::to_string(&payload)
        .unwrap_or_else(|_| r#"{"error":"failed to encode response"}"#.to_string());
    CString::new(json)
        .unwrap_or_else(|_| CString::new(r#"{"error":"NUL in response"}"#).unwrap())
        .into_raw()
}

/// # Safety
/// `ptr`/`len` must describe a valid readable byte range.
unsafe fn slice_from<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], String> {
    if ptr.is_null() {
        return Err("null pointer".into());
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Returns the ZIP-32 seed fingerprint (hex) for a BIP-39 seed.
///
/// # Safety
/// `seed`/`seed_len` must describe a valid readable byte range.
#[no_mangle]
pub unsafe extern "C" fn zsig_seed_fingerprint(seed: *const u8, seed_len: usize) -> *mut c_char {
    envelope(|| {
        let seed = unsafe { slice_from(seed, seed_len) }?;
        let fp = keys::seed_fingerprint(seed).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "fingerprint": hex::encode(fp) }))
    })
}

/// Returns the ZIP-316 encoded UFVK for `account`.
///
/// # Safety
/// `seed`/`seed_len` must describe a valid readable byte range.
#[no_mangle]
pub unsafe extern "C" fn zsig_get_ufvk(
    seed: *const u8,
    seed_len: usize,
    account: u32,
    network: u32,
) -> *mut c_char {
    envelope(|| {
        let seed = unsafe { slice_from(seed, seed_len) }?;
        let network = network_from(network)?;
        let ufvk = keys::ufvk_string(seed, account, network).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "ufvk": ufvk }))
    })
}

/// Returns the default unified address for `account`.
///
/// # Safety
/// `seed`/`seed_len` must describe a valid readable byte range.
#[no_mangle]
pub unsafe extern "C" fn zsig_get_address(
    seed: *const u8,
    seed_len: usize,
    account: u32,
    network: u32,
) -> *mut c_char {
    envelope(|| {
        let seed = unsafe { slice_from(seed, seed_len) }?;
        let network = network_from(network)?;
        let ufvk_str = keys::ufvk_string(seed, account, network).map_err(|e| e.to_string())?;
        let ufvk = keys::decode_ufvk(&ufvk_str, network).map_err(|e| e.to_string())?;
        let address = keys::default_address(&ufvk, network).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "address": address }))
    })
}

/// Checks a PCZT against this seed + account and returns the verified display
/// summary (see [`crate::summary::Summary`]) for the confirmation screen.
///
/// # Safety
/// All pointer/length pairs must describe valid readable byte ranges.
#[no_mangle]
pub unsafe extern "C" fn zsig_check_pczt(
    pczt: *const u8,
    pczt_len: usize,
    seed: *const u8,
    seed_len: usize,
    account: u32,
    network: u32,
) -> *mut c_char {
    envelope(|| {
        let pczt = unsafe { slice_from(pczt, pczt_len) }?;
        let seed = unsafe { slice_from(seed, seed_len) }?;
        let network = network_from(network)?;
        let checked =
            crate::check_pczt(pczt, seed, account, network).map_err(|e| e.to_string())?;
        serde_json::to_value(&checked.summary).map_err(|e| e.to_string())
    })
}

/// Fully re-checks and signs a PCZT; returns the signed PCZT hex-encoded.
///
/// # Safety
/// All pointer/length pairs must describe valid readable byte ranges.
#[no_mangle]
pub unsafe extern "C" fn zsig_sign_pczt(
    pczt: *const u8,
    pczt_len: usize,
    seed: *const u8,
    seed_len: usize,
    account: u32,
    network: u32,
) -> *mut c_char {
    envelope(|| {
        let pczt = unsafe { slice_from(pczt, pczt_len) }?;
        let seed = unsafe { slice_from(seed, seed_len) }?;
        let network = network_from(network)?;
        let signed = crate::sign_pczt(pczt, seed, account, network).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "pczt": hex::encode(signed) }))
    })
}

/// Releases a string returned by any `zsig_*` function.
///
/// # Safety
/// `ptr` must be a pointer previously returned by a `zsig_*` function from
/// this library, and must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn zsig_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(unsafe { CString::from_raw(ptr) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    fn call_json(ptr: *mut c_char) -> serde_json::Value {
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string();
        unsafe { zsig_free_string(ptr) };
        serde_json::from_str(&s).unwrap()
    }

    #[test]
    fn ufvk_roundtrips_through_ffi() {
        let seed = vec![0xabu8; 64];
        let out = call_json(unsafe { zsig_get_ufvk(seed.as_ptr(), seed.len(), 0, 0) });
        assert!(out["ok"]["ufvk"].as_str().unwrap().starts_with("uview"));

        let out = call_json(unsafe { zsig_get_address(seed.as_ptr(), seed.len(), 0, 0) });
        assert!(out["ok"]["address"].as_str().unwrap().starts_with('u'));

        let out = call_json(unsafe { zsig_seed_fingerprint(seed.as_ptr(), seed.len()) });
        assert_eq!(out["ok"]["fingerprint"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn errors_are_reported_not_panicked() {
        let out = call_json(unsafe { zsig_get_ufvk(std::ptr::null(), 0, 0, 0) });
        assert!(out["error"].as_str().is_some());

        let seed = vec![0xabu8; 64];
        let out = call_json(unsafe { zsig_get_ufvk(seed.as_ptr(), seed.len(), 0, 9) });
        assert!(out["error"].as_str().unwrap().contains("unknown network"));

        let junk = vec![0u8; 16];
        let out = call_json(unsafe {
            zsig_check_pczt(junk.as_ptr(), junk.len(), seed.as_ptr(), seed.len(), 0, 0)
        });
        assert!(out["error"].as_str().is_some());
    }
}
