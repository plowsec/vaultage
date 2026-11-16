//! C ABI for the macOS app. Keys never cross this boundary; plaintext only via `coffer_read`.

use std::ffi::{c_char, CStr, CString};
use std::sync::OnceLock;

use vaultage_core::manager::{default_home, Manager};
use serde_json::{json, Value};
use zeroize::Zeroize;

static MANAGER: OnceLock<Result<Manager, String>> = OnceLock::new();

fn manager() -> Result<&'static Manager, String> {
    MANAGER.get_or_init(|| Manager::new(default_home(), true).map_err(|e| e.to_string())).as_ref().map_err(|e| e.clone())
}

fn to_c(v: &Value) -> *mut c_char {
    CString::new(v.to_string()).unwrap_or_default().into_raw()
}

fn parse(req: *const c_char) -> Result<Value, String> {
    if req.is_null() {
        return Err("null request".into());
    }
    let text = unsafe { CStr::from_ptr(req) }.to_str().map_err(|_| "request is not UTF-8".to_string())?;
    serde_json::from_str(text).map_err(|e| e.to_string())
}

fn guarded<T>(f: impl FnOnce() -> T, on_panic: impl FnOnce() -> T) -> T {
    // The release profile aborts on panic; this only matters for unwinding builds.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| on_panic())
}

/// Apply process hardening. Call before anything else. Returns the posture as JSON.
#[no_mangle]
pub extern "C" fn coffer_harden() -> *mut c_char {
    to_c(&serde_json::to_value(vaultage_core::harden::harden()).unwrap_or(Value::Null))
}

/// Run one API request (see vaultage_core::api). `secret` may be null. Free the result with
/// `coffer_free_string`.
#[no_mangle]
pub extern "C" fn coffer_call(request: *const c_char, secret: *const u8, secret_len: usize) -> *mut c_char {
    let fail = |code: &str, msg: String| to_c(&json!({ "ok": false, "code": code, "error": msg }));
    guarded(
        || {
            let req = match parse(request) {
                Ok(r) => r,
                Err(e) => return fail("invalid", e),
            };
            let m = match manager() {
                Ok(m) => m,
                Err(e) => return fail("io", e),
            };
            let secret = if secret.is_null() { &[][..] } else { unsafe { std::slice::from_raw_parts(secret, secret_len) } };
            to_c(&vaultage_core::api::call(m, &req, secret))
        },
        || fail("internal", "internal error".into()),
    )
}

/// Decrypt a file into memory. Returns null and sets `*error` on failure.
/// Free the buffer with `coffer_free_bytes` (it wipes it first).
#[no_mangle]
pub extern "C" fn coffer_read(request: *const c_char, out_len: *mut usize, error: *mut *mut c_char) -> *mut u8 {
    let set_err = |msg: String| {
        if !error.is_null() {
            unsafe { *error = CString::new(msg).unwrap_or_default().into_raw() };
        }
        std::ptr::null_mut()
    };
    guarded(
        || {
            let res = parse(request).and_then(|req| manager().and_then(|m| vaultage_core::api::read(m, &req).map_err(|e| e.to_string())));
            match res {
                Ok(data) => {
                    let mut boxed = data.into_boxed_slice();
                    unsafe { *out_len = boxed.len() };
                    let ptr = boxed.as_mut_ptr();
                    std::mem::forget(boxed);
                    ptr
                }
                Err(e) => set_err(e),
            }
        },
        || set_err("internal error".into()),
    )
}

#[no_mangle]
pub extern "C" fn coffer_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

#[no_mangle]
pub extern "C" fn coffer_free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        let mut b = unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) };
        b.zeroize();
    }
}
