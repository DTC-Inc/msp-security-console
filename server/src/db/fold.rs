//! Case-insensitive search for every letter on SQLite, as PostgreSQL's ILIKE already is: SQLite's own
//! LIKE folds ASCII letters only, so "ärzte" never found "ÄRZTE". `msp_fold(text)` is the text lowercased by Rust's
//! Unicode rules (str::to_lowercase), registered on every SQLite connection as an auto-extension, like sqlite-vec, so
//! search compares msp_fold(name) LIKE msp_fold(pattern). No ICU, nothing loaded from disk; NULL stays NULL.

use libsqlite3_sys as ffi;
use std::os::raw::{c_char, c_int};

/// The function's body: one argument, its text folded. Anything but text (a number, a blob) is folded as SQLite's
/// own text form of it.
unsafe extern "C" fn fold(ctx: *mut ffi::sqlite3_context, argc: c_int, argv: *mut *mut ffi::sqlite3_value) {
    // SAFETY: SQLite calls this with argc values in argv, each valid for the call; the text pointer it hands back is
    // valid for `len` bytes until the value changes, and SQLITE_TRANSIENT has SQLite copy the result before returning.
    unsafe {
        if argc != 1 { ffi::sqlite3_result_null(ctx); return; }
        let v = *argv;
        if ffi::sqlite3_value_type(v) == ffi::SQLITE_NULL { ffi::sqlite3_result_null(ctx); return; }
        let p = ffi::sqlite3_value_text(v);
        let len = ffi::sqlite3_value_bytes(v);
        if p.is_null() || len < 0 { ffi::sqlite3_result_null(ctx); return; }
        let s = String::from_utf8_lossy(std::slice::from_raw_parts(p, len as usize)).to_lowercase();
        ffi::sqlite3_result_text(ctx, s.as_ptr() as *const c_char, s.len() as c_int, ffi::SQLITE_TRANSIENT());
    }
}

/// The auto-extension's entry point: registers msp_fold on the connection being opened.
unsafe extern "C" fn init(db: *mut ffi::sqlite3, _err: *mut *mut c_char, _api: *const ffi::sqlite3_api_routines) -> c_int {
    // SAFETY: SQLite calls an auto-extension with the connection it's opening; the name is a NUL-terminated literal.
    unsafe {
        ffi::sqlite3_create_function_v2(db, c"msp_fold".as_ptr(), 1, ffi::SQLITE_UTF8 | ffi::SQLITE_DETERMINISTIC, std::ptr::null_mut(),
            Some(fold), None, None, None)
    }
}

/// Register msp_fold once per process, for every SQLite connection opened after it.
pub fn register() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: init has the xEntryPoint signature SQLite expects of an auto-extension.
        let rc = unsafe { ffi::sqlite3_auto_extension(Some(init)) };
        let _ = rc;   // only SQLITE_NOMEM fails it; search then refuses with the database's own reason
    });
}
