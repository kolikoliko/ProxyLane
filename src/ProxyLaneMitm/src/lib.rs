pub mod pki;
pub mod session;
#[cfg(test)]
mod tests;
pub mod windows;

use session::{Context, Session};
use std::{
    ffi::{c_char, CStr},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
    sync::{Arc, Mutex},
};
static CONTEXT: Mutex<Option<Arc<Context>>> = Mutex::new(None);

fn context() -> Result<Arc<Context>, String> {
    let mut slot = CONTEXT.lock().map_err(|e| e.to_string())?;
    if let Some(c) = slot.as_ref() {
        return Ok(c.clone());
    }
    let c = Context::open()?;
    *slot = Some(c.clone());
    Ok(c)
}
unsafe fn text<'a>(s: *const c_char) -> Result<&'a str, String> {
    if s.is_null() {
        return Err("null string".into());
    }
    CStr::from_ptr(s).to_str().map_err(|e| e.to_string())
}
unsafe fn write_error(output: *mut c_char, capacity: usize, error: &str) {
    if output.is_null() || capacity == 0 {
        return;
    }
    let n = error.len().min(capacity - 1);
    ptr::copy_nonoverlapping(error.as_ptr(), output as *mut u8, n);
    *output.add(n) = 0;
}
#[no_mangle]
pub extern "C" fn plm_abi_version() -> u32 {
    3
}

#[no_mangle]
/// # Safety
/// The output buffer must be writable for capacity bytes, or null.
/// Actions: 0 status, 1 initialize, 2 trust, 3 remove trust, 4 prepare TLS.
/// Returns flags (1 initialized, 2 trusted) or -1 with an error message.
pub unsafe extern "C" fn plm_ca(action: u32, output: *mut c_char, capacity: usize) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<(i32, String), String> {
        if action > 4 {
            return Err("Unknown CA action".into());
        }
        let path = pki::directory()?;
        if action == 0 && !path.join("ca.json").exists() {
            return Ok((0, format!("CA not initialized.\r\n{}", path.display())));
        }
        let ca = pki::Authority::load(&path, action == 1 || action == 2)?;
        let trusted = windows::trust(
            &ca.der,
            match action {
                2 => "install",
                3 => "remove",
                _ => "status",
            },
        )?;
        if action == 4 {
            if !trusted {
                return Err(
                    "Initialize and install the CA in CA Management first (CurrentUser ROOT)."
                        .into(),
                );
            }
            context()?;
        }
        Ok((1 | if trusted { 2 } else { 0 }, format!(
            "SHA-256: {}\r\nCertificate: {}\r\nCurrentUser ROOT: {}\r\nCRL: http://127.0.0.1:{}/pki/{}.crl",
            ca.id, path.join("proxylane-ca.cer").display(), trusted, ca.port, ca.id)))
    }));
    match result {
        Ok(Ok((flags, info))) => {
            write_error(output, capacity, &info);
            flags
        }
        Ok(Err(e)) => {
            write_error(output, capacity, &e);
            -1
        }
        Err(_) => {
            write_error(output, capacity, "CA operation failed");
            -1
        }
    }
}

#[no_mangle]
/// # Safety
/// The session must be live and exclusively accessed. Callback must not unwind,
/// reenter or retain the borrowed bytes; user must remain valid until plm_free.
pub unsafe extern "C" fn plm_observe(
    handle: *mut Session,
    callback: extern "C" fn(usize, u32, *const u8, usize),
    user: usize,
) {
    if !handle.is_null() {
        (*handle).observer = Some((callback, user));
    }
}

#[no_mangle]
/// # Safety
/// Strings must be NUL-terminated UTF-8. `out` and the optional error buffer
/// must be writable for their declared sizes, and must not alias the strings.
pub unsafe extern "C" fn plm_create(
    host: *const c_char,
    metadata: *const c_char,
    out: *mut *mut Session,
    error: *mut c_char,
    capacity: usize,
) -> i32 {
    if out.is_null() {
        return -1;
    }
    *out = ptr::null_mut();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let host = text(host)?.to_owned();
        let metadata = serde_json::from_str(text(metadata)?).map_err(|e| e.to_string())?;
        // The GUI consumes bounded in-memory observer events. Normal sessions
        // must neither create capture files nor depend on a writable log path.
        Session::new(context()?, host, metadata, false)
    }));
    match result {
        Ok(Ok(session)) => {
            *out = Box::into_raw(Box::new(session));
            0
        }
        Ok(Err(e)) => {
            write_error(error, capacity, &e);
            -1
        }
        Err(_) => {
            write_error(error, capacity, "panic creating MITM session");
            -1
        }
    }
}

fn call(session: &mut Session, f: impl FnOnce(&mut Session) -> Result<i32, String>) -> i32 {
    if !session.error.is_empty() {
        return -1;
    }
    match catch_unwind(AssertUnwindSafe(|| f(session))) {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            session.fail(e);
            -1
        }
        Err(_) => {
            session.fail("panic in MITM session".into());
            -1
        }
    }
}
// op: 0 feed, 1 peek output, 2 consume output, 3 EOF, 4 status/tick.
// status bits: 1 can read; 2 shutdown application output; 4 shutdown upstream output;
//              8 application input EOF; 16 upstream input EOF; 32 ready.
#[no_mangle]
/// # Safety
/// `handle` must be a live session from plm_create, used on one thread at a time.
/// For feed/peek, `data` must address `len` readable/writable bytes respectively.
pub unsafe extern "C" fn plm_io(
    handle: *mut Session,
    op: u32,
    side: u32,
    data: *mut u8,
    len: usize,
) -> i32 {
    if handle.is_null() || side > 1 {
        return -1;
    }
    let s = &mut *handle;
    call(s, |s| {
        let side = side as usize;
        match op {
            0 => {
                if data.is_null() || len == 0 {
                    return Err("empty input".into());
                }
                s.feed(side, slice::from_raw_parts(data, len))?;
                Ok(0)
            }
            1 => {
                if data.is_null() || len == 0 {
                    return Err("empty output buffer".into());
                }
                Ok(s.peek(side, slice::from_raw_parts_mut(data, len))? as i32)
            }
            2 => {
                s.consume(side, len)?;
                Ok(0)
            }
            3 => {
                s.input_eof(side)?;
                Ok(0)
            }
            4 => {
                s.tick()?;
                s.pump()?;
                Ok(i32::from(s.can_read())
                    | (i32::from(s.shutdown_output(0)) << 1)
                    | (i32::from(s.shutdown_output(1)) << 2)
                    | (i32::from(s.eof[0]) << 3)
                    | (i32::from(s.eof[1]) << 4)
                    | (i32::from(s.ready()) << 5))
            }
            _ => Err("invalid operation".into()),
        }
    })
}
#[no_mangle]
/// # Safety
/// `handle` must be live and exclusively accessed. `output` must be writable
/// for `capacity` bytes (or null when no output is needed).
pub unsafe extern "C" fn plm_error(handle: *mut Session, output: *mut c_char, capacity: usize) {
    if !handle.is_null() {
        write_error(output, capacity, &(*handle).error);
    }
}
#[no_mangle]
/// # Safety
/// A non-null handle must come from plm_create, have no concurrent users, and
/// must not have been freed. It becomes invalid after this call.
pub unsafe extern "C" fn plm_free(handle: *mut Session) {
    if !handle.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(handle))));
    }
}
