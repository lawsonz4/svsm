// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! Implement functions required to build the TPM 2.0 Reference Implementation
//! libraries.
//! All these functionalities are owned by the SVSM Rust code,
//! so we just need to create wrappers for them.

use crate::{
    console::_print,
    fs::{BlockFile, File},
    mm::alloc::{layout_from_ptr, layout_from_size},
    sev::msr_protocol::request_termination_msr,
};

use core::{
    alloc::Layout,
    ffi::{c_char, c_int, c_long, c_ulong, c_void, CStr},
    ptr, slice,
    slice::from_raw_parts,
    str::from_utf8,
};

extern crate alloc;
use alloc::alloc::{alloc, alloc_zeroed, dealloc, realloc as _realloc};

#[no_mangle]
pub extern "C" fn malloc(size: c_ulong) -> *mut c_void {
    if size == 0 {
        return ptr::null_mut();
    }

    let Ok(layout) = layout_from_size(size as usize) else {
        return ptr::null_mut();
    };

    // SAFETY: layout is guaranteed to be non-zero size. Memory may not be
    // initiatlized, but that's what the caller expects.
    unsafe { alloc(layout).cast() }
}

#[no_mangle]
pub extern "C" fn calloc(items: c_ulong, size: c_ulong) -> *mut c_void {
    let Some(new_size) = items.checked_mul(size) else {
        return ptr::null_mut();
    };

    if new_size == 0 {
        return ptr::null_mut();
    }

    let Ok(layout) = layout_from_size(new_size as usize) else {
        return ptr::null_mut();
    };

    // SAFETY: layout is guaranteed to be non-zero size.
    unsafe { alloc_zeroed(layout).cast() }
}

#[no_mangle]
pub unsafe extern "C" fn realloc(p: *mut c_void, size: c_ulong) -> *mut c_void {
    let ptr = p as *mut u8;
    let new_size = size as usize;

    if p.is_null() {
        return malloc(size);
    }

    let Some(layout) = layout_from_ptr(ptr) else {
        return ptr::null_mut();
    };

    if new_size == 0 {
        // SAFETY: layout_from_ptr() call ensures that `ptr` was allocated
        // with this allocator and we are using the same `layout` used to
        // allocate `ptr`.
        unsafe { dealloc(ptr, layout) };
        return ptr::null_mut();
    }

    // This will fail if `new_size` rounded value exceeds `isize::MAX`
    if Layout::from_size_align(new_size, layout.align()).is_err() {
        return ptr::null_mut();
    }

    // SAFETY: layout_from_ptr() call ensures that `ptr` was allocated with
    // this allocator and we are using the same `layout` used to allocate
    // `ptr`. We also checked that `new_size` aligned does not overflow and
    // it is not 0.
    unsafe { _realloc(ptr, layout, new_size).cast() }
}

#[no_mangle]
pub unsafe extern "C" fn free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    let ptr = p as *mut u8;
    let Some(layout) = layout_from_ptr(ptr.cast()) else {
        return;
    };
    // SAFETY: layout_from_ptr() call ensures that `ptr` was allocated
    // with this allocator and we are using the same `layout` used to
    // allocate `ptr`.
    unsafe { dealloc(ptr, layout) }
}

#[no_mangle]
pub unsafe extern "C" fn serial_out(s: *const c_char, size: c_int) {
    // SAFETY: caller must provide safety requirements for
    // [`core::slice::from_raw_parts`]
    let str_slice: &[u8] = unsafe { from_raw_parts(s as *const u8, size as usize) };
    if let Ok(rust_str) = from_utf8(str_slice) {
        _print(format_args!("[SVSM] {}", rust_str));
    } else {
        log::error!("ERR: BUG: serial_out arg1 is not a valid utf8 string");
    }
}

#[no_mangle]
pub extern "C" fn abort() -> ! {
    request_termination_msr();
}

//TODO: add lock
pub struct FileWrapper {
    bf: BlockFile,
    seek: usize,
}

// TODO: implement fflush
// TODO: rename functions or call it directly from C

#[no_mangle]
pub unsafe extern "C" fn fopen_wrap(
    pathname: *const c_char,
    _mode: *const c_char,
) -> *mut FileWrapper {
    if pathname.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        // TODO: implement a map for filenames
        match CStr::from_ptr(pathname).to_str() {
            Ok(pathname) => {
                if pathname != "NVChip" {
                    return ptr::null_mut();
                }
            }
            Err(_) => return ptr::null_mut(),
        }

        let layout = match layout_from_size(core::mem::size_of::<FileWrapper>()) {
            Ok(layout) => layout,
            Err(_) => return ptr::null_mut(),
        };

        let file: *mut FileWrapper = alloc(layout).cast();

        (*file) = FileWrapper {
            bf: BlockFile::new(0, 32 * 1024),
            seek: 0,
        };

        file
    }
}

#[no_mangle]
pub extern "C" fn fclose_wrap(file: *mut FileWrapper) -> c_int {
    if file.is_null() {
        return -1;
    }
    let ptr = file as *mut u8;
    if let Some(layout) = layout_from_ptr(ptr) {
        unsafe { dealloc(ptr, layout) }
    }
    0
}

#[no_mangle]
pub extern "C" fn ftell_wrap(file: *mut FileWrapper) -> c_long {
    unsafe { (*file).seek.try_into().unwrap() }
}

#[no_mangle]
pub extern "C" fn fseek_wrap(file: *mut FileWrapper, offset: c_long, whence: c_int) -> c_int {
    let safe_file = unsafe { &mut *file };

    let new_seek: i64 = match whence {
        // SEEK_SET
        0 => offset,
        // SEEK_CUR
        1 => {
            let cur: i64 = safe_file.seek.try_into().unwrap();
            cur + offset
        }
        // SEEK_END
        2 => {
            let end: i64 = safe_file.bf.size().try_into().unwrap();
            end + offset
        }
        _ => return -1,
    };

    if new_seek < 0 {
        return -1;
    }

    safe_file.seek = new_seek.try_into().unwrap();

    0
}

// core::ffi::c_size_t is unstable for now
#[allow(non_camel_case_types)]
pub type c_size_t = usize;

#[no_mangle]
pub extern "C" fn fwrite_wrap(
    ptr: *const c_void,
    size: c_size_t,
    nmeb: c_size_t,
    file: *mut FileWrapper,
) -> c_size_t {
    let safe_file = unsafe { &mut *file };
    let buf = unsafe { slice::from_raw_parts(ptr as *const u8, size * nmeb) };

    match safe_file.bf.write(buf, safe_file.seek) {
        Ok(written) => {
            safe_file.seek += written;
            written / size
        }
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn fread_wrap(
    ptr: *mut c_void,
    size: c_size_t,
    nmeb: c_size_t,
    file: *mut FileWrapper,
) -> c_size_t {
    let safe_file = unsafe { &mut *file };
    let buf = unsafe { slice::from_raw_parts_mut(ptr as *mut u8, size * nmeb) };

    match safe_file.bf.read(buf, safe_file.seek) {
        Ok(read) => {
            safe_file.seek += read;
            read / size
        }
        Err(_) => 0,
    }
}
