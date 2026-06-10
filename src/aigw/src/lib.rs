/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: rust to C wrapper for HuggingFace tokenizers API.
 * Create: 2025-06-18
 */

use std::ffi::{CStr, CString};
use std::ffi::c_char;
use std::ffi::c_void;
use std::path::PathBuf;
use std::ptr;
use tokenizers::tokenizer::Tokenizer;

#[repr(C)]
pub struct HgTokenIds {
    ids: *mut u32,
    len: usize
}

#[unsafe(no_mangle)]
pub extern "C" fn hg_tokenizers_new_from_file(file_path: *const c_char) -> *mut c_void {
    if file_path.is_null() {
        return ptr::null_mut();
    }

    let path_cstr = unsafe { CStr::from_ptr(file_path) };
    let path = match path_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let path = PathBuf::from(path);
    match Tokenizer::from_file(path) {
        Ok(tokenizer) => {
            let handler = Box::into_raw(Box::new(tokenizer));
            handler.cast()
        }
        Err(_) => {
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hg_tokenizers_free(hg_tokenizer_handler: *mut c_void) {
    if hg_tokenizer_handler.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(hg_tokenizer_handler.cast::<Tokenizer>()));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn hg_tokenizers_encode(
    hg_tokenizer_handler: *mut c_void,
    input: *const c_char,
    add_special_tokens: bool,
) -> *mut HgTokenIds {
    // Check if the input pointers are null
    if hg_tokenizer_handler.is_null() || input.is_null() {
        return ptr::null_mut();
    }

    let tokenizer: &Tokenizer;
    unsafe {
    // Cast the void pointer to a Tokenizer reference
        match hg_tokenizer_handler.cast::<Tokenizer>().as_ref() {
            Some(t) => tokenizer = t,
            None => return ptr::null_mut(),
        }
    }

    // Convert the C-style string to a Rust string
    let message_cstr = unsafe { CStr::from_ptr(input) };
    let message = message_cstr.to_str();
    // Return null if the string conversion fails
    if message.is_err() {
        return ptr::null_mut();
    }

    // Call the tokenizer's encode method
    let encoding = tokenizer.encode(message.unwrap(), add_special_tokens);
    // Return null if the encoding fails
    if encoding.is_err() {
        return ptr::null_mut();
    }

    // Convert the encoding result to a vector and optimize memory usage
    let mut vec_ids = encoding.unwrap().get_ids().to_vec();
    vec_ids.shrink_to_fit();
    let ids = vec_ids.as_mut_ptr();
    let len = vec_ids.len();
    // Forget the vector to prevent deallocation
    std::mem::forget(vec_ids);

    // Allocate memory for the HgTokenIds struct and return a raw pointer
    let result = Box::new(HgTokenIds { ids, len });
    Box::into_raw(result)
}

#[unsafe(no_mangle)]
pub extern "C" fn hg_tokenizers_free_token_ids(token_ids: *mut HgTokenIds) {
    // Check if the token_ids pointer is null
    if token_ids.is_null() {
        return;
    }

    // Take ownership of the HgTokenIds struct and free the memory
    let token_ids_box = unsafe { Box::from_raw(token_ids) };

    // If the ids pointer is not null, free the memory it points to
    if !token_ids_box.ids.is_null() {
        // Construct a Vec from the raw parts to free the memory
        unsafe {
            Vec::from_raw_parts(token_ids_box.ids, token_ids_box.len, token_ids_box.len);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hg_tokenizers_decode(
    hg_tokenizer_handler: *mut c_void,  // Pointer to the Tokenizer handler
    token_ids: &HgTokenIds,             // Reference to the HgTokenIds struct containing token IDs and length
    skip_special_tokens: bool,          // Flag indicating whether to skip special tokens
) -> *mut c_char {
    // Check if the input pointers are null
    if hg_tokenizer_handler.is_null() || token_ids.ids.is_null() {
        return ptr::null_mut();
    }

    let tokenizer: &Tokenizer;
    unsafe {
        // Cast the void pointer to a Tokenizer reference
        match hg_tokenizer_handler.cast::<Tokenizer>().as_ref() {
            Some(t) => tokenizer = t,
            None => return ptr::null_mut(),
        }
    }

    // Create a slice from the raw parts
    let ids = unsafe { std::slice::from_raw_parts(token_ids.ids, token_ids.len) };

    // Call the tokenizer's decode method
    let string = match tokenizer.decode(ids, skip_special_tokens) {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    // Convert the Rust String to a C string
    match CString::new(string) {
        Ok(c_string) => c_string.into_raw(),  // Return the raw pointer to the C string
        Err(_) => ptr::null_mut(),            // Return a null pointer if conversion fails
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hg_tokenizers_free_string(input: *mut c_char) {
    if input.is_null() {
        return;
    }
    unsafe {
        drop(std::ffi::CString::from_raw(input));
    }
}