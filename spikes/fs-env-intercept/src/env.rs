//! Environment variables.
//!
//! `std::env::var` reads the process environment without a syscall, so the values are applied at
//! case start on the fuzz thread. In thread mode this uses `std::env::set_var`, which is `unsafe`
//! in edition 2024 because other threads may be reading the environment concurrently; the
//! supervisor thread never touches the environment while a case runs, and harnesses are expected to
//! keep the target on the fuzz thread. The forked isolation mode applies the same choices with
//! `setenv` in the single-threaded child instead. Programs that read `/proc/self/environ` get a
//! virtual copy reflecting the applied values.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;

use crate::draw::Draw;
use crate::spec::Spec;

/// Draw one value per declared variable and apply it; returns what was applied.
pub fn apply(
    draw: &mut dyn Draw,
    spec: &Spec,
    saved: &mut Vec<(String, Option<OsString>)>,
) -> Vec<(String, Option<String>)> {
    let mut applied = Vec::new();
    for var in &spec.env {
        let (_, value) = crate::draw::pick(draw, &var.values);
        saved.push((var.name.clone(), std::env::var_os(&var.name)));
        // SAFETY: see module docs; only the fuzz thread reads the environment during a case.
        unsafe {
            match value {
                Some(value) => std::env::set_var(&var.name, value),
                None => std::env::remove_var(&var.name),
            }
        }
        applied.push((var.name.clone(), value.clone()));
    }
    applied
}

pub fn restore(saved: &mut Vec<(String, Option<OsString>)>) {
    for (name, value) in saved.drain(..).rev() {
        // SAFETY: see module docs.
        unsafe {
            match value {
                Some(value) => std::env::set_var(&name, value),
                None => std::env::remove_var(&name),
            }
        }
    }
}

/// `/proc/self/environ` contents for the current environment.
pub fn environ_blob() -> Vec<u8> {
    let mut blob = Vec::new();
    for (key, value) in std::env::vars_os() {
        blob.extend_from_slice(key.as_bytes());
        blob.push(b'=');
        blob.extend_from_slice(value.as_bytes());
        blob.push(0);
    }
    blob
}
