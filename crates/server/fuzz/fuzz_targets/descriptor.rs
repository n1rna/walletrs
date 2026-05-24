//! Fuzz target for `LianaDescriptor::from_str`, the parser invoked by
//! `load_policy_descriptor` against descriptor strings read from storage.
//! A panic here would crash any RPC that loads a Timelocked-Policy
//! wallet.
//!
//! Usage:
//!   cargo +nightly fuzz run descriptor
//!   cargo +nightly fuzz run descriptor -- -max_total_time=60

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::str::FromStr;

use walletrs::LianaDescriptor;

fuzz_target!(|data: &[u8]| {
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = LianaDescriptor::from_str(s);
});
