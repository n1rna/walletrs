//! Fuzz target for miniscript's `Concrete` policy parser. Walletrs's
//! policy pipeline ultimately routes through miniscript; making the
//! parser robust against arbitrary inputs is defensive against future
//! features that take user-supplied policy expressions.
//!
//! Usage:
//!   cargo +nightly fuzz run miniscript_policy
//!   cargo +nightly fuzz run miniscript_policy -- -max_total_time=60

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::str::FromStr;

use miniscript::descriptor::DescriptorPublicKey;
use miniscript::policy::Concrete;

fuzz_target!(|data: &[u8]| {
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = Concrete::<DescriptorPublicKey>::from_str(s);
});
