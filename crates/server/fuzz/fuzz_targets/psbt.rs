//! Fuzz target for the BDK PSBT parser.
//!
//! Walletrs's `parse_stored_psbt` and `Psbt::from_str(&req.signedpsbt)` paths
//! both feed untrusted bytes through `Psbt::from_str`. Crashes here would
//! become DoS-able gRPC handlers.
//!
//! Usage:
//!   cargo +nightly fuzz run psbt
//!   cargo +nightly fuzz run psbt -- -max_total_time=60

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::str::FromStr;

use bdk_wallet::bitcoin::Psbt;

fuzz_target!(|data: &[u8]| {
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = Psbt::from_str(s);
});
