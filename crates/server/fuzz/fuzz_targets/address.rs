//! Fuzz target for the BDK Bitcoin address parser, exercising the same
//! `BitcoinAddress::from_str` + `require_network` chain that
//! `parse_destination_address` runs on user-supplied gRPC input.
//!
//! Usage:
//!   cargo +nightly fuzz run address
//!   cargo +nightly fuzz run address -- -max_total_time=60

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::str::FromStr;

use bdk_wallet::bitcoin::{Address as BitcoinAddress, Network};

fuzz_target!(|data: &[u8]| {
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };
    if let Ok(unchecked) = BitcoinAddress::from_str(s) {
        // require_network is exercised separately for every network so
        // wrong-network failures are also kept on the panic-free path.
        for net in [Network::Bitcoin, Network::Testnet, Network::Signet, Network::Regtest] {
            let _ = unchecked.clone().require_network(net);
        }
    }
});
