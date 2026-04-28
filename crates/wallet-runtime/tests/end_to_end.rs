//! Acceptance test for the wallet-runtime crate.
//!
//! Drives the full pipeline end to end with an in-memory persister:
//! generate a singlesig hot wallet, persist its initial state, peek a
//! receive address, hand-craft a PSBT spending a synthetic UTXO at that
//! address, and sign it via the runtime's signer helper. Asserts the input
//! has a partial signature after `sign_psbt`.

use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use bdk_wallet::bitcoin::psbt::Input as PsbtInput;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::transaction::Version;
use bdk_wallet::bitcoin::{
    absolute, Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use bdk_wallet::{chain::Merge, ChangeSet, KeychainKind, WalletPersister};
use policy_core::KeyUtils;
use wallet_runtime::{
    add_xprv_signer, create_wallet, load_wallet, peek_address, sign_psbt, InMemoryPersister,
    SignerKind, WalletDescriptors,
};

#[test]
fn singlesig_create_peek_sign_roundtrip() {
    // 1. Generate a fresh BIP39 / BIP84 keyset on testnet, build the
    //    singlesig descriptors policy-core would emit for the corresponding
    //    WalletShape::SingleSig { kind: SegwitV0 }.
    let keyset = KeyUtils::generate_complete_key_set(Network::Testnet);
    let descriptors = WalletDescriptors::new(
        keyset.external_descriptor.clone(),
        keyset.internal_descriptor.clone(),
    );

    // 2. Spin up an in-memory persister and create the wallet through it.
    let mut persister = InMemoryPersister::new();
    let mut wallet =
        create_wallet(&mut persister, Network::Testnet, &descriptors).expect("create wallet");

    // 3. Peek the first receive address and assert it parses as bech32 testnet.
    let addr0 = peek_address(&wallet, KeychainKind::External, 0);
    let addr0_str = addr0.to_string();
    assert!(
        addr0_str.starts_with("tb1q"),
        "expected testnet bech32 v0 address, got {}",
        addr0_str
    );

    // 4. Round-trip the persister: copy the persisted ChangeSet to a fresh
    //    InMemoryPersister and re-load the wallet through it.
    let cs_snapshot: ChangeSet = persister.changeset().clone();
    let mut roundtrip_persister = InMemoryPersister::new();
    InMemoryPersister::persist(&mut roundtrip_persister, &cs_snapshot)
        .expect("seed roundtrip persister");
    let loaded = load_wallet(&mut roundtrip_persister, Network::Testnet)
        .expect("load_wallet result")
        .expect("loaded wallet present");
    let loaded_addr = peek_address(&loaded, KeychainKind::External, 0);
    assert_eq!(loaded_addr, addr0, "peek_address differs after persister round-trip");

    // 5. Hand-craft a PSBT that spends a synthetic UTXO sitting at the
    //    receive address. This bypasses BDK's tx_builder (which would
    //    require the wallet to actually have a synced UTXO graph) and
    //    exercises the signer's PSBT path directly.
    let funding_amount = Amount::from_sat(100_000);
    let funding_txout = TxOut {
        value: funding_amount,
        script_pubkey: addr0.script_pubkey(),
    };
    // Build a real funding transaction so we can reference it as
    // `non_witness_utxo`. BDK by default rejects PSBTs that only carry a
    // witness UTXO (CVE-2020-14199-style guard), and we'd rather provide the
    // full prev-tx than relax the SignOptions.
    let funding_tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![funding_txout.clone()],
    };
    let funding_outpoint = OutPoint {
        txid: funding_tx.compute_txid(),
        vout: 0,
    };

    // BIP-173 example testnet P2WPKH address — short bech32 (42 chars).
    let drain_to = bdk_wallet::bitcoin::Address::from_str("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
        .expect("valid drain address")
        .require_network(Network::Testnet)
        .expect("testnet network match");

    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: drain_to.script_pubkey(),
        }],
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("build psbt");

    // Populate the input so BDK has enough info to sign:
    //   - witness_utxo (segwit v0 sigs commit to amount+script)
    //   - bip32_derivation pointing to the wallet's external chain index 0
    //     so BDK's signer knows which derivation to use.
    let secp = Secp256k1::new();
    let account_xprv = keyset
        .xprv
        .derive_priv(
            &secp,
            &DerivationPath::from_str("m/84'/1'/0'").expect("valid path"),
        )
        .expect("derive account xprv");
    let address0_xprv = account_xprv
        .derive_priv(
            &secp,
            &DerivationPath::from_str("m/0/0").expect("valid path"),
        )
        .expect("derive address xprv");
    let address0_pubkey = address0_xprv.to_priv().public_key(&secp);
    let fingerprint: Fingerprint = keyset.xprv.fingerprint(&secp);
    let full_path = DerivationPath::from_str("m/84'/1'/0'/0/0")
        .expect("full path")
        .into_iter()
        .copied()
        .collect::<Vec<ChildNumber>>();

    let mut input = PsbtInput {
        witness_utxo: Some(funding_txout),
        non_witness_utxo: Some(funding_tx),
        ..PsbtInput::default()
    };
    input
        .bip32_derivation
        .insert(address0_pubkey.inner, (fingerprint, full_path.into()));
    psbt.inputs[0] = input;

    assert!(
        psbt.inputs[0].partial_sigs.is_empty(),
        "no signatures expected before sign step"
    );

    // 6. Register the segwit-v0 signer derived from the keyset on the wallet
    //    and call sign_psbt. BDK consults the wallet's registered signers,
    //    matches them against the PSBT input's bip32_derivation entries, and
    //    populates partial_sigs in-place.
    add_xprv_signer(
        &mut wallet,
        &account_xprv,
        KeychainKind::External,
        0,
        SignerKind::SegwitV0,
    )
    .expect("add signer");

    let signed_all = sign_psbt(&wallet, &mut psbt).expect("sign psbt");
    assert!(
        !psbt.inputs[0].partial_sigs.is_empty()
            || psbt.inputs[0].final_script_witness.is_some(),
        "PSBT input should carry a partial signature after sign_psbt; signed_all={}",
        signed_all
    );

    // Sanity-check the signature was produced by the expected pubkey.
    let signed_keys: Vec<_> = psbt.inputs[0].partial_sigs.keys().collect();
    if !signed_keys.is_empty() {
        assert_eq!(
            signed_keys.len(),
            1,
            "exactly one partial signature expected for a singlesig wallet"
        );
        assert_eq!(
            *signed_keys[0], address0_pubkey,
            "partial signature should be by the wallet's expected pubkey"
        );
    }

    // Re-merge the original snapshot so cs_snapshot's variable isn't dropped
    // unused by the optimizer (silences `unused_assignments` in dev builds).
    let mut sink = ChangeSet::default();
    sink.merge(cs_snapshot);
}
