# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Liana is a Bitcoin wallet development kit written in Rust, focusing on inheritance and recovery wallet functionality with Miniscript descriptors. The project implements a sophisticated Bitcoin wallet system with primary and recovery spending paths, supporting both P2WSH and Taproot transactions.

## Development Commands

### Build and Test
- `cargo build` - Build the project
- `cargo test` - Run all tests
- `cargo check` - Quick syntax and type checking
- `cargo clippy` - Run linter for code quality checks
- `cargo fmt` - Format code according to Rust standards

### Development Workflow
- Tests are included within each module using `#[cfg(test)]`
- Use `cargo test <module_name>` to run specific module tests
- All tests require Rust's standard test harness

## Architecture

### Core Modules

**`src/lib.rs`** - Main library entry point exposing public modules

**`src/descriptors/`** - Core wallet descriptor functionality
- Implements Liana descriptors with primary and recovery spending paths
- Supports both legacy (P2WSH) and Taproot descriptor types
- Handles derivation of addresses for receive and change keychains
- Key components: `LianaDescriptor`, `SinglePathLianaDesc`, policy analysis

**`src/signer.rs`** - Hot signer implementation
- BIP39 mnemonic-based signing using 12-word mnemonics
- Supports both P2WSH (ECDSA) and Taproot (Schnorr) signatures
- Secure mnemonic storage with proper file permissions (Unix: 0o400)
- Master key derivation and hierarchical deterministic wallet support

**`src/spend.rs`** - Transaction creation and coin selection
- Advanced coin selection algorithms using `bdk_coin_select`
- PSBT (Partially Signed Bitcoin Transaction) creation and management
- Fee calculation with anti-fee-sniping locktime implementation
- Support for RBF (Replace-By-Fee) transactions
- Dust output prevention (minimum 5,000 sats)

**`src/random.rs`** - Cryptographically secure randomness
- Multi-source entropy: OS randomness, CPU RDRAND, contextual data
- SHA256-based entropy mixing for additional security
- Cross-platform support (Linux, Windows, macOS)

## Key Dependencies

- `miniscript` v12.0 - Bitcoin Miniscript support with descriptor handling
- `bdk_coin_select` v0.4 - Coin selection algorithms
- `bip39` v2.0 - BIP39 mnemonic generation and validation
- `serde` v1.0 - Serialization/deserialization
- `getrandom` v0.2 - Cross-platform secure random number generation

## Important Constants and Limits

- `DUST_OUTPUT_SATS`: 5,000 (minimum output value)
- `MAX_FEE`: 1 BTC (sanity check for maximum fee)
- `MAX_FEERATE`: 1,000 sats/vb (maximum feerate)
- `LONG_TERM_FEERATE_VB`: 10.0 sats/vb (for coin selection)

## Security Considerations

- Mnemonic files are stored with restricted permissions (0o400 on Unix)
- Multi-source entropy collection for secure key generation
- Comprehensive PSBT sanity checks before transaction creation
- Hardware randomness integration when available (RDRAND)

## Descriptor Format

Liana uses custom descriptor formats supporting:
- Primary spending paths (immediate access)
- Time-locked recovery paths (heir/inheritance functionality)
- Multi-signature configurations
- Both P2WSH (legacy) and Taproot spending methods

## Testing

The codebase includes comprehensive unit tests covering:
- Signer functionality (mnemonic generation, PSBT signing)
- Descriptor derivation and validation
- Transaction creation and fee calculation
- Randomness quality and distribution
- Anti-fee-sniping locktime logic

Tests use deterministic scenarios with known test vectors where possible and include both positive and negative test cases.