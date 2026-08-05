//! Airgapped Zcash PCZT signer for Cupcake.
//!
//! Mirrors the Keystone hardware-wallet policy:
//! - Transparent (P2PKH) inputs: checked against the claimed BIP-44 derivation, signed.
//! - Orchard / Ironwood spends: checked against the account FVK (nullifier, rk,
//!   note commitment), signed with the ZIP-32 spend authorizing key.
//! - Sapling: display only; spends are never signed.
//! - The device never computes zk-proofs; proving happens on the hot wallet.

pub mod check;
pub mod keys;
pub mod sign;
pub mod summary;

pub use check::{check_pczt, CheckError, Checked};
pub use keys::Network;
pub use sign::{sign_pczt, SignError};

/// Errors surfaced across the signer.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidSeed,
    InvalidAccount,
    InvalidUfvk,
    KeyDerivation,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidSeed => write!(f, "invalid seed (must be 32-252 bytes)"),
            Error::InvalidAccount => write!(f, "invalid ZIP-32 account index"),
            Error::InvalidUfvk => write!(f, "invalid unified full viewing key"),
            Error::KeyDerivation => write!(f, "key derivation failed"),
        }
    }
}

impl std::error::Error for Error {}
