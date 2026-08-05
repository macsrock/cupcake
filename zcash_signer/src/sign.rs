//! Signing: re-checks the exact bytes, then adds signatures.
//!
//! Transparent inputs get ECDSA signatures with per-input BIP-44 keys;
//! Orchard/Ironwood spends get RedPallas spend-auth signatures over the
//! shielded sighash with the account's ZIP-32 spend authorizing key.
//! Proving is never done here — that is the hot wallet's job.

use orchard::keys::SpendAuthorizingKey;
use pczt::roles::signer::Signer;

use crate::check::{check_pczt, CheckError};
use crate::keys::{usk_from_seed, Network};

/// Errors from signing.
#[derive(Debug)]
pub enum SignError {
    Check(CheckError),
    Keys(crate::Error),
    Signer(String),
}

impl core::fmt::Display for SignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SignError::Check(e) => write!(f, "{e}"),
            SignError::Keys(e) => write!(f, "{e}"),
            SignError::Signer(e) => write!(f, "signing failed: {e}"),
        }
    }
}

impl std::error::Error for SignError {}

impl From<CheckError> for SignError {
    fn from(e: CheckError) -> Self {
        SignError::Check(e)
    }
}

/// Fully checks `pczt_bytes` and signs everything this seed owns.
///
/// Returns the serialized signed PCZT for the hot wallet to combine,
/// prove, extract, and broadcast.
pub fn sign_pczt(
    pczt_bytes: &[u8],
    seed: &[u8],
    account: u32,
    network: Network,
) -> Result<Vec<u8>, SignError> {
    // The check is the sole gate to signing: nothing that was not just
    // verified against this seed can reach the Signer below.
    let checked = check_pczt(pczt_bytes, seed, account, network)?;

    let usk = usk_from_seed(seed, account, network).map_err(SignError::Keys)?;
    let ask = SpendAuthorizingKey::from(usk.orchard());

    let mut signer =
        Signer::new(checked.pczt).map_err(|e| SignError::Signer(format!("{e:?}")))?;

    for (index, scope, address_index) in &checked.to_sign.transparent {
        let sk = usk
            .transparent()
            .derive_secret_key(*scope, *address_index)
            .map_err(|e| SignError::Signer(format!("input {index}: {e:?}")))?;
        signer
            .sign_transparent(*index, &sk)
            .map_err(|e| SignError::Signer(format!("input {index}: {e:?}")))?;
    }

    for index in &checked.to_sign.orchard {
        signer
            .sign_orchard(*index, &ask)
            .map_err(|e| SignError::Signer(format!("orchard action {index}: {e:?}")))?;
    }

    for index in &checked.to_sign.ironwood {
        signer
            .sign_ironwood(*index, &ask)
            .map_err(|e| SignError::Signer(format!("ironwood action {index}: {e:?}")))?;
    }

    signer
        .finish()
        .serialize()
        .map_err(|e| SignError::Signer(format!("serialize: {e:?}")))
}
