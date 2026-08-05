//! Key derivation for the airgapped signer: BIP-39 seed -> ZIP-32 unified keys.

use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_protocol::consensus::{MainNetwork, NetworkConstants, NetworkType, TestNetwork};
use zip32::fingerprint::SeedFingerprint;
use zip32::AccountId;

use crate::Error;

/// The network the signer is operating on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Main,
    Test,
}

impl Network {
    pub fn coin_type(self) -> u32 {
        match self {
            Network::Main => MainNetwork.coin_type(),
            Network::Test => TestNetwork.coin_type(),
        }
    }

    pub(crate) fn network_type(self) -> NetworkType {
        match self {
            Network::Main => NetworkType::Main,
            Network::Test => NetworkType::Test,
        }
    }
}

/// Computes the ZIP-32 seed fingerprint used to tie PCZT derivation entries to a seed.
pub fn seed_fingerprint(seed: &[u8]) -> Result<[u8; 32], Error> {
    SeedFingerprint::from_seed(seed)
        .map(|fp| fp.to_bytes())
        .ok_or(Error::InvalidSeed)
}

/// Derives the unified spending key for `account` from a BIP-39 seed.
pub fn usk_from_seed(
    seed: &[u8],
    account: u32,
    network: Network,
) -> Result<UnifiedSpendingKey, Error> {
    let account = AccountId::try_from(account).map_err(|_| Error::InvalidAccount)?;
    match network {
        Network::Main => UnifiedSpendingKey::from_seed(&MainNetwork, seed, account),
        Network::Test => UnifiedSpendingKey::from_seed(&TestNetwork, seed, account),
    }
    .map_err(|_| Error::KeyDerivation)
}

/// Derives the ZIP-316 encoded unified full viewing key for `account`.
pub fn ufvk_string(seed: &[u8], account: u32, network: Network) -> Result<String, Error> {
    let usk = usk_from_seed(seed, account, network)?;
    let ufvk = usk.to_unified_full_viewing_key();
    Ok(match network {
        Network::Main => ufvk.encode(&MainNetwork),
        Network::Test => ufvk.encode(&TestNetwork),
    })
}

/// Decodes a ZIP-316 encoded UFVK string.
pub fn decode_ufvk(ufvk: &str, network: Network) -> Result<UnifiedFullViewingKey, Error> {
    match network {
        Network::Main => UnifiedFullViewingKey::decode(&MainNetwork, ufvk),
        Network::Test => UnifiedFullViewingKey::decode(&TestNetwork, ufvk),
    }
    .map_err(|_| Error::InvalidUfvk)
}

/// Returns the default unified address for the account's UFVK.
pub fn default_address(ufvk: &UnifiedFullViewingKey, network: Network) -> Result<String, Error> {
    let (ua, _) = ufvk
        .default_address(UnifiedAddressRequest::AllAvailableKeys)
        .map_err(|_| Error::KeyDerivation)?;
    Ok(match network {
        Network::Main => ua.encode(&MainNetwork),
        Network::Test => ua.encode(&TestNetwork),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // 64-byte all-`0xab` test seed (never use a degenerate all-0x00/0xff seed:
    // SeedFingerprint rejects short seeds, and real wallets pass BIP-39 output).
    fn test_seed() -> Vec<u8> {
        vec![0xab; 64]
    }

    #[test]
    fn fingerprint_is_stable() {
        let fp1 = seed_fingerprint(&test_seed()).unwrap();
        let fp2 = seed_fingerprint(&test_seed()).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn rejects_short_seed() {
        assert!(seed_fingerprint(&[0xab; 16]).is_err());
    }

    #[test]
    fn derives_ufvk_and_address() {
        let ufvk_str = ufvk_string(&test_seed(), 0, Network::Main).unwrap();
        assert!(ufvk_str.starts_with("uview"));
        let ufvk = decode_ufvk(&ufvk_str, Network::Main).unwrap();
        let addr = default_address(&ufvk, Network::Main).unwrap();
        assert!(addr.starts_with('u'));
    }
}
