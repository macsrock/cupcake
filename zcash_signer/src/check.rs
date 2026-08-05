//! The check layer: semantic validation the upstream Signer role explicitly
//! does NOT perform. Modeled on Keystone's firmware policy:
//!
//! - Every transparent input must be a P2PKH coin owned by this seed, with a
//!   BIP-44 derivation that re-derives to the input's script.
//! - Every Orchard/Ironwood spend is verified against the account FVK
//!   (nullifier, randomized verification key), and every action's note
//!   commitment and value commitment are recomputed from the claimed values.
//! - Any spend carrying a `dummy_sk` is rejected (ZIP 374 signer rule).
//! - Sapling bundles are rejected entirely (no Sapling signing support).
//! - Outputs are classified as verified change or external; a `user_address`
//!   is only displayed if it provably contains the raw recipient.

use bip32::ChildNumber;
use orchard::keys::FullViewingKey;
use pczt::roles::verifier::{OrchardError, TransparentError, Verifier};
use pczt::Pczt;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use transparent::address::TransparentAddress;
use transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};
use zcash_address::unified::{self, Container, Encoding};
use zcash_address::{ToAddress, ZcashAddress};
use zip32::fingerprint::SeedFingerprint;

use crate::keys::{usk_from_seed, Network};
use crate::summary::{OutputSummary, Pool, SpendSummary, Summary};

/// What the signer will sign, discovered during checking.
#[derive(Debug, Default)]
pub struct ToSign {
    /// (input index, key scope, address index) for each transparent input.
    pub transparent: Vec<(usize, TransparentKeyScope, NonHardenedChildIndex)>,
    /// Unsigned Orchard action indices owned by this account.
    pub orchard: Vec<usize>,
    /// Unsigned Ironwood action indices owned by this account.
    pub ironwood: Vec<usize>,
}

/// A fully checked PCZT plus everything derived while checking it.
pub struct Checked {
    pub pczt: Pczt,
    pub summary: Summary,
    pub to_sign: ToSign,
}

/// Errors from the check layer. Strings carry context for the UI/log.
#[derive(Debug)]
pub enum CheckError {
    Parse(String),
    Keys(crate::Error),
    Transparent(String),
    Orchard(String),
    Ironwood(String),
    /// The PCZT contains a Sapling bundle; this signer does not support Sapling.
    SaplingUnsupported,
    /// Value balance is inconsistent or the fee is negative.
    ValueBalance(String),
    /// Nothing in this PCZT is signable by this account.
    NothingToSign,
}

impl core::fmt::Display for CheckError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CheckError::Parse(e) => write!(f, "PCZT parse error: {e}"),
            CheckError::Keys(e) => write!(f, "key derivation error: {e}"),
            CheckError::Transparent(e) => write!(f, "transparent check failed: {e}"),
            CheckError::Orchard(e) => write!(f, "orchard check failed: {e}"),
            CheckError::Ironwood(e) => write!(f, "ironwood check failed: {e}"),
            CheckError::SaplingUnsupported => write!(f, "sapling bundles are not supported"),
            CheckError::ValueBalance(e) => write!(f, "value balance check failed: {e}"),
            CheckError::NothingToSign => write!(f, "nothing to sign for this account"),
        }
    }
}

impl std::error::Error for CheckError {}

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&Ripemd160::digest(sha));
    out
}

/// Parses and fully checks `pczt_bytes` against this seed + account.
///
/// This is the only path to a signable PCZT: `sign_pczt` re-runs it on the
/// exact bytes it is given, so nothing can be signed that was not checked.
pub fn check_pczt(
    pczt_bytes: &[u8],
    seed: &[u8],
    account: u32,
    network: Network,
) -> Result<Checked, CheckError> {
    let pczt = Pczt::parse(pczt_bytes).map_err(|e| CheckError::Parse(format!("{e:?}")))?;

    let seed_fp =
        SeedFingerprint::from_seed(seed).ok_or(CheckError::Keys(crate::Error::InvalidSeed))?;
    let usk = usk_from_seed(seed, account, network).map_err(CheckError::Keys)?;
    let fvk = FullViewingKey::from(usk.orchard());
    let coin_type = ChildNumber(network.coin_type() | ChildNumber::HARDENED_FLAG);
    let secp = secp256k1::Secp256k1::new();

    // Reject Sapling entirely (no Sapling signing; keeps the attack surface
    // and the UI honest). Zashi's Orchard/Ironwood flows never include one.
    if !(pczt.sapling().spends().is_empty() && pczt.sapling().outputs().is_empty()) {
        return Err(CheckError::SaplingUnsupported);
    }

    let expiry_height = *pczt.global().expiry_height();

    let mut to_sign = ToSign::default();
    let mut spends: Vec<SpendSummary> = Vec::new();
    let mut outputs: Vec<OutputSummary> = Vec::new();
    let mut transparent_in: u64 = 0;
    let mut transparent_out: u64 = 0;
    // Net value leaving each shielded pool, as verified against per-action values.
    let mut orchard_balance: i128 = 0;
    let mut ironwood_balance: i128 = 0;

    let verifier = Verifier::new(pczt);

    // --- Transparent bundle ---
    let verifier = {
        let to_sign = &mut to_sign;
        let spends = &mut spends;
        let outputs = &mut outputs;
        let transparent_in = &mut transparent_in;
        let transparent_out = &mut transparent_out;
        verifier
            .with_transparent::<String, _>(|bundle| {
                let fail = |msg: String| TransparentError::Custom(msg);

                for (index, input) in bundle.inputs().iter().enumerate() {
                    input
                        .verify()
                        .map_err(|e| fail(format!("input {index}: {e:?}")))?;

                    // P2PKH only, mirroring Keystone.
                    let addr_hash =
                        match TransparentAddress::from_script_from_chain(input.script_pubkey()) {
                            Some(TransparentAddress::PublicKeyHash(h)) => h,
                            _ => {
                                return Err(fail(format!(
                                    "input {index}: only P2PKH inputs are supported"
                                )))
                            }
                        };

                    // The input must be ours: some derivation entry must match
                    // our seed fingerprint, re-derive to the claimed pubkey,
                    // and that pubkey must hash to the script.
                    let mut matched = None;
                    for (pubkey, derivation) in input.bip32_derivation() {
                        if let Some((path_account, scope, address_index)) =
                            derivation.extract_bip_44_fields(&seed_fp, coin_type)
                        {
                            if u32::from(path_account) != account {
                                return Err(fail(format!(
                                    "input {index}: derivation is for another account"
                                )));
                            }
                            let sk = usk
                                .transparent()
                                .derive_secret_key(scope, address_index)
                                .map_err(|e| fail(format!("input {index}: {e:?}")))?;
                            let derived =
                                secp256k1::PublicKey::from_secret_key(&secp, &sk).serialize();
                            if &derived != pubkey {
                                return Err(fail(format!(
                                    "input {index}: claimed pubkey does not match derivation"
                                )));
                            }
                            if hash160(&derived) != addr_hash {
                                return Err(fail(format!(
                                    "input {index}: pubkey does not hash to script"
                                )));
                            }
                            matched = Some((scope, address_index));
                            break;
                        }
                    }
                    let (scope, address_index) = matched.ok_or_else(|| {
                        fail(format!(
                            "input {index}: no derivation entry for this seed/account"
                        ))
                    })?;

                    let value = input.value().into_u64();
                    *transparent_in += value;
                    spends.push(SpendSummary {
                        pool: Pool::Transparent,
                        value,
                    });
                    to_sign.transparent.push((index, scope, address_index));
                }

                for (index, output) in bundle.outputs().iter().enumerate() {
                    output
                        .verify()
                        .map_err(|e| fail(format!("output {index}: {e:?}")))?;

                    let addr_hash =
                        match TransparentAddress::from_script_pubkey(output.script_pubkey()) {
                            Some(TransparentAddress::PublicKeyHash(h)) => h,
                            _ => {
                                return Err(fail(format!(
                                    "output {index}: only P2PKH outputs are supported"
                                )))
                            }
                        };

                    // Change iff a derivation entry proves the script is ours.
                    let mut is_change = false;
                    for (pubkey, derivation) in output.bip32_derivation() {
                        if let Some((path_account, scope, address_index)) =
                            derivation.extract_bip_44_fields(&seed_fp, coin_type)
                        {
                            if u32::from(path_account) != account {
                                continue;
                            }
                            let sk = usk
                                .transparent()
                                .derive_secret_key(scope, address_index)
                                .map_err(|e| fail(format!("output {index}: {e:?}")))?;
                            let derived =
                                secp256k1::PublicKey::from_secret_key(&secp, &sk).serialize();
                            // A derivation entry that does not re-derive is a lie.
                            if &derived != pubkey || hash160(&derived) != addr_hash {
                                return Err(fail(format!(
                                    "output {index}: change derivation does not match script"
                                )));
                            }
                            is_change = true;
                            break;
                        }
                    }

                    let canonical =
                        ZcashAddress::from_transparent_p2pkh(network.network_type(), addr_hash)
                            .encode();

                    let address = match output.user_address() {
                        Some(user_address) => {
                            verify_transparent_user_address(
                                user_address,
                                &addr_hash,
                                network,
                                index,
                            )
                            .map_err(fail)?;
                            user_address.clone()
                        }
                        None => canonical,
                    };

                    let value = output.value().into_u64();
                    *transparent_out += value;
                    outputs.push(OutputSummary {
                        pool: Pool::Transparent,
                        address,
                        value,
                        is_change,
                    });
                }

                Ok(())
            })
            .map_err(|e| match e {
                TransparentError::Custom(msg) => CheckError::Transparent(msg),
                other => CheckError::Transparent(format!("{other:?}")),
            })?
    };

    // --- Orchard + Ironwood bundles (same policy, different pool) ---
    let mut check_pool = |bundle: &orchard::pczt::Bundle,
                          pool: Pool,
                          signable: &mut Vec<usize>,
                          balance_out: &mut i128,
                          spends: &mut Vec<SpendSummary>,
                          outputs: &mut Vec<OutputSummary>|
     -> Result<(), String> {
        bundle
            .verify_cross_address_restriction()
            .map_err(|e| format!("cross-address restriction: {e:?}"))?;

        let mut balance: i128 = 0;

        for (index, action) in bundle.actions().iter().enumerate() {
            let spend = action.spend();
            let output = action.output();

            // ZIP 374: Signers MUST reject PCZTs that contain dummy_sk.
            if spend.dummy_sk().is_some() {
                return Err(format!("action {index}: dummy_sk present"));
            }

            action
                .verify_cv_net()
                .map_err(|e| format!("action {index} cv_net: {e:?}"))?;
            spend
                .verify_nullifier(Some(&fvk))
                .map_err(|e| format!("action {index} nullifier: {e:?}"))?;
            spend
                .verify_rk(Some(&fvk))
                .map_err(|e| format!("action {index} rk: {e:?}"))?;
            output
                .verify_note_commitment(spend)
                .map_err(|e| format!("action {index} note commitment: {e:?}"))?;

            let spend_value = spend
                .value()
                .ok_or_else(|| format!("action {index}: spend value redacted"))?
                .inner();
            let output_value = output
                .value()
                .ok_or_else(|| format!("action {index}: output value redacted"))?
                .inner();
            balance += i128::from(spend_value) - i128::from(output_value);

            // Ownership: fvk field equal to ours, or absent (in which case the
            // nullifier/rk verifications above used ours and passed).
            let ours = match spend.fvk() {
                Some(f) => f == &fvk,
                None => true,
            };

            if spend.spend_auth_sig().is_none() {
                if !ours {
                    return Err(format!(
                        "action {index}: unsigned spend not owned by this account"
                    ));
                }
                if spend_value > 0 {
                    spends.push(SpendSummary {
                        pool,
                        value: spend_value,
                    });
                }
                signable.push(index);
            }

            // Output classification.
            let recipient = output
                .recipient()
                .ok_or_else(|| format!("action {index}: output recipient redacted"))?;
            let is_change = fvk.scope_for_address(&recipient).is_some();

            if output_value > 0 || is_change {
                let address = match output.user_address() {
                    Some(user_address) => {
                        verify_shielded_user_address(user_address, &recipient, index)?;
                        user_address.clone()
                    }
                    None => unified_address_for(&recipient, network)
                        .map_err(|e| format!("action {index}: {e}"))?,
                };
                outputs.push(OutputSummary {
                    pool,
                    address,
                    value: output_value,
                    is_change,
                });
            }
            // Zero-value non-change outputs are dummies; verified above,
            // hidden from display.
        }

        // The claimed bundle balance must match the per-action values.
        let claimed = i128::from(
            i64::try_from(*bundle.value_sum()).map_err(|_| "value_sum out of range".to_string())?,
        );
        if claimed != balance {
            return Err(format!(
                "value_sum {claimed} does not match action values {balance}"
            ));
        }

        *balance_out = balance;
        Ok(())
    };

    let verifier = verifier
        .with_orchard::<String, _>(|bundle| {
            check_pool(
                bundle,
                Pool::Orchard,
                &mut to_sign.orchard,
                &mut orchard_balance,
                &mut spends,
                &mut outputs,
            )
            .map_err(OrchardError::Custom)
        })
        .map_err(|e| CheckError::Orchard(format!("{e:?}")))?;

    let verifier = verifier
        .with_ironwood::<String, _>(|bundle| {
            check_pool(
                bundle,
                Pool::Ironwood,
                &mut to_sign.ironwood,
                &mut ironwood_balance,
                &mut spends,
                &mut outputs,
            )
            .map_err(OrchardError::Custom)
        })
        .map_err(|e| CheckError::Ironwood(format!("{e:?}")))?;

    let pczt = verifier.finish();

    // Positive shielded balance = net value leaving that pool into the
    // transaction value pool; the fee is whatever no output claims.
    let fee = i128::from(transparent_in) - i128::from(transparent_out)
        + orchard_balance
        + ironwood_balance;

    if fee < 0 {
        return Err(CheckError::ValueBalance(format!(
            "negative fee: {fee} zatoshis"
        )));
    }

    if to_sign.transparent.is_empty() && to_sign.orchard.is_empty() && to_sign.ironwood.is_empty()
    {
        return Err(CheckError::NothingToSign);
    }

    let total_out = outputs
        .iter()
        .filter(|o| !o.is_change)
        .map(|o| o.value)
        .sum();
    let total_change = outputs
        .iter()
        .filter(|o| o.is_change)
        .map(|o| o.value)
        .sum();

    let summary = Summary {
        network: match network {
            Network::Main => "main".into(),
            Network::Test => "test".into(),
        },
        spends,
        outputs,
        total_out,
        total_change,
        fee: u64::try_from(fee)
            .map_err(|_| CheckError::ValueBalance("fee out of range".into()))?,
        expiry_height,
    };

    Ok(Checked {
        pczt,
        summary,
        to_sign,
    })
}

/// Encodes an Orchard receiver as an Orchard-only unified address.
fn unified_address_for(recipient: &orchard::Address, network: Network) -> Result<String, String> {
    let receiver = unified::Receiver::Orchard(recipient.to_raw_address_bytes());
    let ua = unified::Address::try_from_items(vec![receiver])
        .map_err(|e| format!("cannot encode recipient: {e:?}"))?;
    Ok(ua.encode(&network.network_type()))
}

/// A shielded output's `user_address` must contain the raw Orchard recipient.
fn verify_shielded_user_address(
    user_address: &str,
    recipient: &orchard::Address,
    index: usize,
) -> Result<(), String> {
    let (_, ua) = unified::Address::decode(user_address)
        .map_err(|e| format!("action {index}: bad user_address: {e:?}"))?;
    let raw = recipient.to_raw_address_bytes();
    let contains = ua.items().iter().any(|item| match item {
        unified::Receiver::Orchard(bytes) => bytes == &raw,
        _ => false,
    });
    if contains {
        Ok(())
    } else {
        Err(format!(
            "action {index}: user_address does not contain the recipient"
        ))
    }
}

/// A transparent output's `user_address` must resolve to the same P2PKH hash:
/// as a canonical transparent address, a ZIP 320 TEX address, or a unified
/// address carrying the matching P2PKH receiver.
fn verify_transparent_user_address(
    user_address: &str,
    addr_hash: &[u8; 20],
    network: Network,
    index: usize,
) -> Result<(), String> {
    let net = network.network_type();
    let p2pkh = ZcashAddress::from_transparent_p2pkh(net, *addr_hash).encode();
    let tex = ZcashAddress::from_tex(net, *addr_hash).encode();
    if user_address == p2pkh || user_address == tex {
        return Ok(());
    }
    if let Ok((_, ua)) = unified::Address::decode(user_address) {
        if ua.items().iter().any(|item| match item {
            unified::Receiver::P2pkh(hash) => hash == addr_hash,
            _ => false,
        }) {
            return Ok(());
        }
    }
    Err(format!(
        "output {index}: user_address does not match the output script"
    ))
}
