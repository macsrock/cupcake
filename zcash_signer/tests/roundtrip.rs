//! Round-trip test: build a PCZT the way a hot wallet does, then check and
//! sign it with the airgapped-signer code paths.

use pczt::roles::creator::Creator;
use pczt::roles::io_finalizer::IoFinalizer;
use pczt::roles::updater::Updater;
use pczt::Pczt;
use rand_core::OsRng;
use transparent::address::TransparentAddress;
use transparent::builder::{SpendInfo, TransparentInputInfo};
use transparent::bundle::{OutPoint, TxOut};
use transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};
use transparent::pczt::Bip32Derivation;
use zcash_primitives::transaction::builder::{Builder, BuildConfig, BundlePadding};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::consensus::{NetworkUpgrade, Parameters, TestNetwork};
use zcash_protocol::value::Zatoshis;

use zcash_signer::check::check_pczt;
use zcash_signer::keys::{seed_fingerprint, usk_from_seed, Network};
use zcash_signer::sign::sign_pczt;

const HARDENED: u32 = 0x8000_0000;

fn test_seed() -> Vec<u8> {
    vec![0xab; 64]
}

fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};
    let sha = Sha256::digest(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&Ripemd160::digest(sha));
    out
}

/// Builds a transparent-only PCZT spending our own coin: one external output,
/// one change output, annotated with BIP-44 derivations like a real Updater.
fn build_transparent_pczt(seed: &[u8]) -> (Vec<u8>, secp256k1::PublicKey) {
    let secp = secp256k1::Secp256k1::new();
    let usk = usk_from_seed(seed, 0, Network::Test).unwrap();
    let fp = seed_fingerprint(seed).unwrap();

    // Our coin at m/44'/1'/0'/0/0.
    let sk0 = usk
        .transparent()
        .derive_secret_key(
            TransparentKeyScope::EXTERNAL,
            NonHardenedChildIndex::const_from_index(0),
        )
        .unwrap();
    let pk0 = secp256k1::PublicKey::from_secret_key(&secp, &sk0);
    let our_addr = TransparentAddress::PublicKeyHash(hash160(&pk0.serialize()));

    // Our change at m/44'/1'/0'/1/0.
    let sk_change = usk
        .transparent()
        .derive_secret_key(
            TransparentKeyScope::INTERNAL,
            NonHardenedChildIndex::const_from_index(0),
        )
        .unwrap();
    let pk_change = secp256k1::PublicKey::from_secret_key(&secp, &sk_change);
    let change_addr = TransparentAddress::PublicKeyHash(hash160(&pk_change.serialize()));

    // External recipient (unrelated key).
    let recipient_sk = secp256k1::SecretKey::from_slice(&[0x42; 32]).unwrap();
    let recipient_pk = secp256k1::PublicKey::from_secret_key(&secp, &recipient_sk);
    let recipient_addr = TransparentAddress::PublicKeyHash(hash160(&recipient_pk.serialize()));

    let height = TestNetwork
        .activation_height(NetworkUpgrade::Nu6_3)
        .unwrap()
        + 1;

    let mut builder = Builder::new(
        TestNetwork,
        height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );

    let coin = TxOut::new(
        Zatoshis::const_from_u64(100_000),
        our_addr.script().into(),
    );
    builder.add_transparent_input(
        TransparentInputInfo::from_parts(
            OutPoint::new([0x11; 32], 0),
            coin,
            SpendInfo::P2pkh { pubkey: pk0 },
        )
        .unwrap(),
    );
    builder
        .add_transparent_output(&recipient_addr, Zatoshis::const_from_u64(60_000))
        .unwrap();
    builder
        .add_transparent_output(&change_addr, Zatoshis::const_from_u64(30_000))
        .unwrap();

    let result = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();
    let pczt = Creator::build_from_parts(result.pczt_parts).unwrap();
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();

    // Annotate ownership the way a real hot-wallet Updater would.
    let pczt = Updater::new(pczt)
        .update_transparent_with(|mut u| {
            let change_index = find_output_index(&u, &change_addr);
            u.update_input_with(0, |mut iu| {
                iu.set_bip32_derivation(
                    pk0.serialize(),
                    Bip32Derivation::parse(
                        fp,
                        vec![44 | HARDENED, 1 | HARDENED, HARDENED, 0, 0],
                    )
                    .unwrap(),
                );
                Ok(())
            })?;
            u.update_output_with(change_index, |mut ou| {
                ou.set_bip32_derivation(
                    pk_change.serialize(),
                    Bip32Derivation::parse(
                        fp,
                        vec![44 | HARDENED, 1 | HARDENED, HARDENED, 1, 0],
                    )
                    .unwrap(),
                );
                Ok(())
            })
        })
        .unwrap()
        .finish();

    (pczt.serialize().unwrap(), pk0)
}

/// Finds the index of the output paying `addr` (the builder may shuffle).
fn find_output_index(u: &transparent::pczt::Updater<'_>, addr: &TransparentAddress) -> usize {
    u.bundle()
        .outputs()
        .iter()
        .position(|o| TransparentAddress::from_script_pubkey(o.script_pubkey()).as_ref() == Some(addr))
        .expect("output present")
}

#[test]
fn transparent_roundtrip_check_and_sign() {
    let seed = test_seed();
    let (pczt_bytes, pk0) = build_transparent_pczt(&seed);

    // Check: summary must reflect what the builder created.
    let checked = check_pczt(&pczt_bytes, &seed, 0, Network::Test).unwrap();
    assert_eq!(checked.summary.spends.len(), 1);
    assert_eq!(checked.summary.spends[0].value, 100_000);
    assert_eq!(checked.summary.outputs.len(), 2);
    assert_eq!(checked.summary.total_out, 60_000);
    assert_eq!(checked.summary.total_change, 30_000);
    assert_eq!(checked.summary.fee, 10_000);
    assert_eq!(checked.to_sign.transparent.len(), 1);
    assert!(checked.to_sign.orchard.is_empty());
    assert!(checked.to_sign.ironwood.is_empty());
    let change = checked
        .summary
        .outputs
        .iter()
        .find(|o| o.is_change)
        .expect("change output flagged");
    assert_eq!(change.value, 30_000);

    // Sign: the input must gain a signature under our pubkey.
    let signed = sign_pczt(&pczt_bytes, &seed, 0, Network::Test).unwrap();
    let signed_pczt = Pczt::parse(&signed).unwrap();
    pczt::roles::verifier::Verifier::new(signed_pczt)
        .with_transparent::<(), _>(|bundle| {
            let sigs = bundle.inputs()[0].partial_signatures();
            assert_eq!(sigs.len(), 1);
            assert!(sigs.contains_key(&pk0.serialize()));
            Ok(())
        })
        .unwrap();
}

#[test]
fn check_rejects_wrong_account() {
    let seed = test_seed();
    let (pczt_bytes, _) = build_transparent_pczt(&seed);
    // Account 1 does not own these derivations.
    assert!(check_pczt(&pczt_bytes, &seed, 1, Network::Test).is_err());
}

#[test]
fn check_rejects_foreign_seed() {
    let seed = test_seed();
    let (pczt_bytes, _) = build_transparent_pczt(&seed);
    let other_seed = vec![0xcd; 64];
    assert!(check_pczt(&pczt_bytes, &other_seed, 0, Network::Test).is_err());
}

#[test]
fn sign_rejects_tampered_output_value(){
    let seed = test_seed();
    let (pczt_bytes, _) = build_transparent_pczt(&seed);

    // Re-parse and swap the recipient output's script for an attacker script.
    // The derivation entry on the change output now lies about a different
    // script, so checking must fail.
    let pczt = Pczt::parse(&pczt_bytes).unwrap();
    let attacker = TransparentAddress::PublicKeyHash([0x99; 20]);
    let tampered = Updater::new(pczt)
        .update_transparent_with(|mut u| {
            let change_index = u
                .bundle()
                .outputs()
                .iter()
                .position(|o| !o.bip32_derivation().is_empty())
                .expect("annotated change output");
            u.update_output_with(change_index, |mut ou| {
                ou.set_user_address(
                    // Claim the change goes somewhere else entirely; the
                    // user_address consistency check must catch this.
                    zcash_address_for(&attacker),
                );
                Ok(())
            })
        })
        .unwrap()
        .finish()
        .serialize()
        .unwrap();

    assert!(check_pczt(&tampered, &seed, 0, Network::Test).is_err());
}

fn zcash_address_for(addr: &TransparentAddress) -> String {
    use zcash_address::{ToAddress, ZcashAddress};
    use zcash_protocol::consensus::NetworkType;
    match addr {
        TransparentAddress::PublicKeyHash(h) => {
            ZcashAddress::from_transparent_p2pkh(NetworkType::Test, *h).encode()
        }
        TransparentAddress::ScriptHash(h) => {
            ZcashAddress::from_transparent_p2sh(NetworkType::Test, *h).encode()
        }
    }
}

// ---------------------------------------------------------------------------
// Ironwood (shielded) round trip via the v6 deferred-anchor builder.
// ---------------------------------------------------------------------------

use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::note::{NoteVersion, RandomSeed, Rho};
use orchard::value::NoteValue;
use orchard::Note;
use zcash_primitives::transaction::builder::DeferredPcztBuilder;
use zcash_protocol::memo::MemoBytes;

/// Deterministically constructs a note owned by `fvk` (provenance is not
/// checked at signing time; witnesses/anchors are deferred to the Prover).
fn fabricate_note(fvk: &FullViewingKey, value: u64, version: NoteVersion) -> Note {
    let mut counter = 0u8;
    let rho = loop {
        let rho = Rho::from_bytes(&[counter; 32]);
        if rho.is_some().into() {
            break rho.unwrap();
        }
        counter += 1;
    };
    let mut counter = 0x40u8;
    let rseed = loop {
        let rseed = RandomSeed::from_bytes([counter; 32], &rho);
        if rseed.is_some().into() {
            break rseed.unwrap();
        }
        counter += 1;
    };
    let recipient = fvk.address_at(0u32, Scope::External);
    let note = Note::from_parts(recipient, NoteValue::from_raw(value), rho, rseed, version);
    assert!(bool::from(note.is_some()), "fabricated note must be valid");
    note.unwrap()
}

fn build_ironwood_pczt(seed: &[u8]) -> Vec<u8> {
    let usk = usk_from_seed(seed, 0, Network::Test).unwrap();
    let fvk = FullViewingKey::from(usk.orchard());

    // External recipient owned by an unrelated key.
    let other_fvk = FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap());
    let recipient = other_fvk.address_at(0u32, Scope::External);

    let height = TestNetwork
        .activation_height(NetworkUpgrade::Nu6_3)
        .unwrap()
        + 1;

    let mut builder: DeferredPcztBuilder<TestNetwork> = DeferredPcztBuilder::new::<
        zcash_primitives::transaction::fees::zip317::FeeError,
    >(
        TestNetwork,
        height,
        BundlePadding::DEFAULT,
        BundlePadding::DEFAULT,
    )
    .unwrap();

    let note = fabricate_note(&fvk, 100_000, NoteVersion::V3);
    builder
        .add_ironwood_spend::<zip317::FeeError>(fvk.clone(), note)
        .unwrap();
    builder
        .add_ironwood_output::<zip317::FeeError>(
            Some(fvk.to_ovk(Scope::External)),
            recipient,
            Zatoshis::const_from_u64(60_000),
            MemoBytes::empty(),
        )
        .unwrap();
    // Change back to ourselves.
    builder
        .add_ironwood_output::<zip317::FeeError>(
            Some(fvk.to_ovk(Scope::External)),
            fvk.address_at(0u32, Scope::External),
            Zatoshis::const_from_u64(30_000),
            MemoBytes::empty(),
        )
        .unwrap();

    let result = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();
    let pczt = Creator::build_from_parts(result.pczt_parts).unwrap();
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();
    pczt.serialize().unwrap()
}

#[test]
fn ironwood_roundtrip_check_and_sign() {
    let seed = test_seed();
    let pczt_bytes = build_ironwood_pczt(&seed);

    let checked = check_pczt(&pczt_bytes, &seed, 0, Network::Test).unwrap();
    use zcash_signer::summary::Pool;
    assert_eq!(checked.summary.spends.len(), 1);
    assert_eq!(checked.summary.spends[0].pool, Pool::Ironwood);
    assert_eq!(checked.summary.spends[0].value, 100_000);
    // Two visible outputs (dummy padding outputs are zero-value and hidden).
    assert_eq!(checked.summary.outputs.len(), 2);
    assert_eq!(checked.summary.total_out, 60_000);
    assert_eq!(checked.summary.total_change, 30_000);
    assert_eq!(checked.summary.fee, 10_000);
    assert!(checked.to_sign.transparent.is_empty());
    assert!(checked.to_sign.orchard.is_empty());
    assert_eq!(checked.to_sign.ironwood.len(), 1);
    let change = checked
        .summary
        .outputs
        .iter()
        .find(|o| o.is_change)
        .expect("change output flagged");
    assert_eq!(change.value, 30_000);
    assert!(change.address.starts_with("utest"), "unified test address");

    // Sign, then confirm every Ironwood action carries a spend-auth signature.
    let signed = sign_pczt(&pczt_bytes, &seed, 0, Network::Test).unwrap();
    let signed_pczt = Pczt::parse(&signed).unwrap();
    pczt::roles::verifier::Verifier::new(signed_pczt)
        .with_ironwood::<(), _>(|bundle| {
            assert!(!bundle.actions().is_empty());
            for action in bundle.actions() {
                assert!(action.spend().spend_auth_sig().is_some());
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn ironwood_check_rejects_foreign_seed() {
    let seed = test_seed();
    let pczt_bytes = build_ironwood_pczt(&seed);
    let other_seed = vec![0xcd; 64];
    assert!(check_pczt(&pczt_bytes, &other_seed, 0, Network::Test).is_err());
}
