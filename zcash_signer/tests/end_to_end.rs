//! Full airgapped round trip against the upstream PCZT roles — the dialect
//! Keystone firmware and Zashi speak.
//!
//! Hot wallet builds (anchors deferred, per ZIP 374) -> airgapped device
//! checks and signs -> hot wallet installs the anchor and witnesses, proves,
//! finalizes spends, and extracts a broadcastable transaction.
//!
//! This is the test that proves the signer's output is actually completable
//! by a standards-compliant hot wallet; everything else only exercises one
//! half of the seam. Proving is slow, so run it in release.

use orchard::circuit::ProvingKey;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use orchard::value::NoteValue;
use orchard::Note;
use pczt::roles::creator::Creator;
use pczt::roles::io_finalizer::IoFinalizer;
use pczt::roles::prover::Prover;
use pczt::roles::spend_finalizer::SpendFinalizer;
use pczt::roles::tx_extractor::TransactionExtractor;
use pczt::roles::updater::Updater;
use pczt::Pczt;
use rand_core::OsRng;
use zcash_primitives::transaction::builder::{BundlePadding, DeferredPcztBuilder};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::consensus::{NetworkUpgrade, Parameters, TestNetwork};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

use zcash_signer::check::check_pczt;
use zcash_signer::keys::{usk_from_seed, Network};
use zcash_signer::sign::sign_pczt;

const MERKLE_DEPTH: usize = 32;

fn test_seed() -> Vec<u8> {
    vec![0xab; 64]
}

fn fabricate_note(fvk: &FullViewingKey, value: u64) -> Note {
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
    Note::from_parts(
        fvk.address_at(0u32, Scope::External),
        NoteValue::from_raw(value),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .unwrap()
}

/// A self-consistent witness: an arbitrary authentication path, plus the
/// anchor it roots to. Enough to satisfy the circuit, which only checks that
/// the path and anchor agree (chain membership is a consensus concern).
fn witness_for(note: &Note) -> (MerklePath, orchard::Anchor) {
    let cmx = ExtractedNoteCommitment::from(note.commitment());
    let filler = MerkleHashOrchard::from_cmx(&cmx);
    let auth_path: [MerkleHashOrchard; MERKLE_DEPTH] = core::array::from_fn(|_| filler);
    let path = MerklePath::from_parts(0, auth_path);
    let anchor = path.root(cmx);
    (path, anchor)
}

#[test]
fn ironwood_sign_prove_extract() {
    let seed = test_seed();
    let usk = usk_from_seed(&seed, 0, Network::Test).unwrap();
    let fvk = FullViewingKey::from(usk.orchard());
    let other = FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap());

    let height = TestNetwork
        .activation_height(NetworkUpgrade::Nu6_3)
        .unwrap()
        + 1;

    // --- Hot wallet: build with the anchor deferred (ZIP 374) ---
    let mut builder: DeferredPcztBuilder<TestNetwork> =
        DeferredPcztBuilder::new::<zip317::FeeError>(
            TestNetwork,
            height,
            BundlePadding::DEFAULT,
            BundlePadding::DEFAULT,
        )
        .unwrap();

    let note = fabricate_note(&fvk, 100_000);
    builder
        .add_ironwood_spend::<zip317::FeeError>(fvk.clone(), note)
        .unwrap();
    builder
        .add_ironwood_output::<zip317::FeeError>(
            Some(fvk.to_ovk(Scope::External)),
            other.address_at(0u32, Scope::External),
            Zatoshis::const_from_u64(60_000),
            MemoBytes::empty(),
        )
        .unwrap();
    builder
        .add_ironwood_output::<zip317::FeeError>(
            Some(fvk.to_ovk(Scope::External)),
            fvk.address_at(0u32, Scope::External),
            Zatoshis::const_from_u64(30_000),
            MemoBytes::empty(),
        )
        .unwrap();

    let built = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();
    let pczt = Creator::build_from_parts(built.pczt_parts).unwrap();
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();
    let unsigned = pczt.serialize().unwrap();

    // --- Airgapped device: check, show, sign. No proving here. ---
    let checked = check_pczt(&unsigned, &seed, 0, Network::Test).unwrap();
    assert_eq!(checked.summary.total_out, 60_000);
    assert_eq!(checked.summary.total_change, 30_000);
    assert_eq!(checked.summary.fee, 10_000);
    let signed_bytes = sign_pczt(&unsigned, &seed, 0, Network::Test).unwrap();

    // --- Hot wallet: install anchor + witnesses, prove, finalize, extract ---
    let signed = Pczt::parse(&signed_bytes).expect("signed PCZT parses");
    let (path, anchor) = witness_for(&note);

    let pczt = Updater::new(signed)
        .set_ironwood_anchor(anchor)
        .unwrap()
        .set_ironwood_spend_witnesses([(0usize, path)])
        .unwrap()
        .finish();

    let pk = ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let pczt = Prover::new(pczt)
        .create_ironwood_proof(&pk)
        .expect("ironwood proving succeeds over the device's signatures")
        .finish();

    let pczt = SpendFinalizer::new(pczt)
        .finalize_spends()
        .expect("spends finalize");

    let tx = TransactionExtractor::new(pczt)
        .extract()
        .expect("a complete, broadcastable transaction");

    // The extractor verifies proofs and signatures, so reaching here means the
    // device's signatures are valid over the transaction the hot wallet built.
    let bundle = tx.ironwood_bundle().expect("ironwood bundle present");
    assert!(!bundle.actions().is_empty());
    // Value left the Ironwood pool to cover the external output and the fee.
    assert!(i64::from(*bundle.value_balance()) > 0);
}
