//! Prints a deterministic-seed test PCZT (testnet, Ironwood spend) as hex.
//!
//! Used to produce the fixture consumed by cupcake's Dart tests:
//!   cargo run --example gen_test_vector > ../test/data/ironwood_pczt.hex

use pczt::roles::creator::Creator;
use pczt::roles::io_finalizer::IoFinalizer;
use rand_core::OsRng;
use zcash_primitives::transaction::builder::{BundlePadding, DeferredPcztBuilder};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::consensus::{NetworkUpgrade, Parameters, TestNetwork};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::note::{NoteVersion, RandomSeed, Rho};
use orchard::value::NoteValue;
use orchard::Note;

use zcash_signer::keys::{usk_from_seed, Network};

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
    Note::from_parts(recipient, NoteValue::from_raw(value), rho, rseed, version).unwrap()
}

fn main() {
    let seed = vec![0xab; 64];
    let usk = usk_from_seed(&seed, 0, Network::Test).unwrap();
    let fvk = FullViewingKey::from(usk.orchard());

    let other_fvk = FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap());
    let recipient = other_fvk.address_at(0u32, Scope::External);

    let height = TestNetwork
        .activation_height(NetworkUpgrade::Nu6_3)
        .unwrap()
        + 1;

    let mut builder: DeferredPcztBuilder<TestNetwork> =
        DeferredPcztBuilder::new::<zip317::FeeError>(
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
    println!("{}", hex::encode(pczt.serialize().unwrap()));
}
