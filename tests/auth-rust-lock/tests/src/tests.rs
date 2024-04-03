use super::*;
use ckb_auth_rs::{AuthAlgorithmIdType, CkbAuthType, EntryCategoryType};
use ckb_testtool::{
    ckb_crypto::secp::{Generator, Privkey},
    ckb_hash::{blake2b_256, new_blake2b},
    ckb_types::{
        bytes::{BufMut, Bytes, BytesMut},
        core::{Capacity, DepType, ScriptHashType, TransactionBuilder, TransactionView},
        packed::{CellDep, CellInputBuilder, CellOutput, WitnessArgs, WitnessArgsBuilder},
        prelude::*,
        H256,
    },
    context::Context,
};
use rand::{thread_rng, Rng};
use std::mem::size_of;

const MAX_CYCLES: u64 = 10_000_000_000;

#[derive(Clone)]
struct CKbAuth {
    privkey: Privkey,
}
impl CKbAuth {
    fn new() -> Self {
        Self {
            privkey: Generator::random_privkey(),
        }
    }

    fn get_pubkey_hash(&self) -> [u8; 20] {
        let pub_key = self.privkey.pubkey().expect("pubkey").serialize();
        let pub_hash = blake2b_256(pub_key.as_slice());
        pub_hash[0..20].try_into().unwrap()
    }

    fn get_auth_args(&self, entry_category_type: &EntryCategoryType) -> Bytes {
        struct EntryType {
            _code_hash: [u8; 20],
            _hash_type: u8,
            _entry_category: u8,
        }
        let mut bytes = BytesMut::with_capacity(size_of::<CkbAuthType>() + size_of::<EntryType>());

        let ckb_auth_type = CkbAuthType {
            algorithm_id: AuthAlgorithmIdType::Ckb,
            pubkey_hash: self.get_pubkey_hash(),
        };
        bytes.put_u8(ckb_auth_type.algorithm_id.into());
        bytes.put(Bytes::from(ckb_auth_type.pubkey_hash.to_vec()));

        bytes.put(CellOutput::calc_data_hash(&Loader::default().load_auth()).as_bytes());
        bytes.put_u8(ScriptHashType::Data1.into());
        bytes.put_u8(entry_category_type.clone() as u8);

        bytes.freeze()
    }

    fn sign(&self, msg: &[u8; 32]) -> Bytes {
        // convert message
        let msg = H256::from(msg.clone());

        let sig = self
            .privkey
            .sign_recoverable(&msg)
            .expect("sign")
            .serialize();
        Bytes::from(sig)
    }
    fn sign_size(&self) -> usize {
        // The fixed length of ckb signature is 65
        65
    }
}

fn gen_tx(ctx: &mut Context, grouped_args: Vec<(Bytes, usize)>) -> TransactionView {
    let mut rng = thread_rng();
    let loader = Loader::default();

    let auth_demo_outpoint = ctx.deploy_cell(loader.load_demo());
    let sighash_dl_out_point = ctx.deploy_cell(loader.load_auth());
    let secp256k1_data_out_point = ctx.deploy_cell(loader.load_secp256k1_data());

    // setup default tx builder
    let dummy_capacity = Capacity::shannons(42);
    let mut tx_builder = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(sighash_dl_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(secp256k1_data_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .build(),
        )
        .output_data(Bytes::new().pack());

    for (args, inputs_size) in grouped_args {
        // setup dummy input unlock script
        for _ in 0..inputs_size {
            let script = ctx
                .build_script(&auth_demo_outpoint, args.clone())
                .expect("generate lock script");
            let previous_output_cell = CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .lock(script)
                .build();
            let input_cell = CellInputBuilder::default()
                .previous_output(ctx.create_cell(previous_output_cell, Bytes::default()))
                .build();

            let mut random_extra_witness = [0u8; 64];
            rng.fill(&mut random_extra_witness);

            let witness_args = WitnessArgsBuilder::default()
                .input_type(Some(Bytes::from(random_extra_witness.to_vec())).pack())
                .build();
            tx_builder = tx_builder
                .input(input_cell)
                .witness(witness_args.as_bytes().pack());
        }
    }

    ctx.complete_tx(tx_builder.build())
}

fn sign_tx(tx: TransactionView, auth: &CKbAuth) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    let begin_index = 0;
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<ckb_testtool::ckb_types::packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == begin_index {
                let mut blake2b = new_blake2b();
                let mut message = [0u8; 32];
                blake2b.update(&tx_hash.raw_data());
                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(auth.sign_size(), 0);
                    buf.into()
                };
                let witness_for_digest = witness
                    .clone()
                    .as_builder()
                    .lock(Some(zero_lock).pack())
                    .build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                blake2b.update(&witness_len.to_le_bytes());
                blake2b.update(&witness_for_digest.as_bytes());
                ((i + 1)..(i + witnesses_len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    blake2b.update(&witness_len.to_le_bytes());
                    blake2b.update(&witness.raw_data());
                });
                blake2b.finalize(&mut message);
                let sig;
                sig = auth.sign(&message);

                witness
                    .as_builder()
                    .lock(Some(sig).pack())
                    .build()
                    .as_bytes()
                    .pack()
            } else {
                tx.witnesses().get(i).unwrap_or_default()
            }
        })
        .collect();
    for i in signed_witnesses.len()..tx.witnesses().len() {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

const CKB_SIGN_GROUP_SIZE: usize = 1;

#[test]
fn test_exec() {
    let auth = CKbAuth::new();

    let mut ctx = Context::default();
    let tx = gen_tx(
        &mut ctx,
        vec![(
            auth.get_auth_args(&EntryCategoryType::Exec),
            CKB_SIGN_GROUP_SIZE,
        )],
    );
    let tx = sign_tx(tx, &auth);

    ctx.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
}

#[test]
#[cfg(feature = "enable-dynamic-library")]
fn test_dll() {
    let auth = CKbAuth::new();
    let mut ctx = Context::default();

    let tx = gen_tx(
        &mut ctx,
        vec![(
            auth.get_auth_args(&EntryCategoryType::DynamicLibrary),
            CKB_SIGN_GROUP_SIZE,
        )],
    );
    let tx = sign_tx(tx, &auth);

    ctx.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
}

#[test]
#[cfg(feature = "ckb2023")]
fn test_spawn() {
    let auth = CKbAuth::new();

    let mut ctx = Context::default();
    let tx = gen_tx(
        &mut ctx,
        vec![(
            auth.get_auth_args(&EntryCategoryType::Spawn),
            CKB_SIGN_GROUP_SIZE,
        )],
    );
    let tx = sign_tx(tx, &auth);

    ctx.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
}
