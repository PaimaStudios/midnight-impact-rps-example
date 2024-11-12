use midnight_base_crypto::proofs::ProverKey;
use midnight_base_crypto::{
    proofs::{ParamsProver, VerifierKey},
    serialize::{deserialize, serialize, NetworkId},
};
use midnight_impact_rps_example::{make_add_commitments_circuit, make_openings_circuit};
use std::{fs::File, io::BufReader};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let kzg_path = concat!(env!("MIDNIGHT_LEDGER_STATIC_DIR"), "/kzg");

    let pp = ParamsProver::read(BufReader::new(File::open(kzg_path).expect(
        "kzg params not found, run: cargo run --bin make_params to generate new ones",
    )))
    .unwrap();

    let commit_ir = make_add_commitments_circuit();
    let open_ir = make_openings_circuit();

    keygen_for_ir(pp.clone(), commit_ir, "add_commitments").await;
    keygen_for_ir(pp, open_ir, "open_commitments").await;
}

async fn keygen_for_ir(
    mut pp: ParamsProver,
    ir: midnight_base_crypto::proofs::IrSource,
    name: &'static str,
) {
    pp = pp.downsize(ir.model(None).k());

    let pk_path = format!("{}/../wasm/pk_{}", env!("CARGO_MANIFEST_DIR"), name);
    let vk_path = format!("{}/../wasm/vk_{}", env!("CARGO_MANIFEST_DIR"), name);

    let (pk, vk) = ir.keygen(&pp).await.unwrap();

    {
        let mut pk_file = File::create(&pk_path).unwrap();
        let mut vk_file = File::create(&vk_path).unwrap();

        serialize(&pk, &mut pk_file, NetworkId::Undeployed).unwrap();
        serialize(&vk, &mut vk_file, NetworkId::Undeployed).unwrap();
    }

    let pk_read = File::open(&pk_path).unwrap();

    let deserialized_pk = deserialize::<ProverKey, _>(pk_read, NetworkId::Undeployed).unwrap();

    assert!(pk == deserialized_pk);

    let vk_read = File::open(&vk_path).unwrap();

    let deserialized_vk = deserialize::<VerifierKey, _>(vk_read, NetworkId::Undeployed).unwrap();

    assert!(vk == deserialized_vk);
}
