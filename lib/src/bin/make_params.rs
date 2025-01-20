use coin_structure::transient_crypto::proofs::ParamsProver;
use std::{fs::File, io::BufReader};

pub fn main() {
    let kzg_path = concat!(env!("MIDNIGHT_LEDGER_STATIC_DIR"), "/kzg");
    let kzg_vp_path = concat!(env!("MIDNIGHT_LEDGER_STATIC_DIR"), "/kzg.vp");

    let pp = ParamsProver::read(BufReader::new(
        File::open(dbg!(kzg_path)).expect("kzg params not found"),
    ))
    .unwrap();

    // // TODO: not entirely sure this constant is for this
    // let pp = ParamsProver::gen(OsRng, VERIFIER_MAX_DEGREE);

    // pp.write(File::create("kzg").unwrap()).unwrap();

    let vp = pp.clone().as_verifier();

    vp.write(File::create(kzg_vp_path).unwrap()).unwrap();
}
