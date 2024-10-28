use std::fs::File;

use midnight_base_crypto::proofs::ParamsProver;
use rand::rngs::OsRng;

pub fn main() {
    let pp = ParamsProver::gen(OsRng, 10);

    pp.write(File::create("kzg").unwrap()).unwrap();

    let vp = pp.clone().as_verifier();

    vp.write(File::create("kzg.vp").unwrap()).unwrap();
}
