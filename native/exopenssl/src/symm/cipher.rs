use openssl::symm::Cipher;
use rustler::types::atom::NifAtom;
use rustler::{NifResult, NifEnv, NifError};

// mod atoms {
//     rustler_atoms! {
//         atom des_ede3_cbc;
//     }
// }

pub fn decode_cypher(cipher: NifAtom, env: NifEnv) -> NifResult<Cipher> {
    let cypher: String = cipher.to_term(env).atom_to_string()?;

    match cypher.as_str() {
        "des_ede3_cbc" => Ok(Cipher::des_ede3_cbc()),
         _ => Err(NifError::BadArg)
    }
}
