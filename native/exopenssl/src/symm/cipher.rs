use openssl::symm::Cipher;
use rustler::types::atom::Atom;
use rustler::{NifResult, Env, Error};

// mod atoms {
//     rustler::rustler_atoms! {
//         atom des_ede3_cbc;
//     }
// }

pub fn decode_cypher(cipher: Atom, env: Env) -> NifResult<Cipher> {
    let cypher: String = cipher.to_term(env).atom_to_string()?;

    match cypher.as_str() {
        "des_ede3_cbc" => Ok(Cipher::des_ede3_cbc()),
         _ => Err(Error::BadArg)
    }
}
