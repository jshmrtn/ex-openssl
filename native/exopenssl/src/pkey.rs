use openssl::pkey::PKey;
use rustler::{NifEnv, NifTerm, NifResult, NifEncoder};
use rustler::resource::ResourceArc;
use errors::to_term as error_stack_to_term;

mod atoms {
    rustler_atoms! {
        atom ok;
        atom error;
    }
}

pub struct PKeyResource {
    pub key: PKey,
}
unsafe impl Send for PKeyResource {}
unsafe impl Sync for PKeyResource {}


fn key_to_resource(key: PKey) -> ResourceArc<PKeyResource> {
    ResourceArc::new(PKeyResource {
        key: key
    })
}

pub fn pem_read<'a>(env: NifEnv<'a>, args: &[NifTerm<'a>]) -> NifResult<NifTerm<'a>> {
    let pem: String = try!(args[0].decode());

    match PKey::private_key_from_pem(pem.as_bytes()) {
        Ok(pkey) => {
            Ok((atoms::ok(), key_to_resource(pkey)).encode(env))
        },
        Err(errors) =>
            Ok((atoms::error(), error_stack_to_term(errors, env)).encode(env))
    }
}
