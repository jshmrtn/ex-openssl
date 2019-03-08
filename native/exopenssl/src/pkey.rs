use openssl::pkey::PKey;
use rustler::{Env, Term, NifResult, Encoder};
use rustler::resource::ResourceArc;
use crate::errors::to_term as error_stack_to_term;

mod atoms {
    rustler::rustler_atoms! {
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

pub fn pem_read<'a>(env: Env<'a>, args: &[Term<'a>]) -> NifResult<Term<'a>> {
    let pem: String = args[0].decode()?;

    match PKey::private_key_from_pem(pem.as_bytes()) {
        Ok(pkey) => {
            Ok((atoms::ok(), key_to_resource(pkey)).encode(env))
        },
        Err(errors) =>
            Ok((atoms::error(), error_stack_to_term(errors, env)).encode(env))
    }
}
