use rustler::{Env, Term, NifResult, Encoder, Error};
use openssl::crypto::pkcs7::pk7_smime::PKCS7;
use crate::errors::to_term as error_stack_to_term;
use crate::crypto::pkcs7::pkcs7_to_resource;
use rustler::resource::ResourceArc;
use crate::crypto::pkcs7::PKCS7Resource;
use crate::crypto::pkcs7::decode_flags;
use rustler::types::atom::Atom;
use openssl::crypto::pkcs7::pk7_smime::PKCS7Flags;
use std::ops::Deref;

mod atoms {
    rustler::rustler_atoms! {
        atom ok;
        atom error;
    }
}

pub fn read<'a>(env: Env<'a>, args: &[Term<'a>]) -> NifResult<Term<'a>> {
    let data: String = args[0].decode()?;
    let mut bcount: Vec<u8> = Vec::new();

    match PKCS7::smime_read(data.as_bytes(), &mut bcount) {
        Ok(pkcs7) => Ok((atoms::ok(), (pkcs7_to_resource(pkcs7), bcount)).encode(env)),
        Err(errors) => Ok((atoms::error(), error_stack_to_term(errors, env)).encode(env))
    }
}

pub fn write<'a>(env: Env<'a>, args: &[Term<'a>]) -> NifResult<Term<'a>> {
    let pkcs7_arc: ResourceArc<PKCS7Resource> = args[0].decode()?;
    let pkcs7 = &pkcs7_arc.deref().pkcs7;

    let data: String = args[1].decode()?;

    if args[2].decode::<Vec<Atom>>()?.len() < 1 {
        return Err(Error::BadArg);
    }

    let flags: PKCS7Flags = decode_flags(args[2].decode()?, env)?;

    match pkcs7.smime_write(data.as_bytes(), flags) {
        Ok(out) => {
            Ok((atoms::ok(), out).encode(env))
        },
        Err(errors) => Ok((atoms::error(), error_stack_to_term(errors, env)).encode(env))
    }
}
