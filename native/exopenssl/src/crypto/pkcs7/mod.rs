#![allow(deprecated)]

pub mod smime;

use openssl::symm::Cipher;
use openssl::crypto::pkcs7::pk7_smime::PKCS7;
use rustler::{NifEnv, NifTerm, NifResult, NifEncoder, NifError};
use rustler::types::atom::NifAtom;
use symm::cipher::decode_cypher;
use crypto::x509::decode_stack;
use crypto::x509::decode_store;
use errors::to_term as error_stack_to_term;
use rustler::resource::ResourceArc;
use pkey::PKeyResource;
use openssl::pkey::PKey;
use crypto::x509::X509Resource;
use openssl::x509::X509;
use rustler::TermType;
use openssl::crypto::pkcs7::pk7_smime;
use openssl::crypto::pkcs7::pk7_smime::PKCS7Flags;
use std::ops::Deref;

mod atoms {
    rustler_atoms! {
        atom ok;
        atom error;
    }
}


pub struct PKCS7Resource {
    pub pkcs7: PKCS7,
}
unsafe impl Send for PKCS7Resource {}
unsafe impl Sync for PKCS7Resource {}

pub fn pkcs7_to_resource(pkcs7: PKCS7) -> ResourceArc<PKCS7Resource> {
    ResourceArc::new(PKCS7Resource {
        pkcs7: pkcs7,
    })
}

pub fn decode_flag(flag: &NifAtom, env: NifEnv) -> NifResult<PKCS7Flags> {
    let flag: String = flag.to_term(env).atom_to_string()?;

    match flag.as_str() {
        "text" => Ok(pk7_smime::PKCS7_TEXT),
        "nocerts" => Ok(pk7_smime::PKCS7_NOCERTS),
        "nosigs" => Ok(pk7_smime::PKCS7_NOSIGS),
        "nochain" => Ok(pk7_smime::PKCS7_NOCHAIN),
        "nointern" => Ok(pk7_smime::PKCS7_NOINTERN),
        "noverify" => Ok(pk7_smime::PKCS7_NOVERIFY),
        "detached" => Ok(pk7_smime::PKCS7_DETACHED),
        "binary" => Ok(pk7_smime::PKCS7_BINARY),
        "noattr" => Ok(pk7_smime::PKCS7_NOATTR),
        "nosmimecap" => Ok(pk7_smime::PKCS7_NOSMIMECAP),
        "nooldmimetype" => Ok(pk7_smime::PKCS7_NOOLDMIMETYPE),
        "crlfeol" => Ok(pk7_smime::PKCS7_CRLFEOL),
        "stream" => Ok(pk7_smime::PKCS7_STREAM),
        "nocrl" => Ok(pk7_smime::PKCS7_NOCRL),
        "partial" => Ok(pk7_smime::PKCS7_PARTIAL),
        "reuse_digest" => Ok(pk7_smime::PKCS7_REUSE_DIGEST),
        // "no_dual_content" => Ok(pk7_smime::PKCS7_NO_DUAL_CONTENT),
        _ => Err(NifError::BadArg)
    }
}

pub fn decode_flags(flags: Vec<NifAtom>, env: NifEnv) -> NifResult<PKCS7Flags> {
    flags
        .iter()
        .fold(Ok(PKCS7Flags::empty()), | acc, term | {
            match acc {
                Ok(flags) => Ok(flags | decode_flag(term, env)?),
                Err(err) => Err(err)
            }
        })
}

pub fn encrypt<'a>(env: NifEnv<'a>, args: &[NifTerm<'a>]) -> NifResult<NifTerm<'a>> {
    match decode_stack(args[0].decode()?) {
        Ok(certs) => {
            let input: String = args[1].decode()?;

            let cipher: Cipher = decode_cypher(args[2].decode()?, env)?;

            if args[3].decode::<Vec<NifAtom>>()?.len() < 1 {
                return Err(NifError::BadArg);
            }

            let flags: PKCS7Flags = decode_flags(args[3].decode()?, env)?;

            match PKCS7::encrypt(&certs, input.as_bytes(), cipher, flags) {
                Ok(pkcs7) => Ok((atoms::ok(), pkcs7_to_resource(pkcs7)).encode(env)),
                Err(errors) => Ok((atoms::error(), error_stack_to_term(errors, env)).encode(env))
            }
        },
        Err(errors) => Ok((atoms::error(), error_stack_to_term(errors, env)).encode(env))
    }
}

pub fn decrypt<'a>(env: NifEnv<'a>, args: &[NifTerm<'a>]) -> NifResult<NifTerm<'a>> {
    let pkcs7_arc: ResourceArc<PKCS7Resource> = args[0].decode()?;
    let pkcs7 = &pkcs7_arc.deref().pkcs7;

    let pkey_arc: ResourceArc<PKeyResource> = args[1].decode()?;
    let pkey: &PKey = &pkey_arc.key;

    let cert_arc: ResourceArc<X509Resource> = args[2].decode()?;
    let cert: &X509 = &cert_arc.cert;

    match PKCS7::decrypt(&pkcs7, pkey, cert) {
        Ok(decrypted) => {
            Ok((atoms::ok(), decrypted).encode(env))
        }
        Err(errors) => Ok((atoms::error(), error_stack_to_term(errors, env)).encode(env))
    }
}

pub fn sign<'a>(env: NifEnv<'a>, args: &[NifTerm<'a>]) -> NifResult<NifTerm<'a>> {
    let sign_cert_arc: ResourceArc<X509Resource> = args[0].decode()?;
    let sign_cert = &sign_cert_arc.cert;

    let pkey_arc: ResourceArc<PKeyResource> = args[1].decode()?;
    let pkey: &PKey = &pkey_arc.key;

    match decode_stack(args[2].decode()?) {
        Ok(certs) => {
            let input: String = args[3].decode()?;

            if args[4].decode::<Vec<NifAtom>>()?.len() < 1 {
                return Err(NifError::BadArg);
            }

            let flags: PKCS7Flags = decode_flags(args[4].decode()?, env)?;

            match PKCS7::sign(sign_cert, pkey, &certs, input.as_bytes(), flags) {
                Ok(pkcs7) => Ok((atoms::ok(), pkcs7_to_resource(pkcs7)).encode(env)),
                Err(errors) => Ok((atoms::error(), error_stack_to_term(errors, env)).encode(env))
            }
        },
        Err(errors) => Ok((atoms::error(), error_stack_to_term(errors, env)).encode(env))
    }
}

pub fn verify<'a>(env: NifEnv<'a>, args: &[NifTerm<'a>]) -> NifResult<NifTerm<'a>> {
    let pkcs7_arc: ResourceArc<PKCS7Resource> = args[0].decode()?;
    let pkcs7 = &pkcs7_arc.deref().pkcs7;

    if args[4].decode::<Vec<NifAtom>>()?.len() < 1 {
        return Err(NifError::BadArg);
    }

    let flags: PKCS7Flags = decode_flags(args[4].decode()?, env)?;

    let mut out: Vec<u8> = Vec::new();

    match decode_stack(args[1].decode()?) {
        Ok(certs) => {
            match decode_store(args[2].decode()?) {
                Ok(store) => {
                    let data_term: NifTerm = args[3].decode()?;

                    match data_term.get_type() {
                        TermType::Atom => {
                            match data_term.atom_to_string()?.as_str() {
                                "nil" => {
                                    match pkcs7.verify(&certs, &store, None, Some(&mut out), flags) {
                                        Ok(_) => Ok((atoms::ok(), (true, out)).encode(env)),
                                        Err(errors) => Ok((atoms::error(), error_stack_to_term(errors, env)).encode(env))
                                    }
                                }
                                _ => Err(NifError::BadArg)
                            }
                        },
                        TermType::Binary => {
                            let bcount: &[u8] = data_term.into_binary()?.as_slice();
                            match pkcs7.verify(&certs, &store, Some(bcount), Some(&mut out), flags) {
                                Ok(_) => Ok((atoms::ok(), (true, out)).encode(env)),
                                Err(errors) => Ok((atoms::error(), error_stack_to_term(errors, env)).encode(env))
                            }
                        },
                        _ => Err(NifError::BadArg)
                    }
                },
                Err(errors) => Ok((atoms::error(), error_stack_to_term(errors, env)).encode(env))
            }
        },
        Err(errors) => Ok((atoms::error(), error_stack_to_term(errors, env)).encode(env))
    }
}
