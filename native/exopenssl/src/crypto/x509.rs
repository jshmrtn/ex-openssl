use openssl::x509::X509;
use rustler::{Env, Term, NifResult, Encoder};
use rustler::resource::ResourceArc;
use crate::errors::to_term as error_stack_to_term;
use openssl::stack::Stack;
use openssl::error::ErrorStack;
use openssl::x509::store::X509Store;
use openssl::x509::store::X509StoreBuilder;

mod atoms {
    rustler::rustler_atoms! {
        atom ok;
        atom error;
    }
}

pub struct X509Resource {
    pub cert: X509,
}
unsafe impl Send for X509Resource {}
unsafe impl Sync for X509Resource {}


fn cert_to_resource(cert: &X509) -> ResourceArc<X509Resource> {
    ResourceArc::new(X509Resource {
        cert: cert.clone()
    })
}

pub fn pem_read<'a>(env: Env<'a>, args: &[Term<'a>]) -> NifResult<Term<'a>> {
    let pem: String = args[0].decode()?;

    match X509::stack_from_pem(pem.as_bytes()) {
        Ok(certs) => {
            let certs: Vec<ResourceArc<X509Resource>> = certs
                .iter()
                .map(| cert | cert_to_resource(cert))
                .collect();

            Ok((atoms::ok(), certs).encode(env))
        },
        Err(errors) =>
            Ok((atoms::error(), error_stack_to_term(errors, env)).encode(env))
    }
}

pub fn decode_stack(certs: Vec<ResourceArc<X509Resource>>) -> Result<Stack<X509>, ErrorStack> {
    certs
        .iter()
        .map(| ref cert_arc | &cert_arc.cert)
        .fold(Stack::new(), | stack, cert | {
            match stack {
                Ok(mut stack) => {
                    match stack.push(cert.clone()) {
                        Ok(_) => Ok(stack),
                        Err(err) => Err(err)
                    }
                },
                Err(err) => Err(err)
            }
        })
}

pub fn decode_store(certs: Vec<ResourceArc<X509Resource>>) -> Result<X509Store, ErrorStack> {
    Ok(
        certs
            .iter()
            .map(| ref cert_arc | &cert_arc.cert)
            .fold(X509StoreBuilder::new(), | stack, cert | {
                match stack {
                    Ok(mut stack) => {
                        match stack.add_cert(cert.clone()) {
                            Ok(_) => Ok(stack),
                            Err(err) => Err(err)
                        }
                    },
                    Err(err) => Err(err)
                }
            })?
            .build()
    )
}
