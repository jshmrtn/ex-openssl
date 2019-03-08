pub mod crypto;
mod errors;
mod symm;
pub mod pkey;

use rustler::{Env, Term};

rustler::rustler_export_nifs! {
    "Elixir.ExOpenssl.Nif",
    [
        ("pem_read_x509", 1, crypto::x509::pem_read),
        ("pem_read_private_key", 1, pkey::pem_read),
        ("pkcs7_encrypt", 4, crypto::pkcs7::encrypt),
        ("pkcs7_decrypt", 3, crypto::pkcs7::decrypt),
        ("pkcs7_sign", 5, crypto::pkcs7::sign),
        ("pkcs7_verify", 5, crypto::pkcs7::verify),
        ("smime_write_pkcs7", 3, crypto::pkcs7::smime::write),
        ("smime_read_pkcs7", 1, crypto::pkcs7::smime::read),
    ],
    Some(on_load)
}

fn on_load(env: Env, _load_info: Term) -> bool {
    rustler::resource_struct_init!(crypto::x509::X509Resource, env);
    rustler::resource_struct_init!(pkey::PKeyResource, env);
    rustler::resource_struct_init!(crypto::pkcs7::PKCS7Resource, env);
    true
}
