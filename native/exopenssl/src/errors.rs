use rustler::{Env, Term, Encoder};
use openssl::error::{Error, ErrorStack};
use rustler::types::atom::nil;
use rustler::types::elixir_struct;

mod atoms {
    rustler::rustler_atoms! {
        atom __exception__;
        atom code;
        atom file;
        atom line;
        atom data;
        atom library;
        atom function;
        atom reason;
    }
}

pub fn to_term<'a>(stack: ErrorStack, env: Env<'a>) -> Vec<Term<'a>> {
    stack.errors()
        .iter()
        .map(| error | error_to_struct(error, env))
        .collect()
}

fn error_to_struct<'a>(error: &Error, env: Env<'a>) -> Term<'a> {
    let exception_atom = atoms::__exception__().encode(env);
    let code_atom = atoms::code().encode(env);
    let file_atom = atoms::file().encode(env);
    let line_atom = atoms::line().encode(env);
    let data_atom = atoms::data().encode(env);
    let library_atom = atoms::library().encode(env);
    let function_atom = atoms::function().encode(env);
    let reason_atom = atoms::reason().encode(env);


    let reason = match error.reason() {
        Some(reason) => String::from(reason).encode(env),
        None => nil().encode(env)
    };
    let data = match error.data() {
        Some(data) => String::from(data).encode(env),
        None => nil().encode(env)
    };
    let library = match error.library() {
        Some(library) => String::from(library).encode(env),
        None => nil().encode(env)
    };
    let function = match error.function() {
        Some(function) => String::from(function).encode(env),
        None => nil().encode(env)
    };

    elixir_struct::make_ex_struct(env, "Elixir.ExOpenssl.Errors.Error").ok().unwrap()
        .map_put(exception_atom, true.encode(env)).ok().unwrap()
        .map_put(code_atom, error.code().encode(env)).ok().unwrap()
        .map_put(file_atom, error.file().encode(env)).ok().unwrap()
        .map_put(line_atom, error.line().encode(env)).ok().unwrap()
        .map_put(data_atom, data.encode(env)).ok().unwrap()
        .map_put(library_atom, library.encode(env)).ok().unwrap()
        .map_put(function_atom, function.encode(env)).ok().unwrap()
        .map_put(reason_atom, reason.encode(env)).ok().unwrap()
}
