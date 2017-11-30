# ExOpenssl

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/jshmrtn/ex-openssl/master/LICENSE)
[![Build Status](https://travis-ci.org/jshmrtn/ex-openssl.svg?branch=master)](https://travis-ci.org/jshmrtn/ex-openssl)
[![Hex.pm Version](https://img.shields.io/hexpm/v/ex_openssl.svg?style=flat)](https://hex.pm/packages/ex_openssl)
[![InchCI](https://inch-ci.org/github/jshmrtn/ex-openssl.svg?branch=master)](https://inch-ci.org/github/jshmrtn/ex-openssl)

## Installation

The package can be installed by adding `ex_openssl` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ex_openssl, "~> 0.1.0"}
  ]
end
```

The docs can be found at [https://hexdocs.pm/ex_openssl](https://hexdocs.pm/ex_openssl).

## Supported OpenSSL Functions

* `X509`
  - `X509::stack_from_pem`
* `PKey`
  - `PKey::private_key_from_pem`
* `PKCS7`
  - `PKCS7::encrypt`
  - `PKCS7::decrypt`
  - `PKCS7::smime_read`
  - `PKCS7::smime_write`
