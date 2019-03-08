defmodule ExOpenssl.Nif do
  @moduledoc false

  use Rustler, otp_app: :ex_openssl, crate: :exopenssl

  def pem_read_x509(_pem), do: :erlang.nif_error(:nif_not_loaded)

  def pem_read_private_key(_pem), do: :erlang.nif_error(:nif_not_loaded)

  def pkcs7_encrypt(_certs, _input, _cipher, _flags), do: :erlang.nif_error(:nif_not_loaded)

  def pkcs7_decrypt(_pkcs7, _pkey, _cert), do: :erlang.nif_error(:nif_not_loaded)

  def pkcs7_sign(_signcert, _pkey, _certs, _input, _flags), do: :erlang.nif_error(:nif_not_loaded)

  def pkcs7_verify(_pkcs7, _certs, _store, _indata, _flags),
    do: :erlang.nif_error(:nif_not_loaded)

  def smime_write_pkcs7(_pkcs7, _data, _flags), do: :erlang.nif_error(:nif_not_loaded)

  def smime_read_pkcs7(_data), do: :erlang.nif_error(:nif_not_loaded)
end
