defmodule ExOpenssl.Crypto.PKCS7 do
  @moduledoc """
  PKCS7 Handling. See `ExOpenssl.Crypto.PKCS7` for IO.
  """

  alias ExOpenssl.Crypto.X509
  alias ExOpenssl.Errors.Error
  alias ExOpenssl.Nif
  alias ExOpenssl.PKey
  alias ExOpenssl.Symm.Cipher
  alias ExOpenssl.Util

  require ExOpenssl.Util

  @opaque pkcs7 :: reference

  @type flag ::
          :text
          | :nocerts
          | :nosigs
          | :nochain
          | :nointern
          | :noverify
          | :detached
          | :binary
          | :noattr
          | :nosmimecap
          | :nooldmimetype
          | :crlfeol
          | :stream
          | :nocrl
          | :partial
          | :reuse_digest
          | :no_dual_content
  @type flags :: [flag]

  @doc """
  Encrypt binary `input` for the recipients `certs`.

  ### Examples

      iex> recipients = ExOpenssl.Crypto.X509.from_pem!(File.read!("priv/test/cert.pem"))
      iex> cleartext = "Foo"
      iex> {:ok, pkcs7} = PKCS7.encrypt(recipients, cleartext, :des_ede3_cbc)
      iex> ExOpenssl.Crypto.PKCS7.SMIME.write!(pkcs7, cleartext)
      "MIME-Version: 1.0...."

  """
  @spec encrypt(
          certs :: [X509.certificate()],
          input :: binary,
          cipher :: Cipher.cipher(),
          flags :: flags
        ) ::
          {:ok, pkcs7} | {:error, [Error.t()]}
  def encrypt(certs, input, cipher, flags \\ [:stream])

  def encrypt(certs, input, cipher, flags)
      when is_list(certs) and is_binary(input) and is_atom(cipher) and length(flags) > 0,
      do: Nif.pkcs7_encrypt(certs, input, cipher, flags)

  @spec encrypt!(
          certs :: [X509.certificate()],
          input :: binary,
          cipher :: Cipher.cipher(),
          flags :: flags
        ) ::
          pkcs7 | no_return
  def encrypt!(certs, input, cipher, flags \\ [:stream])
  Util.raising_def(:encrypt, 4)

  @doc """
  Decrypt pkcs7 `pkcs7` using the recipients `pkey` and `cert`.

  ### Examples

      iex> [recipient] = ExOpenssl.Crypto.X509.from_pem!(File.read!("priv/test/cert.pem"))
      iex> pkey = ExOpenssl.PKey.from_pem!(File.read!("priv/test/key.pem"))
      iex> message = File.read!("priv/test/message_enc_foo.p7")
      iex> {pkcs7, _} = ExOpenssl.Crypto.PKCS7.SMIME.read!(message)
      iex> PKCS7.decrypt!(pkcs7, pkey, recipient)
      "Foo"

  """
  @spec decrypt(pkcs7 :: pkcs7, pkey :: PKey.key(), cert :: X509.certificate()) ::
          {:ok, binary} | {:error, [Error.t()]}
  def decrypt(pkcs7, pkey, cert)

  def decrypt(pkcs7, pkey, cert)
      when is_reference(pkcs7) and is_reference(pkey) and is_reference(cert),
      do: pkcs7 |> Nif.pkcs7_decrypt(pkey, cert) |> clean_decrypt_result

  defp clean_decrypt_result({:ok, out})
       when is_list(out),
       do: {:ok, :erlang.list_to_binary(out)}

  defp clean_decrypt_result({:error, errors}),
    do: {:error, errors}

  @spec decrypt!(pkcs7 :: pkcs7, pkey :: PKey.key(), cert :: X509.certificate()) ::
          binary | no_return
  def decrypt!(pkcs7, pkey, cert)
  Util.raising_def(:decrypt, 3)

  @doc """
  Sign binary `input`.

  ### Examples

      iex> [signcert] = ExOpenssl.Crypto.X509.from_pem!(File.read!("priv/test/cert.pem"))
      iex> cleartext = "Foo"
      iex> pkey = ExOpenssl.PKey.from_pem!(File.read!("priv/test/key.pem"))
      iex> {:ok, pkcs7} = PKCS7.sign(signcert, pkey, cleartext)
      iex> ExOpenssl.Crypto.PKCS7.SMIME.write!(pkcs7, cleartext)
      "MIME-Version: 1.0...."

  """
  @spec sign(
          signcert :: X509.certificate(),
          pkey :: PKey.key(),
          certs :: [X509.certificate()],
          input :: binary,
          flags :: flags
        ) ::
          {:ok, pkcs7} | {:error, [Error.t()]}
  def sign(signcert, pkey, certs \\ [], input, flags \\ [:stream])

  def sign(signcert, pkey, certs, input, flags)
      when is_reference(signcert) and is_reference(pkey) and is_list(certs) and is_binary(input) and
             is_list(flags) and
             length(flags) > 0,
      do: Nif.pkcs7_sign(signcert, pkey, certs, input, flags)

  @spec sign!(
          signcert :: X509.certificate(),
          pkey :: PKey.key(),
          certs :: [X509.certificate()],
          input :: binary,
          flags :: flags
        ) ::
          pkcs7 | no_return
  def sign!(signcert, pkey, certs \\ [], input, flags \\ [:stream])
  Util.raising_def(:sign, 5)

  @doc """
  Verify Signature

  ### Examples

      iex> certs = ExOpenssl.Crypto.X509.from_pem!(File.read!("priv/test/cert.pem"))
      iex> store = ExOpenssl.Crypto.X509.from_pem!(File.read!("priv/test/root-ca.pem"))
      iex> message = File.read!("priv/test/message_sig_clear.p7")
      iex> {pkcs7, bcount} = ExOpenssl.Crypto.PKCS7.SMIME.read!(message)
      iex> PKCS7.verify(pkcs7, certs, store, bcount)
      {:ok, {true, "Foo"}}

  """
  @spec verify(
          pkcs7 :: pkcs7,
          certs :: [X509.certificate()],
          store :: [X509.certificate()],
          indata :: nil | binary,
          flags :: flags
        ) ::
          {:ok, {true, binary}} | {:error, [Error.t()]}
  def verify(pkcs7, certs, store, indata \\ nil, flags \\ [:stream])

  def verify(pkcs7, certs, store, indata, flags)
      when is_reference(pkcs7) and is_list(certs) and is_list(store) and
             (is_binary(indata) or is_nil(indata)) and
             is_list(flags) and length(flags) > 0,
      do: pkcs7 |> Nif.pkcs7_verify(certs, store, indata, flags) |> clean_verify_result

  defp clean_verify_result({:ok, {true, []}}),
    do: {:ok, {true, nil}}

  defp clean_verify_result({:ok, {true, out}}) when is_list(out),
    do: {:ok, {true, :erlang.list_to_binary(out)}}

  defp clean_verify_result({:error, errors}),
    do: {:error, errors}

  @spec verify!(
          pkcs7 :: pkcs7,
          certs :: [X509.certificate()],
          store :: [X509.certificate()],
          indata :: nil | binary,
          flags :: flags
        ) ::
          {true, binary} | no_return
  def verify!(pkcs7, certs, store, indata \\ nil, flags \\ [:stream])
  Util.raising_def(:verify, 5)
end
