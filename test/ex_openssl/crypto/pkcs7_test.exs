defmodule ExOpenssl.Crypto.PKCS7Test do
  @moduledoc false

  @pkey File.read!("priv/test/key.pem")
  @cert File.read!("priv/test/cert.pem")

  use ExUnit.Case
  alias ExOpenssl.Crypto.PKCS7
  alias ExOpenssl.Crypto.PKCS7.SMIME
  alias ExOpenssl.Crypto.X509
  alias ExOpenssl.PKey
  doctest PKCS7, except: [
    sign: 5,
    encrypt: 4,
  ]

  describe "encrypt/5" do
    test "encrypts / decrypts correctly" do
      [recipient] = X509.from_pem!(@cert)
      pkey = PKey.from_pem!(@pkey)
      cleartext = "Foo"
      assert {:ok, pkcs7} = PKCS7.encrypt([recipient], cleartext, :des_ede3_cbc)

      {pkcs7, _} = pkcs7
      |> SMIME.write!(cleartext)
      |> SMIME.read!

      assert {:ok, ^cleartext} = PKCS7.decrypt(pkcs7, pkey, recipient)
    end
  end
end
