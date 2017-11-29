defmodule ExOpenssl.Crypto.PKCS7.SMIMETest do
  @moduledoc false

  @message_enc_foo File.read!("priv/test/message_enc_foo.p7")
  @message_sig_clear File.read!("priv/test/message_sig_clear.p7")
  @message_broken File.read!("priv/test/message_broken.p7")

  use ExUnit.Case
  alias ExOpenssl.Crypto.PKCS7.SMIME
  alias ExOpenssl.Errors.Error
  doctest SMIME, except: [
    read: 1,
  ]

  describe "read/1" do
    test "decodes encrypted message" do
      assert {:ok, {pkcs7, nil}} = SMIME.read(@message_enc_foo)
      assert is_reference(pkcs7)
    end
    test "decodes signed message" do
      assert {:ok, {pkcs7, "Foo"}} = SMIME.read(@message_sig_clear)
      assert is_reference(pkcs7)
    end
    test "errors with invalid message" do
      assert {:error, [%Error{} | _]} = SMIME.read(@message_broken)
    end
  end
end
