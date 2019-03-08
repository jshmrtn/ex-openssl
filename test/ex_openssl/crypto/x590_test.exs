defmodule ExOpenssl.Crypto.X509Test do
  @moduledoc false

  @cert File.read!("priv/test/cert.pem")
  @bad_cert File.read!("priv/test/bad_cert.pem")

  use ExUnit.Case
  alias ExOpenssl.Crypto.X509
  alias ExOpenssl.Errors.Error

  doctest X509,
    except: [
      from_pem: 1
    ]

  describe "from_pem/1" do
    test "parses correct cert" do
      assert {:ok, certs} = X509.from_pem(@cert)
      assert is_list(certs)
      assert Enum.count(certs) == 1
    end

    test "gives error on invalid" do
      assert {:error, errors} = X509.from_pem(@bad_cert)
      assert is_list(errors)

      assert Enum.all?(errors, fn
               %Error{} -> true
               _ -> false
             end)
    end
  end

  describe "from_pem!/1" do
    test "parses correct cert" do
      assert certs = X509.from_pem!(@cert)
      assert is_list(certs)
      assert Enum.count(certs) == 1
    end

    test "gives error on invalid" do
      assert_raise Error, fn ->
        X509.from_pem!(@bad_cert)
      end
    end
  end
end
