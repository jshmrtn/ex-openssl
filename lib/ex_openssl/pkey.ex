defmodule ExOpenssl.PKey do
  @moduledoc """
  Private Key Handling
  """

  alias ExOpenssl.Nif
  alias ExOpenssl.Errors.Error
  alias ExOpenssl.Util
  require ExOpenssl.Util

  @typedoc """
  Pem encoded certificate string.
  """
  @type pem :: String.t

  @opaque key :: reference

  @doc """
  Read Key from Pem String

  ### Examples

      iex> PKey.from_pem(File.read!("priv/test/key.pem"))
      {:ok, #Reference<0.2767117777.4010409990.249887>}

      iex> PKey.from_pem(File.read!("priv/test/bad_key.pem"))
      {:error,
       [%ExOpenssl.Errors.Error{code: 218570907, data: nil,
         file: "crypto/asn1/asn1_lib.c", function: "ASN1_get_object",
         library: "asn1 encoding routines", line: 91, reason: nil},
        %ExOpenssl.Errors.Error{code: 218529894, data: nil,
         file: "crypto/asn1/tasn_dec.c", function: "asn1_check_tlen",
         library: "asn1 encoding routines", line: 1100,
         reason: "MISSING_EQUAL_SIGN"},
        %ExOpenssl.Errors.Error{code: 218595386, data: "Type=X509",
         file: "crypto/asn1/tasn_dec.c", function: "asn1_item_embed_d2i",
         library: "asn1 encoding routines", line: 274, reason: nil},
        %ExOpenssl.Errors.Error{code: 151416845, data: nil,
         file: "crypto/pem/pem_oth.c", function: "PEM_ASN1_read_bio",
         library: "PEM routines", line: 33,
         reason: "configuration file routines"}]}

  """
  @spec from_pem(pem :: pem) :: {:ok, key} | {:error, [Error.t]}
  def from_pem(pem) when is_binary(pem),
    do: Nif.pem_read_private_key(pem)

  @spec from_pem!(pem :: pem) :: key | no_return
  Util.raising_def(:from_pem, 1)
end
