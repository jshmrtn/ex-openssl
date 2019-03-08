defmodule ExOpenssl.Crypto.PKCS7.SMIME do
  @moduledoc """
  PKCS7 SMIME Output Handling Encryption
  """

  alias ExOpenssl.Crypto.PKCS7
  alias ExOpenssl.Errors.Error
  alias ExOpenssl.Nif
  alias ExOpenssl.Util

  require ExOpenssl.Util

  @type bcount :: binary

  @spec write(pkcs7 :: PKCS7.pkcs7(), data :: binary, flags :: PKCS7.flags()) ::
          {:ok, binary} | {:error, [Error.t()]}
  def write(pkcs7, data, flags \\ [:stream])

  def write(pkcs7, data, flags)
      when is_reference(pkcs7) and is_binary(data) and is_list(flags) and length(flags) > 0,
      do: pkcs7 |> Nif.smime_write_pkcs7(data, flags) |> clean_write_result

  defp clean_write_result({:ok, out})
       when is_list(out),
       do: {:ok, :erlang.list_to_binary(out)}

  defp clean_write_result({:error, errors}),
    do: {:error, errors}

  @spec write!(pkcs7 :: PKCS7.pkcs7(), data :: binary, flags :: PKCS7.flags()) ::
          binary | no_return
  def write!(pkcs7, data, flags \\ [:stream])
  Util.raising_def(:write, 3)

  @doc """
  Read SMIME message into PKCS7 format

  ### Examples

      iex> ExOpenssl.Crypto.PKCS7.SMIME.read(File.read!("priv/test/message_enc_foo.p7"))
      {:ok, {#Reference<0.2263162369.3671457794.130711>, []}}

  """
  @spec read(data :: binary) ::
          {:ok, {PKCS7.pkcs7(), bcount}} | {:error, [Error.t()]}
  def read(data)
      when is_binary(data),
      do: data |> Nif.smime_read_pkcs7() |> clean_read_result

  defp clean_read_result({:ok, {pkcs7, []}})
       when is_reference(pkcs7),
       do: {:ok, {pkcs7, nil}}

  defp clean_read_result({:ok, {pkcs7, bcount}})
       when is_reference(pkcs7) and is_list(bcount),
       do: {:ok, {pkcs7, :erlang.list_to_binary(bcount)}}

  defp clean_read_result({:error, errors}),
    do: {:error, errors}

  @spec read!(data :: binary) ::
          {PKCS7.pkcs7(), bcount} | no_return
  Util.raising_def(:read, 1)
end
