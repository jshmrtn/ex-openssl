defmodule ExOpenssl.Errors.Error do
  @moduledoc """
  Openssl Error representation
  """

  @enforce_keys [
    :code,
    :data,
    :file,
    :function,
    :library,
    :line,
    :reason
  ]

  defexception @enforce_keys

  @type t :: %__MODULE__{
          __exception__: true,
          code: integer,
          data: nil | String.t(),
          file: nil | String.t(),
          function: nil | String.t(),
          library: nil | String.t(),
          line: nil | integer,
          reason: nil | String.t()
        }

  def message(%__MODULE__{} = error), do: "#{inspect(error)}"
  def exception(%__MODULE__{} = error), do: error
end
