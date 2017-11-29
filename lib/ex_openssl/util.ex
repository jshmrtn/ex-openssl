defmodule ExOpenssl.Util do
  @moduledoc false

  alias ExOpenssl.Errors.Error

  defmacro raising_def(name, arity) do
    alias ExOpenssl.Util

    raising_name = String.to_atom("#{name}!")
    doc = """
    See `#{name}/#{arity}`
    """
    args = Enum.map(1..arity, fn i ->
      {String.to_atom("arg#{i}"), [], ExOpenssl.Util}
    end)

    {
      :__block__,
      [],
      [
        {
          :@,
          [context: Util, import: Kernel],
          [{:doc, [context: Util], [doc]}]
        },
        {
          :def,
          [context: Util, import: Kernel],
          [
            {
              raising_name,
              [context: Util],
              args
            },
            [
              do: {
                {:., [], [{:__aliases__, [alias: false], [Util]}, :handle_response]},
                [],
                [
                  {
                    :apply,
                    [context: Util, import: Kernel],
                    [
                      {:__MODULE__, [], Util},
                      name,
                      args
                    ]
                  }
                ]
              }
            ]
          ]
        }
      ]
    }
  end

  def handle_response({:ok, ok}), do: ok
  def handle_response({:error, [error | _]}), do: raise Error, error
end
