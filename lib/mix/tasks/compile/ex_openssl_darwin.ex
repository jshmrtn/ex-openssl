if {:unix, :darwin} == :os.type() do
  defmodule Mix.Tasks.Compile.ExOpensslDarwin do
    @moduledoc """
    Compile Native Code on OS X
    """

    use Mix.Task

    @shortdoc "Compile Native on Darwin"

    def run(_) do
      build_script = Path.join(System.cwd!, "native/exopenssl/build.sh")
      {_, 0} = System.cmd(build_script, [], [
        into: IO.stream(:stdio, :line),
        env: [{"OPENSSL_DIR", openssl_path()}],
      ])
    end

    defp openssl_path do
      cond do
        System.get_env("OPENSSL_DIR") ->
          System.get_env("OPENSSL_DIR")
        File.exists?("/usr/local/Cellar/openssl@1.1/") ->
          [path | _] = "/usr/local/Cellar/openssl@1.1/"
          |> File.ls!
          |> Enum.sort
          |> Enum.reverse

          "/usr/local/Cellar/openssl@1.1/" <> path
        File.exists?("/usr/local/Cellar/openssl/") ->
          [path | _] = "/usr/local/Cellar/openssl/"
          |> File.ls!
          |> Enum.sort
          |> Enum.reverse

          "/usr/local/Cellar/openssl/" <> path
        true ->
          IO.puts """
          No directory that contains openssl was automatically detected.
          This is required to build on Mac OSX.

          Either install openssl via Brew (http://brewformulas.org/Openssl)
          or install it manually and specify the Env Variable OPENSSL_DIR.
          """
          raise "openssl install path not found"
      end
    end
  end
end
