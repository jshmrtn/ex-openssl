defmodule ExOpenssl.Mixfile do
  @moduledoc false

  use Mix.Project

  def project do
    [
      app: :ex_openssl,
      version: "0.1.0",
      elixir: "~> 1.5",
      start_permanent: Mix.env == :prod,
      deps: deps(),
      dialyzer: [ignore_warnings: "dialyzer.ignore-warnings"],
      compilers: [:rustler] ++ Mix.compilers,
      rustler_crates: rustler_crates(),
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp rustler_crates do
    [
      exopenssl: [
        path: "native/exopenssl",
        mode: (if Mix.env == :prod, do: :release, else: :debug),
      ]
    ]
  end

  defp deps do
    [
      {:rustler, "~> 0.10.1"},
      {:ex_doc, ">= 0.0.0", only: [:dev, :test], runtime: false},
      {:credo, "~> 0.5", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 0.4", only: [:dev, :test], runtime: false},
    ]
  end
end
