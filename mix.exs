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
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:ex_doc, ">= 0.0.0", only: [:dev, :test], runtime: false},
      {:credo, "~> 0.5", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 0.4", only: [:dev, :test], runtime: false},
    ]
  end
end
