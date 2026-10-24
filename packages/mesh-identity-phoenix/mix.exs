defmodule MetaMesh.Identity.Phoenix.MixProject do
  use Mix.Project

  def project do
    [
      app: :mesh_identity_phoenix,
      version: "0.1.0",
      elixir: "~> 1.16",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Shared Phoenix and Plug adapter for MetaMesh Identity service login",
      package: package()
    ]
  end

  def application do
    [extra_applications: [:logger], mod: {MetaMesh.Identity.Phoenix.Application, []}]
  end

  defp deps do
    [
      {:plug, ">= 1.15.0 and < 2.0.0"},
      {:jason, ">= 1.4.0 and < 2.0.0"}
    ]
  end

  defp package do
    [
      links: %{"GitHub" => "https://github.com/bobishh/meta-mesh"},
      files: ["lib", "mix.exs", "README.md"]
    ]
  end
end
