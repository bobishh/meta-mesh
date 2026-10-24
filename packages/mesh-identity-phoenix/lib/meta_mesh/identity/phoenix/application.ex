defmodule MetaMesh.Identity.Phoenix.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    Supervisor.start_link(
      [MetaMesh.Identity.Phoenix.Challenges],
      strategy: :one_for_one,
      name: MetaMesh.Identity.Phoenix.Supervisor
    )
  end
end
