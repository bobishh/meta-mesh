defmodule MetaMesh.Identity.Phoenix.Challenges do
  @moduledoc false
  use GenServer

  @name __MODULE__
  @max_entries 10_000

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, :ok, Keyword.put_new(opts, :name, @name))
  end

  def issue(challenge, expires_at, now) do
    GenServer.call(@name, {:issue, challenge, expires_at, now})
  end

  def consume(challenge, now) do
    GenServer.call(@name, {:consume, challenge, now})
  end

  @impl true
  def init(:ok), do: {:ok, %{}}

  @impl true
  def handle_call({:issue, challenge, expires_at, now}, _from, entries) do
    active = Map.reject(entries, fn {_key, expiry} -> expiry <= now end)

    if map_size(active) >= @max_entries do
      {:reply, {:error, :capacity}, active}
    else
      {:reply, :ok, Map.put(active, challenge, expires_at)}
    end
  end

  def handle_call({:consume, challenge, now}, _from, entries) do
    case Map.pop(entries, challenge) do
      {expires_at, remaining} when is_integer(expires_at) and expires_at > now ->
        {:reply, {:ok, expires_at}, Map.reject(remaining, fn {_key, expiry} -> expiry <= now end)}

      {_expires_at, remaining} ->
        {:reply, {:error, :expired_or_used}, remaining}
    end
  end
end
