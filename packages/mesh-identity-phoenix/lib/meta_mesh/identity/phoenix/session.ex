defmodule MetaMesh.Identity.Phoenix.Session do
  @moduledoc """
  Shared, expiring Identity grant stored in the application's signed Plug session.

  Applications keep account lookup, resource policy, and their own session token in
  their callback. This module owns the common verified Identity session invariant.
  """

  import Plug.Conn

  @session_key :mesh_identity
  @default_max_age 43_200

  def current(conn, now \\ System.system_time(:second)) do
    current_session(get_session(conn, @session_key), now)
  end

  def current_session(session, now \\ System.system_time(:second)) do
    case session do
      %{"person_id" => person_id, "device_id" => device_id, "expires_at" => expires_at} = grant
      when is_binary(person_id) and is_binary(device_id) and is_integer(expires_at) and
             expires_at > now ->
        if valid_person_id?(person_id) and byte_size(device_id) in 1..256 do
          {:ok, grant}
        else
          :error
        end

      _ ->
        :error
    end
  end

  def start(conn, identity, session_fields \\ %{}, max_age \\ @default_max_age)

  def start(conn, %{person_id: person_id, device_id: device_id}, session_fields, max_age)
      when is_binary(person_id) and is_binary(device_id) and is_map(session_fields) and
             is_integer(max_age) and max_age > 0 do
    now = System.system_time(:second)

    conn
    |> configure_session(renew: true)
    |> clear_session()
    |> put_session(@session_key, %{
      "person_id" => person_id,
      "device_id" => device_id,
      "expires_at" => now + max_age
    })
    |> put_fields(session_fields)
  end

  def max_age(config), do: Keyword.get(config, :session_max_age, @default_max_age)

  def clear(conn), do: conn |> configure_session(renew: true) |> clear_session()

  def valid_person_id?(person_id) when is_binary(person_id) and byte_size(person_id) == 43 do
    case Base.url_decode64(person_id, padding: false) do
      {:ok, bytes} ->
        byte_size(bytes) == 32 and Base.url_encode64(bytes, padding: false) == person_id

      :error ->
        false
    end
  end

  def valid_person_id?(_), do: false

  defp put_fields(conn, fields) do
    Enum.reduce(fields, conn, fn {key, value}, acc -> put_session(acc, key, value) end)
  end
end
