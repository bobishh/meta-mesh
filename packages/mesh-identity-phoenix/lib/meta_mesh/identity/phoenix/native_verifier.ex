defmodule MetaMesh.Identity.Phoenix.NativeVerifier do
  @moduledoc false

  @max_input_bytes 128 * 1024
  @max_output_bytes 65_536
  @timeout_ms 5_000

  def verify(config, evidence, origin, challenge, expires_at, now) do
    case Keyword.get(config, :verifier) do
      {module, function, extra} when is_atom(module) and is_atom(function) and is_list(extra) ->
        apply(module, function, [evidence, origin, challenge, expires_at, now] ++ extra)

      _ ->
        verify_native(
          Keyword.get(config, :verifier_path),
          evidence,
          origin,
          challenge,
          expires_at,
          now
        )
    end
  rescue
    _ -> {:error, :invalid_proof}
  end

  defp verify_native(path, evidence, origin, challenge, expires_at, now)
       when is_binary(path) and path != "" do
    input = %{
      identity: evidence["identity"],
      deviceId: evidence["deviceId"],
      certificates: evidence["certificates"],
      proof: evidence["proof"],
      expectedOrigin: origin,
      expectedChallenge: challenge,
      expectedExpiresAtMs: expires_at * 1_000,
      nowMs: now * 1_000
    }

    with {:ok, json} <- Jason.encode(input),
         true <- byte_size(json) <= @max_input_bytes do
      run(path, json <> "\n")
    else
      _ -> {:error, :invalid_proof}
    end
  end

  defp verify_native(_, _, _, _, _, _), do: {:error, :verifier_unavailable}

  defp run(path, input) do
    port =
      Port.open({:spawn_executable, String.to_charlist(path)}, [
        :binary,
        :exit_status,
        :use_stdio,
        {:args, []}
      ])

    try do
      true = Port.command(port, input)
      collect(port, <<>>, System.monotonic_time(:millisecond) + @timeout_ms)
    after
      if Port.info(port), do: Port.close(port)
    end
  rescue
    _ -> {:error, :verifier_unavailable}
  end

  defp collect(port, output, deadline) when byte_size(output) <= @max_output_bytes do
    remaining = deadline - System.monotonic_time(:millisecond)

    if remaining <= 0 do
      {:error, :verifier_timeout}
    else
      receive do
        {^port, {:data, data}} -> collect(port, output <> data, deadline)
        {^port, {:exit_status, 0}} -> decode(output)
        {^port, {:exit_status, _}} -> {:error, :invalid_proof}
      after
        remaining -> {:error, :verifier_timeout}
      end
    end
  end

  defp collect(_, _, _), do: {:error, :verifier_output_too_large}

  defp decode(output) do
    case Jason.decode(String.trim(output)) do
      {:ok, %{"verified" => true, "personId" => person_id, "deviceId" => device_id}}
      when is_binary(person_id) and is_binary(device_id) ->
        {:ok, %{person_id: person_id, device_id: device_id}}

      _ ->
        {:error, :invalid_proof}
    end
  end
end
