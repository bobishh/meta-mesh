defmodule MetaMesh.Identity.Phoenix.ServiceLogin do
  @moduledoc """
  Plug adapter for same-tab MetaMesh Identity service login.

  Mount in the application's login pipeline after session and CSRF plugs. Configure
  `:identity_login` under the selected OTP app with exact origins, the SDK native
  verifier path, and `:on_verified_identity` / optional `:on_logout` callbacks.
  """

  @behaviour Plug
  import Plug.Conn

  alias MetaMesh.Identity.Phoenix.Challenges
  alias MetaMesh.Identity.Phoenix.NativeVerifier
  alias MetaMesh.Identity.Phoenix.Session

  @challenge_lifetime_seconds 120
  @max_evidence_bytes 128 * 1024

  @impl Plug
  def init(opts), do: Keyword.fetch!(opts, :otp_app)

  @impl Plug
  def call(conn, otp_app) do
    config = Application.get_env(otp_app, :identity_login)

    case {conn.method, conn.request_path, configured_config?(config)} do
      {"GET", "/identity/login", true} ->
        login_page(conn, config)

      {"GET", "/.well-known/mesh-service-login/callback", true} ->
        callback_page(conn, config)

      {"POST", "/identity/login/challenge", true} ->
        challenge(conn, config)

      {"POST", "/identity/login/exchange", true} ->
        exchange(conn, config)

      {"POST", "/identity/logout", true} ->
        logout(conn, config)

      {method, path, false}
      when method in ["GET", "POST"] and
             path in [
               "/identity/login",
               "/identity/login/challenge",
               "/identity/login/exchange",
               "/identity/logout",
               "/.well-known/mesh-service-login/callback"
             ] ->
        unavailable(conn)

      _ ->
        conn
    end
  end

  def configured?(otp_app) when is_atom(otp_app),
    do: configured_config?(Application.get_env(otp_app, :identity_login))

  defp configured_config?(config) when is_list(config) do
    with identity_origin when is_binary(identity_origin) <- Keyword.get(config, :identity_origin),
         application_origin when is_binary(application_origin) <-
           Keyword.get(config, :application_origin),
         on_verified when is_tuple(on_verified) <- Keyword.get(config, :on_verified_identity),
         true <- valid_origin?(identity_origin) and valid_origin?(application_origin),
         true <- valid_verifier_config?(config) do
      true
    else
      _ -> false
    end
  end

  defp configured_config?(_), do: false

  defp valid_verifier_config?(config) do
    case Keyword.get(config, :verifier) do
      {module, function, extra} when is_atom(module) and is_atom(function) and is_list(extra) ->
        true

      _ ->
        is_binary(Keyword.get(config, :verifier_path)) and
          Keyword.get(config, :verifier_path) != ""
    end
  end

  defp login_page(conn, config) do
    return_to = safe_return_to(conn.params["return_to"])
    conn = put_session(conn, :mesh_identity_return_to, return_to)
    page(conn, config, "login")
  end

  defp callback_page(conn, config), do: page(conn, config, "callback")

  defp page(conn, config, mode) do
    button = if mode == "callback", do: " hidden", else: ""
    progress = if mode == "callback", do: "", else: " hidden"
    javascript_path = Keyword.get(config, :javascript_path, "/assets/js/identity_login.js")
    stylesheet_path = Keyword.get(config, :stylesheet_path)

    stylesheet =
      if is_binary(stylesheet_path),
        do: "<link rel=\"stylesheet\" href=\"#{escape_html(stylesheet_path)}\">",
        else: ""

    conn
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_content_type("text/html")
    |> send_resp(200, """
    <!doctype html>
    <html lang="en">
      <head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign in · #{escape_html(Keyword.get(config, :application_name, "Application"))}</title>#{stylesheet}</head>
      <body data-identity-login-mode="#{mode}">
        <main>
          <h1>Sign in to #{escape_html(Keyword.get(config, :application_name, "Application"))}</h1>
          <p>Continue with your MetaMesh Identity account.</p>
          <button id="identity-login" type="button"#{button}>Sign in with MetaMesh Identity</button>
          <p id="identity-login-progress"#{progress}>Completing sign-in…</p>
          <p id="identity-login-status" role="status" aria-live="polite"></p>
        </main>
        <script type="module" src="#{escape_html(javascript_path)}"></script>
      </body>
    </html>
    """)
  end

  defp challenge(conn, config) do
    with {:ok, origin} <- request_origin(conn, config),
         now <- System.system_time(:second),
         expires_at <- now + @challenge_lifetime_seconds,
         challenge <- Base.encode16(:crypto.strong_rand_bytes(32), case: :lower),
         :ok <- Challenges.issue(challenge, expires_at, now) do
      conn
      |> put_resp_header("cache-control", "no-store")
      |> json_response(200, %{
        kind: "mesh-service-login-request",
        version: 2,
        origin: origin,
        challenge: challenge,
        expires_at: expires_at,
        return_to: origin <> "/.well-known/mesh-service-login/callback",
        identity_origin: Keyword.fetch!(config, :identity_origin)
      })
    else
      {:error, :origin_denied} ->
        error(conn, 403, "origin_denied", "Request origin is not allowed")

      {:error, :capacity} ->
        error(conn, 503, "login_capacity", "Identity sign-in is busy. Try again.")

      _ ->
        error(conn, 503, "login_unavailable", "Identity sign-in is unavailable")
    end
  end

  defp exchange(conn, config) do
    params = conn.body_params
    challenge = params["challenge"]
    evidence = params["evidence"]
    now = System.system_time(:second)

    with true <- is_binary(challenge) and is_map(evidence),
         {:ok, evidence_json} <- Jason.encode(evidence),
         true <- byte_size(evidence_json) <= @max_evidence_bytes,
         {:ok, origin} <- request_origin(conn, config),
         {:ok, expires_at} <- Challenges.consume(challenge, now),
         {:ok, verified} <-
           NativeVerifier.verify(config, evidence, origin, challenge, expires_at, now),
         true <- Session.valid_person_id?(verified.person_id),
         {:ok, app_session} <-
           invoke(Keyword.fetch!(config, :on_verified_identity), [conn, verified]) do
      return_to = safe_return_to(get_session(conn, :mesh_identity_return_to))
      session_fields = Map.get(app_session, :session, %{})

      if not is_map(session_fields) do
        error(conn, 500, "login_adapter_error", "Identity sign-in could not be completed")
      else
        conn =
          conn
          |> Session.start(verified, session_fields)
          |> delete_session(:mesh_identity_return_to)

        {:ok, identity_session} = Session.current(conn)

        conn
        |> put_resp_header("cache-control", "no-store")
        |> json_response(200, %{
          person_id: verified.person_id,
          device_id: verified.device_id,
          expires_at: identity_session["expires_at"],
          return_to: safe_return_to(Map.get(app_session, :return_to, return_to))
        })
      end
    else
      false ->
        error(conn, 401, "invalid_identity_proof", "Identity proof is invalid")

      {:error, :origin_denied} ->
        error(conn, 403, "origin_denied", "Request origin is not allowed")

      {:error, :expired_or_used} ->
        error(conn, 401, "invalid_identity_proof", "Identity proof is invalid or expired")

      {:error, :unlinked_identity} ->
        error(
          conn,
          403,
          "account_link_required",
          "Connect this Identity to an existing account first"
        )

      {:error, reason} when reason in [:verifier_unavailable, :verifier_timeout] ->
        error(conn, 503, "identity_login_unavailable", "Identity sign-in is unavailable")

      {:error, _reason} ->
        error(conn, 401, "invalid_identity_proof", "Identity proof is invalid or expired")

      _ ->
        error(conn, 503, "identity_login_unavailable", "Identity sign-in is unavailable")
    end
  end

  defp logout(conn, config) do
    session = get_session(conn)

    with :ok <- invoke_optional(Keyword.get(config, :on_logout), [session]) do
      conn
      |> Session.clear()
      |> put_resp_header("location", "/identity/login")
      |> send_resp(302, "")
    else
      _ -> error(conn, 503, "logout_unavailable", "Sign out could not be completed")
    end
  end

  defp request_origin(conn, config) do
    expected = Keyword.fetch!(config, :application_origin)

    case get_req_header(conn, "origin") do
      [^expected] -> {:ok, expected}
      _ -> {:error, :origin_denied}
    end
  end

  defp safe_return_to(path) when is_binary(path) and byte_size(path) <= 2048 do
    uri = URI.parse(path)

    if String.starts_with?(path, "/") and not String.starts_with?(path, "//") and
         is_nil(uri.scheme) and is_nil(uri.host) and
         uri.path not in ["/identity/login", "/.well-known/mesh-service-login/callback"] do
      path
    else
      "/"
    end
  end

  defp safe_return_to(_), do: "/"

  defp valid_origin?(origin) do
    uri = URI.parse(origin)

    with %URI{scheme: scheme, host: host, userinfo: nil, path: path, query: nil, fragment: nil} <-
           uri,
         true <- is_binary(host) and path in [nil, "", "/"],
         true <- scheme in ["https", "http"],
         true <- scheme == "https" or local_http_host?(host),
         true <-
           String.downcase(host) == host and Enum.all?(String.to_charlist(host), &(&1 < 128)),
         true <- canonical_origin(uri) == origin do
      true
    else
      _ -> false
    end
  end

  defp canonical_origin(%URI{scheme: scheme, host: host, port: port}) do
    host_text = if String.contains?(host, ":"), do: "[#{host}]", else: host
    default_port = if scheme == "https", do: 443, else: 80
    port_text = if port == default_port, do: "", else: ":#{port}"
    "#{scheme}://#{host_text}#{port_text}"
  end

  defp local_http_host?(host) do
    host == "localhost" or
      case :inet.parse_address(String.to_charlist(host)) do
        {:ok, {127, _, _, _}} -> true
        {:ok, {0, 0, 0, 0, 0, 0, 0, 1}} -> true
        _ -> false
      end
  end

  defp invoke({module, function, extra}, args)
       when is_atom(module) and is_atom(function) and is_list(extra),
       do: apply(module, function, args ++ extra)

  defp invoke(_, _), do: {:error, :invalid_adapter}

  defp invoke_optional(nil, _), do: :ok

  defp invoke_optional(callback, args) do
    case invoke(callback, args) do
      :ok -> :ok
      {:ok, _} -> :ok
      error -> error
    end
  end

  defp unavailable(conn),
    do: conn |> put_status(:not_found) |> send_resp(404, "Identity sign-in is not configured.")

  defp error(conn, status, code, message) do
    json_response(conn, status, %{error: %{code: code, message: message}})
  end

  defp json_response(conn, status, value) do
    conn
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(value))
  end

  defp escape_html(value) do
    value |> to_string() |> Plug.HTML.html_escape() |> IO.iodata_to_binary()
  end
end
