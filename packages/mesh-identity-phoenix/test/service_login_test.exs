defmodule MetaMesh.Identity.Phoenix.ServiceLoginTest do
  use ExUnit.Case, async: false

  import Plug.Conn

  alias MetaMesh.Identity.Phoenix.ServiceLogin
  alias MetaMesh.Identity.Phoenix.Session

  @otp_app :mesh_identity_phoenix_test
  @origin "https://courses.example"
  @identity_origin "https://identity.example"
  @person_id "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

  setup do
    previous = Application.get_env(@otp_app, :identity_login)

    Application.put_env(@otp_app, :identity_login,
      identity_origin: @identity_origin,
      application_origin: @origin,
      verifier_path: "/native/verifier",
      verifier: {__MODULE__.Verifier, :verify, []},
      on_verified_identity: {__MODULE__.Adapter, :sign_in, []},
      on_logout: {__MODULE__.Adapter, :sign_out, []},
      application_name: "Courses"
    )

    on_exit(fn ->
      if previous,
        do: Application.put_env(@otp_app, :identity_login, previous),
        else: Application.delete_env(@otp_app, :identity_login)
    end)

    :ok
  end

  test "Given an Identity request, when owner approves, then issue one expiring session and reject replay" do
    challenge_conn = request("POST", "/identity/login/challenge", %{}, @origin)
    assert challenge_conn.status == 200
    request = Jason.decode!(challenge_conn.resp_body)

    assert request["kind"] == "mesh-service-login-request"
    assert request["version"] == 2
    assert request["return_to"] == @origin <> "/.well-known/mesh-service-login/callback"
    assert request["identity_origin"] == @identity_origin

    exchange_params = %{
      "challenge" => request["challenge"],
      "evidence" => %{"proof" => "fixture"}
    }

    signed_in = request("POST", "/identity/login/exchange", exchange_params, @origin)
    assert signed_in.status == 200
    response = Jason.decode!(signed_in.resp_body)
    assert response["person_id"] == @person_id
    assert response["device_id"] == "verified-device"
    assert response["return_to"] == "/courses/next"
    assert {:ok, %{"person_id" => @person_id}} = Session.current(signed_in)
    assert get_session(signed_in, :app_user_token) == "local-token"

    replay = request("POST", "/identity/login/exchange", exchange_params, @origin)
    assert replay.status == 401
    assert Jason.decode!(replay.resp_body)["error"]["code"] == "invalid_identity_proof"
  end

  test "Given a request from another origin, when requesting a challenge, then deny it" do
    denied = request("POST", "/identity/login/challenge", %{}, "https://attacker.example")
    assert denied.status == 403
    assert Jason.decode!(denied.resp_body)["error"]["code"] == "origin_denied"
  end

  test "Given an expired challenge, when exchanging proof, then reject it" do
    challenge = String.duplicate("a", 64)

    :ok =
      MetaMesh.Identity.Phoenix.Challenges.issue(
        challenge,
        System.system_time(:second) - 1,
        System.system_time(:second) - 121
      )

    denied =
      request(
        "POST",
        "/identity/login/exchange",
        %{
          "challenge" => challenge,
          "evidence" => %{"proof" => "fixture"}
        },
        @origin
      )

    assert denied.status == 401
  end

  test "Given an Identity session, when logging out, then revoke app token and clear shared session" do
    signed_in =
      Plug.Test.init_test_session(conn(:get, "/"), %{})
      |> Session.start(%{person_id: @person_id, device_id: "verified-device"}, %{
        app_user_token: "local-token"
      })

    logged_out = request_with_session("POST", "/identity/logout", %{}, @origin, signed_in)
    assert logged_out.status == 302
    assert get_session(logged_out, :mesh_identity) == nil
    assert get_session(logged_out, :app_user_token) == nil
  end

  test "Given an expired session, when read, then report no authenticated identity" do
    conn =
      Plug.Test.init_test_session(conn(:get, "/"), %{
        mesh_identity: %{
          "person_id" => @person_id,
          "device_id" => "verified-device",
          "expires_at" => 1
        }
      })

    assert Session.current(conn) == :error
  end

  defp request(method, path, params, origin) do
    conn = conn(method, path) |> put_req_header("origin", origin)
    conn = Plug.Test.init_test_session(conn, %{mesh_identity_return_to: "/courses/next"})
    conn = if method == "POST", do: put_body_params(conn, params), else: conn
    ServiceLogin.call(conn, @otp_app)
  end

  defp request_with_session(method, path, params, origin, session_conn) do
    conn = conn(method, path) |> put_req_header("origin", origin)
    conn = Plug.Test.init_test_session(conn, Map.new(get_session(session_conn)))
    conn = put_body_params(conn, params)
    ServiceLogin.call(conn, @otp_app)
  end

  defp put_body_params(conn, params) do
    conn
    |> put_req_header("content-type", "application/json")
    |> Map.put(:body_params, params)
    |> Map.put(:params, params)
  end

  defp conn(method, path), do: Plug.Test.conn(method, path)

  defmodule Verifier do
    def verify(%{"proof" => "fixture"}, _origin, _challenge, _expires_at, _now),
      do:
        {:ok,
         %{person_id: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", device_id: "verified-device"}}

    def verify(_, _, _, _, _), do: {:error, :invalid_proof}
  end

  defmodule Adapter do
    def sign_in(_conn, %{person_id: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
      do: {:ok, %{session: %{app_user_token: "local-token"}, return_to: "/courses/next"}}

    def sign_in(_, _), do: {:error, :unlinked_identity}

    def sign_out(%{app_user_token: "local-token"}), do: :ok
    def sign_out(_), do: :ok
  end
end
