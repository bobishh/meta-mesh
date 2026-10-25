# MetaMesh Identity Phoenix adapter

`MetaMesh.Identity.Phoenix.ServiceLogin` provides the shared same-tab Identity service-login
routes and server lifecycle for Plug/Phoenix applications. It owns exact-origin validation,
v2 request construction, bounded one-time challenges, native proof verification, the common
expiring Identity session, callback handling, and logout. Applications own account linking,
resource access, and their existing account/session token.

Add `{:mesh_identity_phoenix, git: "https://github.com/bobishh/meta-mesh.git", subdir: "packages/mesh-identity-phoenix", rev: "<immutable commit>"}`
to the application. Mount it after session and CSRF protection in an Identity-only pipeline:

```elixir
pipeline :identity_login_pages do
  plug :accepts, ["html"]
  plug :fetch_session
  plug :put_secure_browser_headers
end

pipeline :identity_login_api do
  plug :accepts, ["json"]
  plug :fetch_session
end

pipeline :identity_logout do
  plug :accepts, ["html"]
  plug :fetch_session
  plug :protect_from_forgery
  plug :put_secure_browser_headers
end

scope "/" do
  pipe_through :identity_login_pages
  forward "/identity/login", MetaMesh.Identity.Phoenix.ServiceLogin, otp_app: :my_app
  forward "/.well-known/mesh-service-login/callback", MetaMesh.Identity.Phoenix.ServiceLogin,
    otp_app: :my_app
end

scope "/identity/login" do
  pipe_through :identity_login_api
  forward "/challenge", MetaMesh.Identity.Phoenix.ServiceLogin, otp_app: :my_app
  forward "/exchange", MetaMesh.Identity.Phoenix.ServiceLogin, otp_app: :my_app
end

scope "/" do
  pipe_through :identity_logout
  forward "/identity/logout", MetaMesh.Identity.Phoenix.ServiceLogin, otp_app: :my_app
end
```

The plug handles `GET /identity/login`, `GET /.well-known/mesh-service-login/callback`,
`POST /identity/login/challenge`, `POST /identity/login/exchange`, and `POST /identity/logout`.
Configure `:identity_login` under the selected OTP app with `:identity_origin`,
`:application_origin`, `:verifier_path`, and `:on_verified_identity` as an MFA tuple
`{module, function, extra_args}`. The callback receives `(conn, verified_grant)` and returns
`{:ok, %{session: app_session_fields, return_to: local_path}}` or `{:error, :unlinked_identity}`.
Optional `:on_logout` receives the old Plug session and must return `:ok`; use it to revoke an
application-owned session token. `MetaMesh.Identity.Phoenix.Session.current/1` reads the
verified Identity session; `Session.start/3` and `Session.clear/1` are available to adapters.

`:session_max_age` configures the verified service session lifetime in positive integer
seconds. The default remains 43,200 seconds (12 hours) for existing consumers. For example,
`session_max_age: 60 * 86_400` issues a 60-day session. Invalid values disable login rather
than issuing an unbounded session. Direct adapters can pass the lifetime as the fourth
argument to `Session.start/4`. Expiration is fixed at sign-in; activity does not renew it.
Existing grants retain their issued expiration. Applications must configure their browser
cookie persistence and local account-token lifetime to match; this package does not own
those policies.

Build the native verifier from the same immutable MetaMesh revision:

```sh
cargo build --locked --release --package meta-mesh-core --bin verify_service_login
```

Set `:verifier_path` to `target/release/verify_service_login`. The binary uses
`meta_mesh_core::service_login::verify_service_login`; this package does not implement
cryptography. The challenge registry is bounded to 10,000 live challenges and is in-memory.
Process restart invalidates pending challenges. Multi-node deployments must route a login's
challenge and exchange to the same node; cross-node replication is intentionally not provided.
