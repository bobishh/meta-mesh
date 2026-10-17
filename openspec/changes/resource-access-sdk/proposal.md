## Why

Applications need one resource connection protocol for an independent service identity, explicit owner consent and scoped operation authorization. Board membership and service login must not silently become universal service permissions.

## What Changes

- Add `@meta-uber/mesh-resource`: provider `addResource`, client `connectResource`, durable pending approval and subject-bound invitation redemption.
- Validate the same signed wire protocol in native `meta_mesh_core::resource_access` and policy WASM.
- Expose HTTP JSON transport/handler without embedding a product UI, database or board schema.
- Keep issuer, subject, resource, audience, capabilities, expiry, epoch and replay protection explicit.
- Preserve existing identities. Never export root private keys or infer encryption scope from a grant.

## Capabilities

### New Capabilities
- `resource-access`: shared resource connection and operation capabilities.

### Modified Capabilities
None.

## Impact

New SDK package and native-core module; one policy WASM facade and generated browser artifacts. Existing workspace roles and grants retain their wire format. Applications adopt the resource SDK explicitly; this does not silently replace existing service permissions or encryption arrangements.
