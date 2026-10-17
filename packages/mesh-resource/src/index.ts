export { ResourceClient, type ConnectResourceOptions } from "./client"
export { ResourceProvider } from "./provider"
export { RESOURCE_SIGNATURE_DOMAIN, MAX_GRANT_DURATION_MS } from "./protocol"
export type { ResourceDescriptor, ResourceRegistration, ResourceGrant, ResourceOperationProof,
  ApprovalRequest, AccessDecision, ConnectionResult, Authorization, AuthorizeInput,
  ResourceState, ResourceStore, ResourceConnectionStore, ResourceConnectionTransport,
  ResourceConnectionMessage, ResourceConnectionResponse, PendingConnection } from "./protocol"
export { createHttpResourceTransport, createResourceConnectionHandler } from "./http"
