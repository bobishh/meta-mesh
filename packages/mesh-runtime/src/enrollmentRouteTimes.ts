import { MAX_DEVICE_ROUTE_LIFETIME_MS } from "@meta-uber/mesh-replication"

export function enrollmentRouteTimestamps(issuedAtMs = Date.now()): { issuedAt: string; expiresAt: string } {
  return {
    issuedAt: new Date(issuedAtMs).toISOString(),
    expiresAt: new Date(issuedAtMs + MAX_DEVICE_ROUTE_LIFETIME_MS).toISOString(),
  }
}
