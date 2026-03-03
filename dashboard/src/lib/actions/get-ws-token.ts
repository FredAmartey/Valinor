"use server"

import { getAccessToken } from "@/lib/auth"

/**
 * Server action that returns the access token for WebSocket connections.
 * The token lives only in the server-side JWT and is never exposed on
 * the client session object. This action is the single, auditable point
 * where the client can request the token for the WS handshake.
 */
export async function getWsToken(): Promise<string | null> {
  return getAccessToken()
}
