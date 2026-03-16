import { getAccessToken } from "@/lib/auth"
import { ApiError } from "@/lib/api-error"
import type { ApiErrorResponse } from "@/lib/types"

export { ApiError }

const API_BASE_URL = process.env.HEIMDALL_API_URL ?? "http://localhost:8080"

export function buildUrl(path: string, params?: Record<string, string>): string {
  const url = new URL(path, API_BASE_URL)
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== "") {
        url.searchParams.set(key, value)
      }
    }
  }
  return url.toString()
}

/**
 * Server-side API client. Used in Server Components and Server Actions.
 * Gets access token from the JWT automatically.
 */
export async function api<T>(
  path: string,
  options?: RequestInit & { params?: Record<string, string> },
): Promise<T> {
  const accessToken = await getAccessToken()
  const { params, ...fetchOptions } = options ?? {}
  const url = buildUrl(path, params)

  const res = await fetch(url, {
    ...fetchOptions,
    headers: {
      "Content-Type": "application/json",
      ...(accessToken
        ? { Authorization: `Bearer ${accessToken}` }
        : process.env.HEIMDALL_DEV_TOKEN
          ? { Authorization: `Bearer ${process.env.HEIMDALL_DEV_TOKEN}` }
          : {}),
      ...fetchOptions.headers,
    },
  })

  if (!res.ok) {
    let body: ApiErrorResponse
    try {
      body = await res.json()
    } catch {
      body = { error: res.statusText }
    }
    throw new ApiError(res.status, body)
  }

  // Handle 204 No Content
  if (res.status === 204) {
    return undefined as T
  }

  return res.json()
}
