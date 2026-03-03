import { ApiError } from "@/lib/api-error"
import type { ApiErrorResponse } from "@/lib/types"

/**
 * Client-side API function. Used in "use client" components via TanStack Query.
 * Calls the BFF proxy at /api/v/... which attaches the access token server-side.
 * No token needed from the caller.
 */
export async function apiClient<T>(
  path: string,
  options?: RequestInit & { params?: Record<string, string> },
): Promise<T> {
  const { params, ...fetchOptions } = options ?? {}

  const url = new URL(`/api/v${path}`, window.location.origin)
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== "") {
        url.searchParams.set(key, value)
      }
    }
  }

  const res = await fetch(url.toString(), {
    ...fetchOptions,
    headers: {
      "Content-Type": "application/json",
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

  if (res.status === 204) {
    return undefined as T
  }

  return res.json()
}
