import { ApiError } from "@/lib/api-error"
import type { ApiErrorResponse } from "@/lib/types"

const API_BASE_URL = process.env.NEXT_PUBLIC_VALINOR_API_URL ?? "http://localhost:8080"

/**
 * Client-side API function. Used in "use client" components via TanStack Query.
 * Caller must pass the access token (from useSession).
 */
export async function apiClient<T>(
  path: string,
  accessToken: string,
  options?: RequestInit & { params?: Record<string, string> },
): Promise<T> {
  const { params, ...fetchOptions } = options ?? {}

  const url = new URL(path, API_BASE_URL)
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
      Authorization: `Bearer ${accessToken}`,
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
