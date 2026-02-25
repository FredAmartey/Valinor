import { auth } from "@/lib/auth"
import type { ApiErrorResponse } from "@/lib/types"

const API_BASE_URL = process.env.VALINOR_API_URL ?? "http://localhost:8080"

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: ApiErrorResponse,
  ) {
    super(`API error ${status}: ${body.error}`)
    this.name = "ApiError"
  }
}

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
 * Gets access token from NextAuth session automatically.
 */
export async function api<T>(
  path: string,
  options?: RequestInit & { params?: Record<string, string> },
): Promise<T> {
  const session = await auth()
  const { params, ...fetchOptions } = options ?? {}
  const url = buildUrl(path, params)

  const res = await fetch(url, {
    ...fetchOptions,
    headers: {
      "Content-Type": "application/json",
      ...(session?.accessToken ? { Authorization: `Bearer ${session.accessToken}` } : {}),
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
