import type { ApiErrorResponse } from "@/lib/types"

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: ApiErrorResponse,
  ) {
    super(`API error ${status}: ${body.error}`)
    this.name = "ApiError"
  }
}
