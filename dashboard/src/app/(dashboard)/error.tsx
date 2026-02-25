"use client"

import { ArrowCounterClockwise } from "@phosphor-icons/react"

export default function DashboardError({
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <div className="flex min-h-[50vh] items-center justify-center">
      <div className="text-center space-y-4">
        <h2 className="text-lg font-semibold text-zinc-900">Something went wrong</h2>
        <p className="text-sm text-zinc-500 max-w-md">
          An unexpected error occurred. This has been logged for investigation.
        </p>
        <button
          onClick={reset}
          className="inline-flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98]"
        >
          <ArrowCounterClockwise size={16} />
          Try again
        </button>
      </div>
    </div>
  )
}
