import { Badge } from "@/components/ui/badge"

const statusStyles: Record<string, string> = {
  running: "bg-emerald-50 text-emerald-700 border-emerald-200",
  warm: "bg-amber-50 text-amber-700 border-amber-200",
  provisioning: "bg-amber-50 text-amber-700 border-amber-200",
  unhealthy: "bg-rose-50 text-rose-700 border-rose-200",
  destroying: "bg-zinc-100 text-zinc-500 border-zinc-200",
  destroyed: "bg-zinc-100 text-zinc-500 border-zinc-200",
  stopped: "bg-zinc-100 text-zinc-500 border-zinc-200",
  replacing: "bg-amber-50 text-amber-700 border-amber-200",
}

export function AgentStatusBadge({ status }: { status: string }) {
  return (
    <Badge variant="outline" className={statusStyles[status] ?? "bg-zinc-100 text-zinc-500 border-zinc-200"}>
      {status}
    </Badge>
  )
}

export function AgentStatusDot({ status }: { status: string }) {
  const dotColors: Record<string, string> = {
    running: "bg-emerald-500",
    warm: "bg-amber-500",
    provisioning: "bg-amber-500",
    unhealthy: "bg-rose-500",
    destroying: "bg-zinc-400",
    destroyed: "bg-zinc-400",
    stopped: "bg-zinc-400",
    replacing: "bg-amber-500",
  }

  const isRunning = status === "running"

  return (
    <span className="relative flex h-2.5 w-2.5">
      {isRunning && (
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
      )}
      <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${dotColors[status] ?? "bg-zinc-400"}`} />
    </span>
  )
}
