import { Badge } from "@/components/ui/badge"

const statusStyles = {
  active: "bg-emerald-50 text-emerald-700 border-emerald-200",
  suspended: "bg-amber-50 text-amber-700 border-amber-200",
  archived: "bg-zinc-100 text-zinc-500 border-zinc-200",
} as const

export function TenantStatusBadge({ status }: { status: "active" | "suspended" | "archived" }) {
  return (
    <Badge variant="outline" className={statusStyles[status]}>
      {status}
    </Badge>
  )
}
