import { RBACView } from "@/components/rbac/rbac-view"

export default function RBACPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">RBAC</h1>
        <p className="mt-1 text-sm text-zinc-500">Manage roles and permissions.</p>
      </div>
      <RBACView />
    </div>
  )
}
