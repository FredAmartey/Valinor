import Link from "next/link"
import { UserTable } from "@/components/users/user-table"
import { Plus } from "@phosphor-icons/react/dist/ssr"

export default function UsersPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Users</h1>
          <p className="mt-1 text-sm text-zinc-500">Manage users in your organization.</p>
        </div>
        <Link
          href="/users/new"
          className="flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98]"
        >
          <Plus size={16} />
          Create user
        </Link>
      </div>
      <UserTable />
    </div>
  )
}
