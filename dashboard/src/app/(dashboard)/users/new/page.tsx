import { auth } from "@/lib/auth"
import { hasPermission } from "@/lib/permissions"
import { CreateUserForm } from "@/components/users/create-user-form"

export default async function NewUserPage() {
  const session = await auth()
  if (!hasPermission(session?.user?.isPlatformAdmin ?? false, session?.user?.roles ?? [], "users:write")) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-6 max-w-lg">
        <h2 className="text-sm font-semibold text-rose-800">Permission denied</h2>
        <p className="mt-1 text-sm text-rose-700">
          You need the <span className="font-mono">users:write</span> permission to create users.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Create User</h1>
        <p className="mt-1 text-sm text-zinc-500">Add a new user to your organization.</p>
      </div>
      <CreateUserForm />
    </div>
  )
}
