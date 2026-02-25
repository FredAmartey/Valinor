import { CreateUserForm } from "@/components/users/create-user-form"

export default function NewUserPage() {
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
