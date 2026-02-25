import { CreateTenantForm } from "@/components/tenants/create-tenant-form"

export default function NewTenantPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
          Create Tenant
        </h1>
        <p className="mt-1 text-sm text-zinc-500">
          Provision a new organization on the platform.
        </p>
      </div>
      <CreateTenantForm />
    </div>
  )
}
