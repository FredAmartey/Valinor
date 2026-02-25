import Link from "next/link"
import { TenantTable } from "@/components/tenants/tenant-table"

export default function TenantsPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
            Tenants
          </h1>
          <p className="mt-1 text-sm text-zinc-500">
            Manage organizations on the platform.
          </p>
        </div>
        <Link
          href="/tenants/new"
          className="flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98]"
        >
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 256 256"><path d="M224,128a8,8,0,0,1-8,8H136v80a8,8,0,0,1-16,0V136H40a8,8,0,0,1,0-16h80V40a8,8,0,0,1,16,0v80h80A8,8,0,0,1,224,128Z"/></svg>
          Create tenant
        </Link>
      </div>
      <TenantTable />
    </div>
  )
}
