"use client"

import { useState } from "react"
import { RoleList } from "./role-list"
import { RoleDetail } from "./role-detail"
import { CreateRoleDialog } from "./create-role-dialog"
import { Plus, ShieldCheck } from "@phosphor-icons/react"
import type { Role } from "@/lib/types"

export function RBACView() {
  const [selectedRole, setSelectedRole] = useState<Role | null>(null)
  const [showCreate, setShowCreate] = useState(false)

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-[320px_1fr]">
      {/* Left panel — role list */}
      <div className="rounded-xl border border-zinc-200 bg-white p-4">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-zinc-900">Roles</h2>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1 rounded-lg bg-zinc-900 px-2.5 py-1.5 text-xs font-medium text-white transition-colors hover:bg-zinc-800"
          >
            <Plus size={12} />
            Create
          </button>
        </div>
        <RoleList
          selectedId={selectedRole?.id ?? null}
          onSelect={setSelectedRole}
        />
      </div>

      {/* Right panel — role detail */}
      <div className="rounded-xl border border-zinc-200 bg-white p-6">
        {selectedRole ? (
          <RoleDetail
            role={selectedRole}
            onDeleted={() => setSelectedRole(null)}
          />
        ) : (
          <div className="flex flex-col items-center justify-center py-20 text-zinc-400">
            <ShieldCheck size={40} />
            <p className="mt-3 text-sm">Select a role to view permissions.</p>
          </div>
        )}
      </div>

      <CreateRoleDialog
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={(role) => {
          setShowCreate(false)
          setSelectedRole(role)
        }}
      />
    </div>
  )
}
