"use client"

import { useState, useEffect } from "react"
import { useUpdateRoleMutation, useDeleteRoleMutation } from "@/lib/queries/roles"
import { PermissionMatrix } from "./permission-matrix"
import { FloppyDisk, Trash } from "@phosphor-icons/react"
import type { Role } from "@/lib/types"

interface RoleDetailProps {
  role: Role
  onDeleted: () => void
}

export function RoleDetail({ role, onDeleted }: RoleDetailProps) {
  const [permissions, setPermissions] = useState<string[]>(role.permissions)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const updateMutation = useUpdateRoleMutation()
  const deleteMutation = useDeleteRoleMutation()

  const isDirty = JSON.stringify([...permissions].sort()) !== JSON.stringify([...role.permissions].sort())
  const isSystem = role.is_system
  const isWildcard = role.permissions.includes("*")

  useEffect(() => {
    setPermissions(role.permissions)
    setShowDeleteConfirm(false)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset on role change, not on every permissions reference
  }, [role.id])

  function handleSave() {
    updateMutation.mutate(
      { roleId: role.id, data: { name: role.name, permissions } },
    )
  }

  function handleDelete() {
    deleteMutation.mutate(role.id, {
      onSuccess: () => onDeleted(),
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-zinc-900">{role.name}</h2>
          <p className="text-xs text-zinc-400">
            Created {new Date(role.created_at).toLocaleDateString()}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {!isSystem && (
            <>
              {isDirty && (
                <button
                  onClick={handleSave}
                  disabled={updateMutation.isPending}
                  className="flex items-center gap-1.5 rounded-lg bg-zinc-900 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 disabled:opacity-50"
                >
                  <FloppyDisk size={14} />
                  {updateMutation.isPending ? "Saving\u2026" : "Save"}
                </button>
              )}
              <button
                onClick={() => setShowDeleteConfirm(true)}
                disabled={deleteMutation.isPending}
                className="flex items-center gap-1.5 rounded-lg border border-red-200 px-3 py-1.5 text-sm font-medium text-red-600 transition-colors hover:bg-red-50 disabled:opacity-50"
              >
                <Trash size={14} />
                Delete
              </button>
            </>
          )}
        </div>
      </div>

      {isSystem && (
        <div className="rounded-lg border border-zinc-200 bg-zinc-50 px-4 py-3 text-sm text-zinc-600">
          System role — permissions are read-only.
        </div>
      )}

      {isWildcard ? (
        <div className="rounded-lg border border-zinc-200 bg-zinc-50 px-4 py-3 text-sm text-zinc-600">
          This role has wildcard access — all permissions are granted.
        </div>
      ) : (
        <PermissionMatrix
          permissions={permissions}
          readonly={isSystem}
          onChange={setPermissions}
        />
      )}

      {updateMutation.isError && (
        <p className="text-sm text-red-600">
          Failed to update: {(updateMutation.error as Error).message}
        </p>
      )}

      {showDeleteConfirm && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4">
          <p className="text-sm text-red-800">
            Delete role <strong>{role.name}</strong>? This cannot be undone.
            The role must not be assigned to any users.
          </p>
          <div className="mt-3 flex gap-2">
            <button
              onClick={handleDelete}
              disabled={deleteMutation.isPending}
              className="rounded-lg bg-red-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
            >
              {deleteMutation.isPending ? "Deleting\u2026" : "Confirm delete"}
            </button>
            <button
              onClick={() => setShowDeleteConfirm(false)}
              className="rounded-lg border border-zinc-200 px-3 py-1.5 text-sm text-zinc-600 hover:bg-zinc-50"
            >
              Cancel
            </button>
          </div>
          {deleteMutation.isError && (
            <p className="mt-2 text-sm text-red-600">
              {(deleteMutation.error as Error).message}
            </p>
          )}
        </div>
      )}
    </div>
  )
}
