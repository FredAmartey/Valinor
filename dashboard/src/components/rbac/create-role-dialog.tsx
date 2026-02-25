"use client"

import { useState, useEffect, useRef, useCallback } from "react"
import { useCreateRoleMutation } from "@/lib/queries/roles"
import { PermissionMatrix } from "./permission-matrix"
import type { Role } from "@/lib/types"

interface CreateRoleDialogProps {
  open: boolean
  onClose: () => void
  onCreated: (role: Role) => void
}

export function CreateRoleDialog({ open, onClose, onCreated }: CreateRoleDialogProps) {
  const createMutation = useCreateRoleMutation()
  const [name, setName] = useState("")
  const [permissions, setPermissions] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const dialogRef = useRef<HTMLDivElement>(null)
  const nameInputRef = useRef<HTMLInputElement>(null)

  const handleClose = useCallback(() => {
    setName("")
    setPermissions([])
    setError(null)
    onClose()
  }, [onClose])

  // Focus the name input when dialog opens
  useEffect(() => {
    if (open) {
      nameInputRef.current?.focus()
    }
  }, [open])

  // Escape key to close
  useEffect(() => {
    if (!open) return
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        handleClose()
      }
    }
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [open, handleClose])

  if (!open) return null

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) {
      setError("Role name is required")
      return
    }
    setError(null)
    createMutation.mutate(
      { name: name.trim(), permissions },
      {
        onSuccess: (role) => {
          setName("")
          setPermissions([])
          onCreated(role)
        },
        onError: (err) => {
          setError((err as Error).message)
        },
      },
    )
  }

  function handleBackdropClick(e: React.MouseEvent) {
    if (e.target === e.currentTarget) {
      handleClose()
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      onClick={handleBackdropClick}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="create-role-title"
        className="w-full max-w-2xl rounded-xl bg-white p-6 shadow-xl"
      >
        <h2 id="create-role-title" className="text-lg font-semibold text-zinc-900">Create Role</h2>
        <form onSubmit={handleSubmit} className="mt-4 space-y-4">
          <div>
            <label htmlFor="role-name" className="block text-sm font-medium text-zinc-700">
              Name
            </label>
            <input
              ref={nameInputRef}
              id="role-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. analyst"
              className="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm focus:border-zinc-500 focus:outline-none focus:ring-1 focus:ring-zinc-500"
            />
          </div>
          <div>
            <p className="mb-2 text-sm font-medium text-zinc-700">Permissions</p>
            <PermissionMatrix permissions={permissions} readonly={false} onChange={setPermissions} />
          </div>
          {error && <p className="text-sm text-red-600">{error}</p>}
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={handleClose}
              className="rounded-lg border border-zinc-200 px-4 py-2 text-sm text-zinc-600 hover:bg-zinc-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 disabled:opacity-50"
            >
              {createMutation.isPending ? "Creating\u2026" : "Create role"}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
