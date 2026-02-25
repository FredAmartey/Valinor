"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { useCreateDepartmentMutation, useDepartmentsQuery } from "@/lib/queries/departments"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export function CreateDepartmentForm() {
  const router = useRouter()
  const mutation = useCreateDepartmentMutation()
  const { data: departments } = useDepartmentsQuery()
  const [name, setName] = useState("")
  const [parentId, setParentId] = useState("")

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    mutation.mutate(
      { name, parent_id: parentId || undefined },
      { onSuccess: (dept) => router.push(`/departments/${dept.id}`) },
    )
  }

  return (
    <form onSubmit={handleSubmit} className="max-w-lg space-y-6">
      <div className="space-y-2">
        <Label htmlFor="name">Name</Label>
        <Input
          id="name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. Scouting"
          required
          maxLength={255}
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="parent">Parent Department</Label>
        <select
          id="parent"
          className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
          value={parentId}
          onChange={(e) => setParentId(e.target.value)}
        >
          <option value="">None (top-level)</option>
          {departments?.map((d) => (
            <option key={d.id} value={d.id}>{d.name}</option>
          ))}
        </select>
        <p className="text-xs text-zinc-400">Optional. Nest this department under a parent.</p>
      </div>

      {mutation.isError && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
          <p className="text-sm text-rose-700">Failed to create department.</p>
        </div>
      )}

      <button
        type="submit"
        disabled={mutation.isPending || !name}
        className="rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {mutation.isPending ? "Creating..." : "Create department"}
      </button>
    </form>
  )
}
