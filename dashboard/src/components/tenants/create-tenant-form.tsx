"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { useCreateTenantMutation } from "@/lib/queries/tenants"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
}

export function CreateTenantForm() {
  const router = useRouter()
  const mutation = useCreateTenantMutation()
  const [name, setName] = useState("")
  const [slug, setSlug] = useState("")
  const [slugManuallyEdited, setSlugManuallyEdited] = useState(false)

  function handleNameChange(value: string) {
    setName(value)
    if (!slugManuallyEdited) {
      setSlug(slugify(value))
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    mutation.mutate(
      { name, slug },
      { onSuccess: (tenant) => router.push(`/tenants/${tenant.id}`) },
    )
  }

  return (
    <form onSubmit={handleSubmit} className="max-w-lg space-y-6">
      <div className="space-y-2">
        <Label htmlFor="name">Name</Label>
        <Input
          id="name"
          value={name}
          onChange={(e) => handleNameChange(e.target.value)}
          placeholder="e.g. Chelsea FC"
          required
        />
        <p className="text-xs text-zinc-400">The display name for this tenant organization.</p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="slug">Slug</Label>
        <Input
          id="slug"
          value={slug}
          onChange={(e) => {
            setSlug(e.target.value)
            setSlugManuallyEdited(true)
          }}
          placeholder="e.g. chelsea-fc"
          required
          pattern="^[a-z0-9]+(-[a-z0-9]+)*$"
        />
        <p className="text-xs text-zinc-400">
          URL-safe identifier. Auto-generated from name, but you can customize it.
        </p>
      </div>

      {mutation.isError && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
          <p className="text-sm text-rose-700">
            Failed to create tenant. Please check the details and try again.
          </p>
        </div>
      )}

      <button
        type="submit"
        disabled={mutation.isPending || !name || !slug}
        className="rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {mutation.isPending ? "Creating..." : "Create tenant"}
      </button>
    </form>
  )
}
