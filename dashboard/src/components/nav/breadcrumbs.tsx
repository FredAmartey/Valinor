"use client"

import { usePathname } from "next/navigation"
import Link from "next/link"
import { CaretRight } from "@phosphor-icons/react"

function formatSegment(segment: string): string {
  return segment
    .replace(/-/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

export function Breadcrumbs() {
  const pathname = usePathname()
  const segments = pathname.split("/").filter(Boolean)

  if (segments.length === 0) return null

  return (
    <nav className="flex items-center gap-1.5 text-sm text-zinc-500">
      <Link href="/" className="hover:text-zinc-700 transition-colors">
        Home
      </Link>
      {segments.map((segment, index) => {
        const href = "/" + segments.slice(0, index + 1).join("/")
        const isLast = index === segments.length - 1
        return (
          <span key={href} className="flex items-center gap-1.5">
            <CaretRight size={12} className="text-zinc-400" />
            {isLast ? (
              <span className="text-zinc-900 font-medium">{formatSegment(segment)}</span>
            ) : (
              <Link href={href} className="hover:text-zinc-700 transition-colors">
                {formatSegment(segment)}
              </Link>
            )}
          </span>
        )
      })}
    </nav>
  )
}
