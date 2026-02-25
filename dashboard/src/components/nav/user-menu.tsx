"use client"

import { useSession, signOut } from "next-auth/react"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { SignOut } from "@phosphor-icons/react"

function getInitials(name: string): string {
  return name
    .split(" ")
    .map((n) => n[0])
    .join("")
    .toUpperCase()
    .slice(0, 2)
}

export function UserMenu() {
  const { data: session } = useSession()
  if (!session?.user) return null

  const { name, email, isPlatformAdmin } = session.user

  return (
    <DropdownMenu>
      <DropdownMenuTrigger className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-zinc-50 transition-colors outline-none">
        <Avatar className="h-7 w-7">
          <AvatarFallback className="bg-zinc-200 text-zinc-700 text-xs font-medium">
            {getInitials(name ?? email ?? "?")}
          </AvatarFallback>
        </Avatar>
        <span className="text-sm font-medium text-zinc-700 hidden md:inline">
          {name ?? email}
        </span>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <div className="px-2 py-1.5">
          <p className="text-sm font-medium text-zinc-900">{name}</p>
          <p className="text-xs text-zinc-500">{email}</p>
          {isPlatformAdmin && (
            <Badge variant="secondary" className="mt-1 text-xs">Platform Admin</Badge>
          )}
        </div>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onClick={() => signOut({ callbackUrl: "/login" })}
          className="text-zinc-600"
        >
          <SignOut size={16} className="mr-2" />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
