"use client"

import { useState } from "react"
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet"
import { Sidebar } from "./sidebar"
import { List } from "@phosphor-icons/react"

export function MobileSidebar() {
  const [open, setOpen] = useState(false)

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <button
          className="flex h-9 w-9 items-center justify-center rounded-lg text-zinc-500 hover:bg-zinc-100 lg:hidden"
          aria-label="Open navigation"
        >
          <List size={20} />
        </button>
      </SheetTrigger>
      <SheetContent side="left" className="w-60 p-0">
        <Sidebar />
      </SheetContent>
    </Sheet>
  )
}
