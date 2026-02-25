import { auth } from "@/lib/auth"
import { Sidebar } from "@/components/nav/sidebar"
import { TopBar } from "@/components/nav/top-bar"
import { MobileSidebar } from "@/components/nav/mobile-sidebar"
import { PermissionProvider } from "@/components/providers/permission-provider"

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const session = await auth()
  const roles = session?.user?.roles ?? []
  const isPlatformAdmin = session?.user?.isPlatformAdmin ?? false

  return (
    <PermissionProvider roles={roles} isPlatformAdmin={isPlatformAdmin}>
      <div className="flex min-h-[100dvh]">
        <div className="hidden lg:block">
          <Sidebar />
        </div>
        <div className="flex flex-1 flex-col">
          <header className="flex h-14 items-center gap-3 border-b border-zinc-200 bg-white px-4 lg:px-6">
            <MobileSidebar />
            <TopBar />
          </header>
          <main className="flex-1 px-4 py-6 lg:px-8">
            <div className="mx-auto max-w-[1400px]">{children}</div>
          </main>
        </div>
      </div>
    </PermissionProvider>
  )
}
