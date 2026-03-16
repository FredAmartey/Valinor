"use client"

export function AuthCard({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-[100dvh] items-center justify-center bg-gradient-to-b from-zinc-950 to-zinc-900">
      <div className="w-full max-w-sm space-y-6 rounded-2xl bg-white p-8 shadow-2xl shadow-black/20">
        <div className="text-center">
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
            Heimdall
          </h1>
        </div>
        {children}
      </div>
    </div>
  )
}
