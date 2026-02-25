import { signIn } from "@/lib/auth"

export default function LoginPage() {
  return (
    <div className="flex min-h-[100dvh] items-center justify-center bg-zinc-50">
      <div className="w-full max-w-sm space-y-6 text-center">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
            Valinor Dashboard
          </h1>
          <p className="mt-2 text-sm text-zinc-500">
            Sign in to manage your AI agent infrastructure.
          </p>
        </div>
        <form
          action={async () => {
            "use server"
            await signIn("valinor", { redirectTo: "/" })
          }}
        >
          <button
            type="submit"
            className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98]"
          >
            Sign in with SSO
          </button>
        </form>
      </div>
    </div>
  )
}
