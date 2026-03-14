import { auth } from "@/lib/auth";
import { hasPermission } from "@/lib/permissions";
import { SecurityEventsView } from "@/components/security/security-events-view";
import { ShieldWarning } from "@phosphor-icons/react/dist/ssr";

export default async function SecurityPage() {
  const session = await auth();
  const canRead = hasPermission(
    session?.user?.isPlatformAdmin ?? false,
    session?.user?.roles ?? [],
    "audit:read",
  );

  if (!canRead) {
    return (
      <div className="py-12 text-center">
        <p className="text-sm font-medium text-zinc-900">Access denied</p>
        <p className="mt-1 text-sm text-zinc-500">
          You do not have permission to view security events.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <ShieldWarning size={24} className="text-zinc-400" />
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
            Security Center
          </h1>
          <p className="mt-1 text-sm text-zinc-500">
            Inspect blocked prompts, halted sessions, and review-required
            activity.
          </p>
        </div>
      </div>
      <SecurityEventsView />
    </div>
  );
}
