import { auth } from "@/lib/auth";
import { hasPermission } from "@/lib/permissions";
import { ApprovalsQueue } from "@/components/approvals/approvals-queue";
import { HandPalm } from "@phosphor-icons/react/dist/ssr";

export default async function TenantApprovalsPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
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
          You do not have permission to view tenant approvals.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <HandPalm size={24} className="text-zinc-400" />
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
            Approvals
          </h1>
          <p className="mt-1 text-sm text-zinc-500">
            Review this tenant’s pending and recently resolved approval
            requests.
          </p>
        </div>
      </div>
      <ApprovalsQueue tenantId={id} />
    </div>
  );
}
