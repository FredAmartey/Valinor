import { UserDetail } from "@/components/users/user-detail"
import { auth } from "@/lib/auth"

export default async function UserDetailPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params
  const session = await auth()
  const tenantId = session?.user?.tenantId ?? ""

  return <UserDetail id={id} tenantId={tenantId} />
}
