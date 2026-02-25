import { Breadcrumbs } from "./breadcrumbs"
import { UserMenu } from "./user-menu"

export function TopBar() {
  return (
    <div className="flex flex-1 items-center justify-between">
      <Breadcrumbs />
      <UserMenu />
    </div>
  )
}
