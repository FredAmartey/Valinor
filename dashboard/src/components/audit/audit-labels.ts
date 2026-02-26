export interface ActionLabel {
  label: string
  category: "channel" | "user" | "agent" | "tenant" | "department" | "role"
}

const ACTION_LABELS: Record<string, ActionLabel> = {
  // Channel events
  "channel.message.accepted": { label: "Message Accepted", category: "channel" },
  "channel.message.duplicate": { label: "Message Duplicate", category: "channel" },
  "channel.message.replay_blocked": { label: "Replay Blocked", category: "channel" },
  "channel.webhook.ignored": { label: "Webhook Ignored", category: "channel" },
  "channel.webhook.rejected_signature": { label: "Signature Rejected", category: "channel" },
  "channel.action_denied_unverified": { label: "Denied (Unverified)", category: "channel" },
  "channel.action_executed": { label: "Action Executed", category: "channel" },
  "channel.action_denied_rbac": { label: "Denied (RBAC)", category: "channel" },
  "channel.action_denied_no_agent": { label: "Denied (No Agent)", category: "channel" },
  "channel.action_denied_sentinel": { label: "Denied (Sentinel)", category: "channel" },
  "channel.action_dispatch_failed": { label: "Dispatch Failed", category: "channel" },

  // User events
  "user.created": { label: "User Created", category: "user" },
  "user.updated": { label: "User Updated", category: "user" },
  "user.suspended": { label: "User Suspended", category: "user" },
  "user.reactivated": { label: "User Reactivated", category: "user" },

  // Agent events
  "agent.provisioned": { label: "Agent Provisioned", category: "agent" },
  "agent.updated": { label: "Agent Updated", category: "agent" },
  "agent.destroyed": { label: "Agent Destroyed", category: "agent" },

  // Tenant events
  "tenant.created": { label: "Tenant Created", category: "tenant" },
  "tenant.updated": { label: "Tenant Updated", category: "tenant" },
  "tenant.suspended": { label: "Tenant Suspended", category: "tenant" },

  // Department events
  "department.created": { label: "Department Created", category: "department" },
  "department.updated": { label: "Department Updated", category: "department" },
  "department.deleted": { label: "Department Deleted", category: "department" },

  // Role events
  "role.created": { label: "Role Created", category: "role" },
  "role.updated": { label: "Role Updated", category: "role" },
  "role.deleted": { label: "Role Deleted", category: "role" },
  "user_role.assigned": { label: "Role Assigned", category: "role" },
  "user_role.revoked": { label: "Role Revoked", category: "role" },
}

const CATEGORY_COLORS: Record<string, string> = {
  channel: "bg-blue-500",
  user: "bg-emerald-500",
  agent: "bg-amber-500",
  tenant: "bg-violet-500",
  department: "bg-cyan-500",
  role: "bg-rose-500",
}

export function getActionLabel(action: string): ActionLabel {
  return ACTION_LABELS[action] ?? { label: action, category: "channel" }
}

export function getCategoryColor(category: string): string {
  return CATEGORY_COLORS[category] ?? "bg-zinc-400"
}

export const SOURCE_LABELS: Record<string, string> = {
  api: "API",
  whatsapp: "WhatsApp",
  telegram: "Telegram",
  slack: "Slack",
  system: "System",
}

export const ACTION_CATEGORIES = [
  { value: "", label: "All actions" },
  { value: "channel", label: "Channel" },
  { value: "user", label: "User" },
  { value: "agent", label: "Agent" },
  { value: "tenant", label: "Tenant" },
  { value: "department", label: "Department" },
  { value: "role", label: "Role" },
] as const

export const RESOURCE_TYPES = [
  { value: "", label: "All resources" },
  { value: "user", label: "User" },
  { value: "agent", label: "Agent" },
  { value: "tenant", label: "Tenant" },
  { value: "department", label: "Department" },
  { value: "role", label: "Role" },
  { value: "connector", label: "Connector" },
] as const

export const SOURCES = [
  { value: "", label: "All sources" },
  { value: "api", label: "API" },
  { value: "whatsapp", label: "WhatsApp" },
  { value: "telegram", label: "Telegram" },
  { value: "slack", label: "Slack" },
  { value: "system", label: "System" },
] as const
