// Tenant types — matches Go internal/tenant/handler.go responses
export interface Tenant {
  id: string
  name: string
  slug: string
  status: "active" | "suspended" | "archived"
  settings: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface TenantCreateRequest {
  name: string
  slug: string
}

// User types — matches Go internal/tenant/user_handler.go responses
export interface User {
  id: string
  tenant_id: string
  email: string
  display_name: string
  oidc_subject: string
  oidc_issuer: string
  status: "active" | "suspended"
  is_platform_admin: boolean
  created_at: string
}

// Department types
export interface Department {
  id: string
  tenant_id: string
  name: string
  parent_id: string | null
  created_at: string
}

// Agent types — matches Go internal/orchestrator/handler.go responses
export interface AgentInstance {
  id: string
  tenant_id: string
  department_id: string | null
  user_id: string
  vm_id: string
  connection_id: string
  status: "provisioning" | "running" | "unhealthy" | "stopped" | "replacing"
  config: Record<string, unknown>
  vsock_cid: number
  tool_allowlist: string[]
  created_at: string
  last_health_check: string
}

// Audit types — matches Go internal/audit/handler.go responses
export interface AuditEvent {
  id: string
  tenant_id: string
  user_id: string | null
  action: string
  resource_type: string | null
  resource_id: string | null
  metadata: Record<string, unknown> | null
  source: string
  correlation_id: string
  created_at: string
}

// Connector types — matches Go internal/connectors/handler.go responses
export interface Connector {
  id: string
  tenant_id: string
  name: string
  connector_type: string
  endpoint: string
  resources: unknown[]
  tools: unknown[]
  status: "active" | "inactive"
  created_at: string
}

// Channel link types — matches Go internal/channels/handler.go responses
export interface ChannelLink {
  id: string
  tenant_id: string
  user_id: string
  platform: "slack" | "whatsapp" | "telegram"
  platform_user_id: string
  status: "pending_verification" | "verified" | "revoked"
  created_at: string
}

// API error shape
export interface ApiErrorResponse {
  error: string
  details?: Record<string, string>
}

// Paginated list wrapper (if API returns counts)
export interface ListResponse<T> {
  items: T[]
  total?: number
}

// Overview stats (aggregated on client from multiple endpoints)
export interface OverviewStats {
  tenantCount: number
  activeTenantCount: number
  agentCount: number
  unhealthyAgentCount: number
  userCount: number
  recentAuditEvents: AuditEvent[]
}
