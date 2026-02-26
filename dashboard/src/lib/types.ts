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
  tenant_id: string | null
  user_id: string | null
  department_id: string | null
  vm_id: string | null
  connection_id: string
  status: "warm" | "provisioning" | "running" | "unhealthy" | "destroying" | "destroyed"
  config: string | Record<string, unknown>
  vsock_cid: number | null
  vm_driver: string
  tool_allowlist: string | string[]
  consecutive_failures: number
  created_at: string
  last_health_check: string | null
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
  created_at: string
}

export interface AuditListResponse {
  events: AuditEvent[]
  count: number
}

export interface AuditFilters {
  action?: string
  resource_type?: string
  user_id?: string
  source?: string
  after?: string
  before?: string
  limit?: string
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

// Role types — matches Go internal/tenant/role_handler.go responses
export interface Role {
  id: string
  tenant_id: string
  name: string
  permissions: string[]
  is_system: boolean
  created_at: string
}

export interface UserRole {
  user_id: string
  role_id: string
  role_name: string
  scope_type: "org" | "department"
  scope_id: string
}

export interface CreateUserRequest {
  email: string
  display_name?: string
}

export interface CreateDepartmentRequest {
  name: string
  parent_id?: string
}

export interface AssignRoleRequest {
  role_id: string
  scope_type: "org" | "department"
  scope_id: string
}

export interface UpdateRoleRequest {
  name: string
  permissions: string[]
}

// Agent request types — matches Go internal/orchestrator/handler.go
export interface ProvisionAgentRequest {
  user_id?: string
  department_id?: string
  config?: Record<string, unknown>
}

export interface ConfigureAgentRequest {
  config: Record<string, unknown>
  tool_allowlist: string[]
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
