import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AgentActivityTimeline } from "./agent-activity-timeline";

vi.mock("@/lib/queries/activity", () => ({
  useAgentActivityQuery: vi.fn(),
}));

describe("AgentActivityTimeline", () => {
  beforeEach(async () => {
    const { useAgentActivityQuery } = await import("@/lib/queries/activity");
    vi.mocked(useAgentActivityQuery).mockReturnValue({
      data: {
        events: [
          {
            id: "evt-1",
            tenant_id: "tenant-1",
            agent_id: "agent-1",
            user_id: null,
            department_id: null,
            session_id: "session-1",
            correlation_id: "corr-1",
            approval_id: "approval-1",
            connector_id: "connector-1",
            channel_message_id: null,
            kind: "approval.requested",
            status: "approval_required",
            risk_class: "external_writes",
            source: "agent",
            provenance: "runtime_vsock",
            internal_event_type: "connector.approval_requested",
            binding: "vsock",
            delivery_target: "Contact 123",
            runtime_source: "openclaw",
            title: "Approval requested",
            summary: "Update CRM contact",
            actor_label: "",
            target_label: "Contact 123",
            sensitive_content_ref: null,
            metadata: {
              connector_name: "crm-api",
              tool_name: "update_contact",
              governed_action_id: "7aa0f9b1-5a40-4f0f-8b6f-e66009fa2cf8",
            },
            occurred_at: "2026-03-14T18:00:00Z",
            completed_at: null,
            created_at: "2026-03-14T18:00:00Z",
          },
        ],
        count: 1,
      },
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
      isFetching: false,
    } as never);
  });

  it("surfaces governed connector context in the timeline", () => {
    render(<AgentActivityTimeline agentId="agent-1" />);

    expect(screen.getByText("Connector crm-api")).toBeInTheDocument();
    expect(screen.getByText("Tool update_contact")).toBeInTheDocument();
    expect(screen.getByText("Action 7aa0f9b1")).toBeInTheDocument();
  });
});
