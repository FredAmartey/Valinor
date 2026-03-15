import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ApprovalsQueue } from "./approvals-queue";

vi.mock("@/lib/queries/approvals", () => ({
  useApprovalsQuery: vi.fn(),
  useApproveRequestMutation: vi.fn(),
  useDenyRequestMutation: vi.fn(),
}));

vi.mock("@/components/providers/permission-provider", () => ({
  useCan: vi.fn(),
}));

describe("ApprovalsQueue", () => {
  beforeEach(async () => {
    const {
      useApprovalsQuery,
      useApproveRequestMutation,
      useDenyRequestMutation,
    } = await import("@/lib/queries/approvals");
    const { useCan } = await import("@/components/providers/permission-provider");

    vi.mocked(useApprovalsQuery).mockReturnValue({
      data: {
        approvals: [
          {
            id: "approval-1",
            tenant_id: "tenant-1",
            agent_id: "agent-1",
            requested_by: "user-1",
            reviewed_by: null,
            channel_outbox_id: null,
            risk_class: "external_writes",
            status: "pending",
            target_type: "crm_record",
            target_label: "Contact 123",
            action_summary: "Update CRM contact",
            metadata: {
              connector_name: "crm-api",
              tool_name: "update_contact",
              governed_action_id: "7aa0f9b1-5a40-4f0f-8b6f-e66009fa2cf8",
            },
            created_at: "2026-03-14T18:00:00Z",
            reviewed_at: null,
            expires_at: null,
          },
        ],
        count: 1,
      },
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    } as never);
    vi.mocked(useApproveRequestMutation).mockReturnValue({
      mutate: vi.fn(),
      isPending: false,
    } as never);
    vi.mocked(useDenyRequestMutation).mockReturnValue({
      mutate: vi.fn(),
      isPending: false,
    } as never);
    vi.mocked(useCan).mockReturnValue(true as never);
  });

  it("shows connector governance details for approval requests", () => {
    render(<ApprovalsQueue />);

    expect(screen.getByText("Connector crm-api")).toBeInTheDocument();
    expect(screen.getByText("Tool update_contact")).toBeInTheDocument();
    expect(screen.getByText("Action 7aa0f9b1")).toBeInTheDocument();
  });
});
