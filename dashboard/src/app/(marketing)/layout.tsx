import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Heimdall — Security, observability, and governance for AI agents",
  description:
    "Trust AI agents with real access using visibility, isolation, governance, and auditability built for teams and enterprises.",
};

export default function MarketingLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
}
