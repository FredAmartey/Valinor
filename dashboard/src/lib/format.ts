export function formatDate(dateStr: string, style: "short" | "long" = "short"): string {
  return new Date(dateStr).toLocaleDateString("en-US", {
    month: style === "long" ? "long" : "short",
    day: "numeric",
    year: "numeric",
  })
}
