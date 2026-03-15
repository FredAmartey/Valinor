function readString(metadata: Record<string, unknown> | null | undefined, key: string) {
  const value = metadata?.[key]
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null
}

export function connectorGovernanceLabels(metadata: Record<string, unknown> | null | undefined) {
  const labels: string[] = []

  const connectorName = readString(metadata, "connector_name")
  if (connectorName) {
    labels.push(`Connector ${connectorName}`)
  }

  const toolName = readString(metadata, "tool_name")
  if (toolName) {
    labels.push(`Tool ${toolName}`)
  }

  const governedActionID = readString(metadata, "governed_action_id")
  if (governedActionID) {
    labels.push(`Action ${governedActionID.slice(0, 8)}`)
  }

  return labels
}
