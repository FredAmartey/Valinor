"use client"

import { useState, useEffect, useRef, useCallback } from "react"
import { useSession } from "next-auth/react"
import type { ChatMessage, WsServerMessage } from "@/lib/types"

type WsStatus = "connecting" | "connected" | "disconnected" | "error"

const WS_BASE_URL = (
  process.env.NEXT_PUBLIC_VALINOR_API_URL ?? "http://localhost:8080"
).replace(/^http/, "ws")

const MAX_RECONNECT_ATTEMPTS = 3
const RECONNECT_BASE_DELAY = 1000

export function useAgentWebSocket(agentId: string, enabled: boolean) {
  const { data: session } = useSession()
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [status, setStatus] = useState<WsStatus>("disconnected")
  const [error, setError] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectAttempts = useRef(0)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>(undefined)

  const connect = useCallback(() => {
    if (!session?.accessToken || !enabled) return

    const url = `${WS_BASE_URL}/api/v1/agents/${agentId}/ws?access_token=${session.accessToken}`
    const ws = new WebSocket(url)
    wsRef.current = ws
    setStatus("connecting")
    setError(null)

    ws.onopen = () => {
      setStatus("connected")
      reconnectAttempts.current = 0
    }

    ws.onmessage = (event) => {
      const msg: WsServerMessage = JSON.parse(event.data)
      setMessages((prev) => {
        switch (msg.type) {
          case "chunk": {
            if (msg.done) {
              return prev.map((m) =>
                m.requestId === msg.request_id &&
                m.type === "assistant" &&
                m.streaming
                  ? {
                      ...m,
                      content: m.content + (msg.content ?? ""),
                      streaming: false,
                    }
                  : m,
              )
            }
            const existing = prev.find(
              (m) =>
                m.requestId === msg.request_id &&
                m.type === "assistant" &&
                m.streaming,
            )
            if (existing) {
              return prev.map((m) =>
                m === existing
                  ? { ...m, content: m.content + (msg.content ?? "") }
                  : m,
              )
            }
            return [
              ...prev,
              {
                id: crypto.randomUUID(),
                type: "assistant",
                content: msg.content ?? "",
                requestId: msg.request_id,
                timestamp: Date.now(),
                streaming: true,
              },
            ]
          }

          case "tool_executed":
            return [
              ...prev,
              {
                id: crypto.randomUUID(),
                type: "tool",
                content: `Called \`${msg.tool_name}\``,
                toolName: msg.tool_name,
                requestId: msg.request_id,
                timestamp: Date.now(),
              },
            ]

          case "tool_failed":
            return [
              ...prev,
              {
                id: crypto.randomUUID(),
                type: "tool",
                content: `Tool \`${msg.tool_name}\` failed: ${msg.reason}`,
                toolName: msg.tool_name,
                reason: msg.reason,
                requestId: msg.request_id,
                timestamp: Date.now(),
              },
            ]

          case "tool_blocked":
            return [
              ...prev,
              {
                id: crypto.randomUUID(),
                type: "tool",
                content: `Tool \`${msg.tool_name}\` blocked: ${msg.reason}`,
                toolName: msg.tool_name,
                reason: msg.reason,
                requestId: msg.request_id,
                timestamp: Date.now(),
              },
            ]

          case "error":
            return [
              ...prev,
              {
                id: crypto.randomUUID(),
                type: "error",
                content: msg.message ?? "Unknown error",
                requestId: msg.request_id,
                timestamp: Date.now(),
              },
            ]

          case "session_halt":
            return [
              ...prev,
              {
                id: crypto.randomUUID(),
                type: "halt",
                content: `Session halted: ${msg.reason}`,
                reason: msg.reason,
                requestId: msg.request_id,
                timestamp: Date.now(),
              },
            ]

          default:
            return prev
        }
      })
    }

    ws.onerror = () => {
      setError("WebSocket connection error")
      setStatus("error")
    }

    ws.onclose = (event) => {
      wsRef.current = null
      if (event.code === 1000 || event.code === 1001) {
        setStatus("disconnected")
        return
      }
      // Unexpected close — attempt reconnect with exponential backoff
      if (reconnectAttempts.current < MAX_RECONNECT_ATTEMPTS) {
        const delay =
          RECONNECT_BASE_DELAY * Math.pow(2, reconnectAttempts.current)
        reconnectAttempts.current++
        setStatus("connecting")
        reconnectTimer.current = setTimeout(connect, delay)
      } else {
        setStatus("error")
        setError("Connection lost. Refresh to retry.")
      }
    }
  }, [agentId, enabled, session?.accessToken])

  useEffect(() => {
    connect()
    return () => {
      clearTimeout(reconnectTimer.current)
      wsRef.current?.close(1000, "component unmounted")
      wsRef.current = null
    }
  }, [connect])

  const sendMessage = useCallback((content: string) => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return
    setMessages((prev) => [
      ...prev,
      {
        id: crypto.randomUUID(),
        type: "user",
        content,
        timestamp: Date.now(),
      },
    ])
    wsRef.current.send(JSON.stringify({ type: "message", content }))
  }, [])

  return { messages, sendMessage, status, error }
}
