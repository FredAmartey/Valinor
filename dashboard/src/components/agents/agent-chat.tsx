"use client"

import { useState, useRef, useEffect } from "react"
import { useAgentWebSocket } from "@/hooks/use-agent-websocket"
import {
  PaperPlaneRight,
  CircleNotch,
  Wrench,
  Warning,
  ShieldWarning,
} from "@phosphor-icons/react"
import type { ChatMessage } from "@/lib/types"

function StatusDot({ status }: { status: string }) {
  const color =
    status === "connected"
      ? "bg-emerald-500"
      : status === "connecting"
        ? "bg-amber-500 animate-pulse"
        : "bg-zinc-400"
  return <span className={`inline-block h-2 w-2 rounded-full ${color}`} />
}

function MessageBubble({ msg }: { msg: ChatMessage }) {
  if (msg.type === "user") {
    return (
      <div className="flex justify-end">
        <div className="max-w-[75%] rounded-xl rounded-br-sm bg-zinc-900 px-3 py-2 text-sm text-white">
          {msg.content}
        </div>
      </div>
    )
  }

  if (msg.type === "assistant") {
    return (
      <div className="flex justify-start">
        <div className="max-w-[75%] rounded-xl rounded-bl-sm bg-zinc-100 px-3 py-2 text-sm text-zinc-900">
          {msg.content}
          {msg.streaming && (
            <span className="ml-1 inline-block h-3 w-1 animate-pulse rounded-full bg-zinc-400" />
          )}
        </div>
      </div>
    )
  }

  if (msg.type === "tool") {
    return (
      <div className="flex justify-center">
        <div className="flex items-center gap-1.5 rounded-full border border-zinc-200 bg-zinc-50 px-3 py-1 text-xs text-zinc-500">
          <Wrench size={12} />
          {msg.content}
        </div>
      </div>
    )
  }

  if (msg.type === "error") {
    return (
      <div className="flex justify-center">
        <div className="flex items-center gap-1.5 rounded-lg border border-rose-200 bg-rose-50 px-3 py-1.5 text-xs text-rose-600">
          <Warning size={12} />
          {msg.content}
        </div>
      </div>
    )
  }

  if (msg.type === "halt") {
    return (
      <div className="flex justify-center">
        <div className="flex items-center gap-1.5 rounded-lg border border-amber-200 bg-amber-50 px-3 py-1.5 text-xs text-amber-700">
          <ShieldWarning size={12} />
          {msg.content}
        </div>
      </div>
    )
  }

  return null
}

export function AgentChat({
  agentId,
  agentStatus,
}: {
  agentId: string
  agentStatus: string
}) {
  const enabled = agentStatus === "running"
  const { messages, sendMessage, status, error } = useAgentWebSocket(
    agentId,
    enabled,
  )
  const [input, setInput] = useState("")
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    scrollRef.current?.scrollTo({
      top: scrollRef.current.scrollHeight,
      behavior: "smooth",
    })
  }, [messages])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const trimmed = input.trim()
    if (!trimmed) return
    sendMessage(trimmed)
    setInput("")
  }

  if (!enabled) {
    return (
      <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-6 text-center">
        <p className="text-sm text-zinc-500">
          Agent must be running to use the debug console.
        </p>
      </div>
    )
  }

  return (
    <div
      className="flex flex-col rounded-xl border border-zinc-200 bg-white"
      style={{ height: "480px" }}
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-zinc-100 px-4 py-2">
        <h3 className="text-sm font-medium text-zinc-900">Debug Console</h3>
        <div className="flex items-center gap-2 text-xs text-zinc-500">
          <StatusDot status={status} />
          {status === "connecting"
            ? "Connecting..."
            : status === "connected"
              ? "Connected"
              : "Disconnected"}
        </div>
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto p-4">
        {messages.length === 0 && status === "connected" && (
          <p className="pt-8 text-center text-sm text-zinc-400">
            Send a message to test this agent.
          </p>
        )}
        {messages.map((msg) => (
          <MessageBubble key={msg.id} msg={msg} />
        ))}
      </div>

      {/* Error bar */}
      {error && (
        <div className="border-t border-rose-100 bg-rose-50 px-4 py-2 text-xs text-rose-600">
          {error}
        </div>
      )}

      {/* Input */}
      <form
        onSubmit={handleSubmit}
        className="flex items-center gap-2 border-t border-zinc-100 p-3"
      >
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          disabled={status !== "connected"}
          placeholder={
            status === "connected" ? "Type a message..." : "Connecting..."
          }
          className="flex-1 rounded-lg border border-zinc-200 px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={status !== "connected" || !input.trim()}
          className="rounded-lg bg-zinc-900 p-2 text-white transition-colors active:scale-[0.98] disabled:opacity-50 hover:bg-zinc-800"
        >
          {status === "connecting" ? (
            <CircleNotch size={16} className="animate-spin" />
          ) : (
            <PaperPlaneRight size={16} />
          )}
        </button>
      </form>
    </div>
  )
}
