import { getAccessToken } from "@/lib/auth"
import { NextRequest, NextResponse } from "next/server"

const API_BASE_URL = process.env.VALINOR_API_URL ?? "http://localhost:8080"

/**
 * BFF proxy: forwards client-side API calls to the Go backend,
 * attaching the access token server-side so it never reaches the browser.
 */
async function proxy(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const accessToken = await getAccessToken()
  if (!accessToken) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 })
  }

  const { path } = await params
  const target = new URL(`/${path.join("/")}`, API_BASE_URL)
  req.nextUrl.searchParams.forEach((value, key) => {
    target.searchParams.set(key, value)
  })

  const headers = new Headers(req.headers)
  headers.set("Authorization", `Bearer ${accessToken}`)
  headers.delete("host")
  headers.delete("cookie")

  const res = await fetch(target.toString(), {
    method: req.method,
    headers,
    body: req.body,
    // @ts-expect-error -- Node fetch supports duplex for streaming bodies
    duplex: "half",
  })

  return new NextResponse(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: {
      "Content-Type": res.headers.get("Content-Type") ?? "application/json",
    },
  })
}

export const GET = proxy
export const POST = proxy
export const PUT = proxy
export const PATCH = proxy
export const DELETE = proxy
