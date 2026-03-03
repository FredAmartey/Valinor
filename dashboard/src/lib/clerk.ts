import { Clerk } from "@clerk/clerk-js"

let clerkInstance: Clerk | null = null
let clerkPromise: Promise<Clerk> | null = null

const publishableKey = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY

export function getClerk(): Promise<Clerk> {
  if (!publishableKey) {
    return Promise.reject(new Error("NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY not set"))
  }

  if (clerkInstance?.loaded) {
    return Promise.resolve(clerkInstance)
  }

  if (clerkPromise) {
    return clerkPromise
  }

  clerkPromise = (async () => {
    const clerk = new Clerk(publishableKey)
    await clerk.load()
    clerkInstance = clerk
    return clerk
  })()

  return clerkPromise
}

export function getClerkSync(): Clerk | null {
  return clerkInstance
}
