import { test, expect } from "@playwright/test"

test("login page renders", async ({ page }) => {
  await page.goto("/login")
  await expect(page.getByText("Valinor Dashboard")).toBeVisible()
  await expect(page.getByText("Sign in with SSO")).toBeVisible()
})

test("unauthenticated redirect", async ({ page }) => {
  await page.goto("/")
  await expect(page).toHaveURL(/\/login/)
})
