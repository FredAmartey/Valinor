import { test, expect } from "@playwright/test"

test.describe("Dashboard smoke tests", () => {
  test("login page renders with email input", async ({ page }) => {
    await page.goto("/login")
    await expect(page.getByText("Valinor Dashboard")).toBeVisible()
    await expect(page.getByLabel("Email")).toBeVisible()
    await expect(page.getByText("Sign in (Dev Mode)")).toBeVisible()
  })

  test("unauthenticated user is redirected to login", async ({ page }) => {
    await page.goto("/")
    await expect(page).toHaveURL(/login/)
  })
})
