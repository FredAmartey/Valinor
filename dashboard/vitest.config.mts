import { defineConfig } from "vitest/config"
import react from "@vitejs/plugin-react"
import tsconfigPaths from "vite-tsconfig-paths"
import path from "path"

export default defineConfig({
  plugins: [tsconfigPaths(), react()],
  resolve: {
    alias: [
      {
        find: /^next\/server$/,
        replacement: path.resolve(import.meta.dirname, "src/__mocks__/next-server.ts"),
      },
    ],
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    server: {
      deps: {
        inline: ["next-auth"],
      },
    },
  },
})
