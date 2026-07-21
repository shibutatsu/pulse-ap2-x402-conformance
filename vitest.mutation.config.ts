import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    include: ["test/**/*.test.ts"],
    minWorkers: 1,
    maxWorkers: 1,
    testTimeout: 10_000,
    hookTimeout: 10_000,
  },
});
