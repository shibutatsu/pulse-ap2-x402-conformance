#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import process from "node:process";
import { Command } from "commander";
import { verifyConformanceBundle } from "./verifier.js";

const program = new Command()
  .name("pulse-ap2-x402-verify")
  .description("Verify an AP2–x402 conformance fixture bundle without network access")
  .argument("<bundle>", "path to a conformance bundle JSON file")
  .option("--json", "print the complete machine-readable verification report")
  .parse();

const [bundlePath] = program.args as [string];
const options = program.opts<{ json?: boolean }>();

try {
  const raw = await readFile(bundlePath, "utf8");
  const report = await verifyConformanceBundle(JSON.parse(raw) as unknown);
  if (options.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    process.stdout.write(
      `Verified ${report.total} cases: ${report.passedExpectations} expected decisions matched, ${report.failedExpectations} differed.\n`,
    );
    for (const item of report.cases.filter((entry) => !entry.expectationMatched)) {
      const codes = item.report.failures.map((failure) => failure.code).join(", ") || "none";
      process.stdout.write(
        `- ${item.id ?? "<unknown>"}: consistent=${item.report.consistent}, codes=${codes}\n`,
      );
    }
  }
  process.exitCode = report.allExpectationsMatched ? 0 : 1;
} catch (error) {
  const message = error instanceof Error ? error.message : "Unknown verification error";
  process.stderr.write(`Unable to verify bundle: ${message}\n`);
  process.exitCode = 2;
}
