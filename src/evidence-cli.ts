#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import process from "node:process";
import { Command, InvalidArgumentError } from "commander";
import { http, createPublicClient } from "viem";
import {
  type PublicEvmReader,
  selectPublicEvmCase,
  verifyIndependentReproductionRecord,
  verifyIndependentSecurityReviewRecord,
  verifyPublicEvmSettlement,
} from "./evidence.js";

function positiveInteger(value: string): bigint {
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new InvalidArgumentError("Expected a positive integer");
  }
  return BigInt(value);
}

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8")) as unknown;
}

const program = new Command()
  .name("pulse-ap2-x402-evidence")
  .description("Validate independent evidence and verify a public EVM settlement")
  .showHelpAfterError();

program
  .command("reproduction")
  .description("Validate an independent 80-case reproduction record")
  .argument("<bundle>", "path to a versioned fixture bundle")
  .argument("<record>", "path to the independent reproduction record")
  .action(async (bundlePath: string, recordPath: string) => {
    const [bundleRaw, record] = await Promise.all([
      readFile(bundlePath, "utf8"),
      readJson(recordPath),
    ]);
    const report = verifyIndependentReproductionRecord(bundleRaw, record);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (!report.automatedChecksPassed) process.exitCode = 1;
  });

program
  .command("review")
  .description("Validate an independent security review record")
  .argument("<record>", "path to the independent review record")
  .action(async (recordPath: string) => {
    const report = verifyIndependentSecurityReviewRecord(await readJson(recordPath));
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (!report.automatedChecksPassed) process.exitCode = 1;
  });

program
  .command("evm")
  .description("Verify an accepted case against a public EVM transaction receipt")
  .argument("<case-or-bundle>", "path to a standalone case or versioned fixture bundle")
  .requiredOption("--case <id>", "accepted fixture case id")
  .option("--min-confirmations <count>", "minimum block confirmations", positiveInteger, 1n)
  .option("--output <path>", "write the evidence record to this path")
  .action(
    async (
      bundlePath: string,
      options: { case: string; minConfirmations: bigint; output?: string },
    ) => {
      const rpcUrl = process.env.PULSE_EVM_RPC_URL;
      if (rpcUrl === undefined || rpcUrl.length === 0) {
        throw new Error("Set PULSE_EVM_RPC_URL to a read-only public EVM endpoint.");
      }
      const selectedCase = selectPublicEvmCase(await readJson(bundlePath), options.case);

      const client = createPublicClient({ transport: http(rpcUrl) });
      const evidence = await verifyPublicEvmSettlement(
        selectedCase,
        client as unknown as PublicEvmReader,
        options.minConfirmations,
      );
      const output = `${JSON.stringify(evidence, null, 2)}\n`;
      if (options.output === undefined) {
        process.stdout.write(output);
      } else {
        await writeFile(options.output, output, { encoding: "utf8", flag: "wx" });
        process.stdout.write(`Wrote verified public EVM evidence to ${options.output}.\n`);
      }
    },
  );

try {
  await program.parseAsync();
} catch (error) {
  const message = error instanceof Error ? error.message : "Unknown evidence verification error";
  process.stderr.write(`Unable to verify evidence: ${message}\n`);
  process.exitCode = 2;
}
