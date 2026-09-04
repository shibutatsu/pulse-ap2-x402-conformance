#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import process from "node:process";
import { Command, InvalidArgumentError } from "commander";
import { http, createPublicClient } from "viem";
import {
  type PublicEvmHeadTag,
  type PublicEvmReader,
  type PublicEvmV02Reader,
  assessPublicEvmSettlementV02,
  selectPublicEvmCase,
  verifyIndependentReproductionRecord,
  verifyIndependentSecurityReviewRecord,
  verifyPublicEvmSettlement,
  verifyPublicEvmSettlementRecord,
  verifyPublicEvmSettlementV02,
} from "./evidence.js";

function positiveInteger(value: string): bigint {
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new InvalidArgumentError("Expected a positive integer");
  }
  return BigInt(value);
}

function nonnegativeInteger(value: string): bigint {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new InvalidArgumentError("Expected a non-negative integer");
  }
  return BigInt(value);
}

function publicEvmHeadTag(value: string): PublicEvmHeadTag {
  if (value !== "latest" && value !== "safe" && value !== "finalized") {
    throw new InvalidArgumentError("Expected latest, safe, or finalized");
  }
  return value;
}

function publicEvmHeadTags(value: string): PublicEvmHeadTag[] {
  const values = value.split(",").map(publicEvmHeadTag);
  if (values.length === 0 || new Set(values).size !== values.length) {
    throw new InvalidArgumentError("Expected a non-empty comma-separated list of unique head tags");
  }
  return values;
}

type RereadMode = "always" | "if-policy-unsatisfied" | "never";

function rereadMode(value: string): RereadMode {
  if (value !== "always" && value !== "if-policy-unsatisfied" && value !== "never") {
    throw new InvalidArgumentError("Expected always, if-policy-unsatisfied, or never");
  }
  return value;
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
  .command("evm-record")
  .description("Validate a recorded public EVM evidence file against its offline case")
  .argument("<case>", "path to the standalone public EVM conformance case")
  .argument("<record>", "path to the recorded public EVM evidence")
  .action(async (casePath: string, recordPath: string) => {
    const [conformanceCase, record] = await Promise.all([readJson(casePath), readJson(recordPath)]);
    const report = await verifyPublicEvmSettlementRecord(conformanceCase, record);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (!report.automatedChecksPassed) process.exitCode = 1;
  });

program
  .command("evm-assess")
  .description("Assess a 0.2 EVM evidence record under a caller-supplied consumer policy")
  .argument("<case>", "path to the standalone public EVM conformance case")
  .argument("<record>", "path to the recorded public EVM evidence")
  .requiredOption(
    "--max-observation-age-seconds <seconds>",
    "maximum age accepted by the consumer",
    nonnegativeInteger,
  )
  .requiredOption(
    "--min-confirmations <count>",
    "minimum recorded confirmations accepted by the consumer",
    positiveInteger,
  )
  .requiredOption(
    "--allowed-head-tags <tags>",
    "comma-separated accepted head tags",
    publicEvmHeadTags,
  )
  .requiredOption("--trusted-verifier-operator <operator>", "trusted verifier operator value")
  .requiredOption(
    "--trusted-verifier-repository-url <url>",
    "trusted verifier repository URL value",
  )
  .requiredOption("--trusted-verifier-commit <sha>", "trusted verifier commit value")
  .requiredOption(
    "--reread <mode>",
    "online re-read policy: always, if-policy-unsatisfied, or never",
    rereadMode,
  )
  .action(
    async (
      casePath: string,
      recordPath: string,
      options: {
        maxObservationAgeSeconds: bigint;
        minConfirmations: bigint;
        allowedHeadTags: PublicEvmHeadTag[];
        trustedVerifierOperator: string;
        trustedVerifierRepositoryUrl: string;
        trustedVerifierCommit: string;
        reread: RereadMode;
      },
    ) => {
      const [conformanceCase, record] = await Promise.all([
        readJson(casePath),
        readJson(recordPath),
      ]);
      const assessment = await assessPublicEvmSettlementV02(conformanceCase, record, {
        maximumObservationAgeSeconds: options.maxObservationAgeSeconds,
        minimumConfirmations: options.minConfirmations,
        allowedHeadTags: options.allowedHeadTags,
        trustedVerifierProvenance: {
          operator: options.trustedVerifierOperator,
          repositoryUrl: options.trustedVerifierRepositoryUrl,
          commit: options.trustedVerifierCommit,
        },
        reread: options.reread,
      });
      process.stdout.write(`${JSON.stringify(assessment, null, 2)}\n`);
      if (!assessment.accepted) process.exitCode = 1;
    },
  );

program
  .command("evm")
  .description("Verify an accepted case against a public EVM transaction receipt")
  .argument("<case-or-bundle>", "path to a standalone case or versioned fixture bundle")
  .requiredOption("--case <id>", "accepted fixture case id")
  .option("--min-confirmations <count>", "minimum block confirmations", positiveInteger)
  .option("--output <path>", "write the evidence record to this path")
  .action(
    async (
      bundlePath: string,
      options: { case: string; minConfirmations?: bigint; output?: string },
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
        options.minConfirmations ?? 1n,
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

program
  .command("evm-v0.2")
  .description("Create a provenance-bound 0.2 observation of a public EVM settlement")
  .argument("<case-or-bundle>", "path to a standalone case or versioned fixture bundle")
  .requiredOption("--case <id>", "accepted fixture case id")
  .requiredOption("--verifier-operator <operator>", "operator making the observation")
  .requiredOption("--verifier-repository-url <url>", "public verifier repository URL")
  .requiredOption("--verifier-commit <sha>", "40-character verifier commit")
  .option("--head-tag <tag>", "head tag to observe", publicEvmHeadTag, "latest")
  .option("--min-confirmations <count>", "minimum confirmations at that head", positiveInteger)
  .option("--output <path>", "write the evidence record to this path")
  .action(
    async (
      bundlePath: string,
      options: {
        case: string;
        verifierOperator: string;
        verifierRepositoryUrl: string;
        verifierCommit: string;
        headTag: PublicEvmHeadTag;
        minConfirmations?: bigint;
        output?: string;
      },
    ) => {
      const rpcUrl = process.env.PULSE_EVM_RPC_URL;
      if (rpcUrl === undefined || rpcUrl.length === 0) {
        throw new Error("Set PULSE_EVM_RPC_URL to a read-only public EVM endpoint.");
      }
      const selectedCase = selectPublicEvmCase(await readJson(bundlePath), options.case);
      const client = createPublicClient({ transport: http(rpcUrl) });
      const evidence = await verifyPublicEvmSettlementV02(
        selectedCase,
        client as unknown as PublicEvmV02Reader,
        {
          verifierProvenance: {
            operator: options.verifierOperator,
            repositoryUrl: options.verifierRepositoryUrl,
            commit: options.verifierCommit,
            command: "pulse-ap2-x402-evidence evm-v0.2",
          },
          headTag: options.headTag,
          minimumConfirmations: options.minConfirmations ?? 1n,
        },
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
