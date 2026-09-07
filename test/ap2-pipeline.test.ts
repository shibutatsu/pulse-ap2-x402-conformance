import { execFile } from "node:child_process";
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const ap2Commit = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43";
let root: string;
let project: string;
let env: NodeJS.ProcessEnv;

async function executable(path: string, contents: string): Promise<void> {
  await writeFile(path, `#!/bin/sh\nset -eu\n${contents}\n`);
  await chmod(path, 0o700);
}

beforeEach(async () => {
  root = await realpath(await mkdtemp(join(tmpdir(), "pulse-pipeline-test-")));
  project = join(root, "project");
  const bin = join(root, "bin");
  await mkdir(join(project, "scripts/ap2"), { recursive: true });
  await mkdir(bin);
  await mkdir(join(root, "shared tmp"));
  await copyFile(
    new URL("../scripts/ap2/run-pinned.sh", import.meta.url),
    join(project, "scripts/ap2/run-pinned.sh"),
  );
  env = {
    PATH: `${bin}:${process.env.PATH}`,
    TMPDIR: join(root, "shared tmp"),
    STAGE_LOG: join(root, "stages"),
    INTERPRETER_LOG: join(root, "interpreters"),
    GIT_LOG: join(root, "git-calls"),
    TRUSTED_INTERPRETER: join(root, "trusted-python"),
    EXPECTED_COMMIT: ap2Commit,
  };
  await executable(
    join(root, "trusted-python"),
    `printf '%s\\n' "$0" >> "$INTERPRETER_LOG"
printf '%s\\n' "$@" >> "$STAGE_LOG"`,
  );
  await executable(
    join(bin, "uv"),
    `case "$1" in
  --version) echo 'uv 0.10.11' ;;
  venv) mkdir -p "$2/bin"; cp "$TRUSTED_INTERPRETER" "$2/bin/python" ;;
  pip) if [ "\${FAIL_SYNC:-0}" = 1 ]; then exit 7; fi ;;
  *) exit 9 ;;
esac`,
  );
  await executable(
    join(bin, "git"),
    `printf '%s\\n' "$@" >> "$GIT_LOG"
case "$1:$3" in
  clone:*) mkdir -p "$4/.git" ;;
  -C:rev-parse) echo "$EXPECTED_COMMIT" ;;
  -C:status) printf '%s' "\${DIRTY_SOURCE:-}" ;;
esac`,
  );
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

function run(args: string[] = [], cwd = project) {
  return execFileAsync("sh", [join(project, "scripts/ap2/run-pinned.sh"), ...args], {
    cwd,
    env,
  });
}

it.each(["default", "override", "symlink", "trailing-slash", "symlink-trailing-slash"])(
  "ignores a planted legacy cache (%s)",
  async (mode) => {
    const legacy = join(root, "shared tmp", `pulse-ap2-${ap2Commit}`);
    const planted = mode.includes("symlink") ? join(root, "planted") : legacy;
    await mkdir(join(planted, "venv-py312/bin"), { recursive: true });
    await mkdir(join(planted, "AP2/.git"), { recursive: true });
    const marker = join(root, "plant-ran");
    await executable(join(planted, "venv-py312/bin/python"), `touch '${marker}'`);
    if (mode.includes("symlink")) await symlink(planted, legacy);
    if (mode !== "default")
      env.AP2_PIPELINE_CACHE_DIR = `${legacy}${mode.includes("trailing-slash") ? "///" : ""}`;

    await run();
    await expect(stat(marker)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readFile(env.GIT_LOG as string, "utf8")).not.toContain(`${legacy}/AP2\n`);
    expect(await readFile(env.STAGE_LOG as string, "utf8")).toBe(
      "scripts/ap2/generate_signed_artifacts.py\nscripts/ap2/verify_extract_artifacts.py\n",
    );
    expect(await readdir(join(root, "shared tmp"))).toEqual([`pulse-ap2-${ap2Commit}`]);
    await expect(stat(join(planted, "venv-py312/bin/python"))).resolves.toBeDefined();
  },
);

it("uses different roots, preserves public-evidence arguments, and cleans a relative prefix", async () => {
  env.AP2_PIPELINE_CACHE_DIR = "shared tmp/run";
  await run(["--public-evidence", "--output", "output with spaces.json"], root);
  await run(["--public-evidence", "--output", "output with spaces.json"], root);
  const interpreters = (await readFile(env.INTERPRETER_LOG as string, "utf8")).trim().split("\n");
  expect(interpreters).toHaveLength(2);
  expect(new Set(interpreters).size).toBe(2);
  expect(await readFile(env.STAGE_LOG as string, "utf8")).toBe(
    "scripts/ap2/generate_public_evm_artifacts.py\n--output\noutput with spaces.json\n".repeat(2),
  );
  expect(await readdir(join(root, "shared tmp"))).toEqual([]);
});

it.each(["clean", "wrong-commit", "dirty"])("keeps local source checks (%s)", async (mode) => {
  const source = join(root, "trusted source");
  await mkdir(source);
  env.AP2_SOURCE_DIR = source;
  if (mode === "wrong-commit") env.EXPECTED_COMMIT = "0".repeat(40);
  if (mode === "dirty") env.DIRTY_SOURCE = " M sdk.py";
  if (mode === "clean") {
    await run();
  } else {
    await expect(run()).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining(mode === "dirty" ? "must be clean" : "expected"),
    });
    await expect(stat(env.STAGE_LOG as string)).rejects.toMatchObject({ code: "ENOENT" });
  }
  expect(await readFile(env.GIT_LOG as string, "utf8")).not.toContain("clone\n");
  expect(await readdir(join(root, "shared tmp"))).toEqual([]);
  await expect(stat(source)).resolves.toBeDefined();
});

it("cleans only the allocated directory after a dependency failure", async () => {
  env.FAIL_SYNC = "1";
  const sentinel = join(root, "shared tmp", "keep");
  await writeFile(sentinel, "untouched");
  await expect(run()).rejects.toMatchObject({ code: 7 });
  expect(await readdir(join(root, "shared tmp"))).toEqual(["keep"]);
  expect(await readFile(sentinel, "utf8")).toBe("untouched");
  await expect(stat(env.STAGE_LOG as string)).rejects.toMatchObject({ code: "ENOENT" });
});

it.each(["/", ".", "..", "shared tmp/.", "shared tmp/../"])(
  "rejects a prefix without a directory name (%s)",
  async (prefix) => {
    env.AP2_PIPELINE_CACHE_DIR = prefix;
    await expect(run([], root)).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining("must name a prefix"),
    });
    await expect(stat(env.GIT_LOG as string)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readdir(join(root, "shared tmp"))).toEqual([]);
  },
);
