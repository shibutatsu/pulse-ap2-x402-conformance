#!/bin/sh
set -eu

ap2_commit="e1ea56db72a6385bce3e5c1112b3a56ce60acb43"
required_uv_version="0.10.11"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
cache_root=${AP2_PIPELINE_CACHE_DIR:-${TMPDIR:-/tmp}/pulse-ap2-${ap2_commit}}

actual_uv_version=$(uv --version | awk '{print $2}')
if [ "$actual_uv_version" != "$required_uv_version" ]; then
  echo "uv $required_uv_version is required, found $actual_uv_version" >&2
  exit 1
fi

if [ -n "${AP2_SOURCE_DIR:-}" ]; then
  sdk_source=$(CDPATH= cd -- "$AP2_SOURCE_DIR" && pwd)
  actual_commit=$(git -C "$sdk_source" rev-parse HEAD)
  if [ "$actual_commit" != "$ap2_commit" ]; then
    echo "AP2_SOURCE_DIR is at $actual_commit, expected $ap2_commit" >&2
    exit 1
  fi
else
  sdk_source="$cache_root/AP2"
  if [ ! -d "$sdk_source/.git" ]; then
    mkdir -p "$cache_root"
    git clone --filter=blob:none https://github.com/google-agentic-commerce/AP2.git "$sdk_source"
  fi
  git -C "$sdk_source" fetch --depth=1 origin "$ap2_commit"
  git -C "$sdk_source" checkout --detach "$ap2_commit"
fi

if [ -n "$(git -C "$sdk_source" status --porcelain)" ]; then
  echo "AP2 source checkout must be clean" >&2
  exit 1
fi

venv_dir="$cache_root/venv-py312"
if [ ! -x "$venv_dir/bin/python" ]; then
  uv venv "$venv_dir" --python 3.12
fi
uv pip sync \
  --python "$venv_dir/bin/python" \
  --require-hashes \
  "$script_dir/requirements.lock.txt"
uv pip install \
  --python "$venv_dir/bin/python" \
  --no-build-isolation \
  --no-deps \
  "$sdk_source"

cd "$project_root"
AP2_SOURCE_DIR="$sdk_source" "$venv_dir/bin/python" \
  scripts/ap2/generate_signed_artifacts.py
AP2_SOURCE_DIR="$sdk_source" "$venv_dir/bin/python" \
  scripts/ap2/verify_extract_artifacts.py
