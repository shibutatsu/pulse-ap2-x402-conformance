#!/bin/sh
set -eu

ap2_commit="e1ea56db72a6385bce3e5c1112b3a56ce60acb43"
required_uv_version="0.10.11"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)

actual_uv_version=$(uv --version | awk '{print $2}')
if [ "$actual_uv_version" != "$required_uv_version" ]; then
  echo "uv $required_uv_version is required, found $actual_uv_version" >&2
  exit 1
fi

# Allocate a private sibling of any legacy cache, never a child inside it.
cache_prefix=${AP2_PIPELINE_CACHE_DIR:-${TMPDIR:-/tmp}/pulse-ap2-${ap2_commit}}
while [ "${cache_prefix%/}" != "$cache_prefix" ]; do
  cache_prefix=${cache_prefix%/}
done
case "$cache_prefix" in
  ""|.|..|*/.|*/..)
    echo "AP2_PIPELINE_CACHE_DIR must name a prefix below a trusted parent directory" >&2
    exit 1
    ;;
esac
umask 077
cache_root=$(mktemp -d "$cache_prefix.XXXXXX")
cache_root=$(CDPATH= cd -- "$cache_root" && pwd -P)
trap 'rm -rf -- "$cache_root"' 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -n "${AP2_SOURCE_DIR:-}" ]; then
  sdk_source=$(CDPATH= cd -- "$AP2_SOURCE_DIR" && pwd)
  actual_commit=$(git -C "$sdk_source" rev-parse HEAD)
  if [ "$actual_commit" != "$ap2_commit" ]; then
    echo "AP2_SOURCE_DIR is at $actual_commit, expected $ap2_commit" >&2
    exit 1
  fi
else
  sdk_source="$cache_root/AP2"
  git clone --filter=blob:none https://github.com/google-agentic-commerce/AP2.git "$sdk_source"
  git -C "$sdk_source" fetch --depth=1 origin "$ap2_commit"
  git -C "$sdk_source" checkout --detach "$ap2_commit"
fi

if [ -n "$(git -C "$sdk_source" status --porcelain)" ]; then
  echo "AP2 source checkout must be clean" >&2
  exit 1
fi

venv_dir="$cache_root/venv-py312"
uv venv "$venv_dir" --python 3.12
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
case "${1:-}" in
  "")
    AP2_SOURCE_DIR="$sdk_source" "$venv_dir/bin/python" \
      scripts/ap2/generate_signed_artifacts.py
    AP2_SOURCE_DIR="$sdk_source" "$venv_dir/bin/python" \
      scripts/ap2/verify_extract_artifacts.py
    ;;
  --public-evidence)
    shift
    AP2_SOURCE_DIR="$sdk_source" "$venv_dir/bin/python" \
      scripts/ap2/generate_public_evm_artifacts.py "$@"
    ;;
  *)
    echo "usage: $0 [--public-evidence GENERATOR_OPTIONS]" >&2
    exit 2
    ;;
esac
