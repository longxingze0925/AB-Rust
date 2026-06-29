#!/usr/bin/env bash
set -Eeuo pipefail

AB_REPO="${AB_REPO:-longxingze0925/AB-Rust}"
AB_REF="${AB_REF:-main}"
AB_RAW_BASE="${AB_RAW_BASE:-https://raw.githubusercontent.com/${AB_REPO}/${AB_REF}}"

script_dir=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P || true)"
fi

if [[ -n "$script_dir" && -f "$script_dir/abctl.sh" ]]; then
  exec bash "$script_dir/abctl.sh"
fi

tmp_dir="$(mktemp -d)"
cleanup() { rm -rf "$tmp_dir"; }
trap cleanup EXIT

cache_bust="${AB_CACHE_BUST:-$(date +%s)}"
curl -fsSL \
  -H "Cache-Control: no-cache" \
  -H "Pragma: no-cache" \
  "$AB_RAW_BASE/ops/abctl.sh?cb=$cache_bust" \
  -o "$tmp_dir/abctl.sh"
exec bash "$tmp_dir/abctl.sh"
