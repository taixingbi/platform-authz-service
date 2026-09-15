#!/usr/bin/env bash
# Refreshes policies/ from the canonical bedrock-gateway-policies repo.
# Same interim mechanism as bedrock-gateway-app's script of the same
# name -- see policies/iam_tenants.yaml's banner comment. Only
# iam_tenants.yaml is needed here (this service does principal mapping
# only, not the full tenant policy).
#
# Usage:
#   ./scripts/sync-policies.sh [path-to-bedrock-gateway-policies-checkout]
#   (defaults to ../bedrock-gateway-policies, i.e. a sibling checkout)
set -euo pipefail

SRC="${1:-../bedrock-gateway-policies}/environments/dev"
DST="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/policies"

if [ ! -d "$SRC" ]; then
  echo "error: $SRC not found -- pass the path to a bedrock-gateway-policies checkout" >&2
  exit 1
fi

for f in iam_tenants.yaml; do
  banner=$(sed -n '/^# ====/,/^# ====/p' "$DST/$f")
  { printf '%s\n' "$banner"; cat "$SRC/$f"; } > "$DST/$f.tmp"
  mv "$DST/$f.tmp" "$DST/$f"
  echo "synced $f from $SRC"
done
