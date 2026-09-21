#!/usr/bin/env bash
# Refreshes policies/ from the canonical platform-policy-definitions repo.
# Same interim mechanism as bedrock-runtime-gateway-app's script of the same
# name -- see policies/iam_tenants.yaml's banner comment. Only
# iam_tenants.yaml is needed here (this service does principal mapping
# only, not the full tenant policy).
#
# Usage:
#   ./scripts/sync-policies.sh [path-to-platform-policy-definitions-checkout]
#   (defaults to ../platform-policy-definitions, i.e. a sibling checkout)
set -euo pipefail

SRC="${1:-../platform-policy-definitions}/environments/dev"
DST="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/policies"

if [ ! -d "$SRC" ]; then
  echo "error: $SRC not found -- pass the path to a platform-policy-definitions checkout" >&2
  exit 1
fi

for f in iam_tenants.yaml; do
  banner=$(sed -n '/^# ====/,/^# ====/p' "$DST/$f")
  { printf '%s\n' "$banner"; cat "$SRC/$f"; } > "$DST/$f.tmp"
  mv "$DST/$f.tmp" "$DST/$f"
  echo "synced $f from $SRC"
done
