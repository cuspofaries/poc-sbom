#!/usr/bin/env bash
# =============================================================================
# sbom-policy.sh - Evaluate SBOM against OPA compliance policies
#
# Usage: ./scripts/sbom-policy.sh <sbom-file> <policies-dir>
# =============================================================================
set -euo pipefail

SBOM_FILE="${1:?Usage: $0 <sbom-file> <policies-dir>}"
POLICIES_DIR="${2:-./policies}"

echo "📋 Evaluating SBOM against policies..."
echo "   SBOM:     ${SBOM_FILE}"
echo "   Policies: ${POLICIES_DIR}/"
echo ""

if ! command -v opa &>/dev/null; then
    echo "❌ OPA not installed. Run: task install:opa"
    exit 1
fi

# --- Evaluate deny rules ---
echo "── Deny Rules (blocking) ──"
DENY_RESULT=$(opa eval \
    -d "${POLICIES_DIR}/" \
    -i "$SBOM_FILE" \
    'data.sbom.deny' \
    --format raw 2>/dev/null || echo "[]")

if [ "$DENY_RESULT" = "[]" ] || [ "$DENY_RESULT" = "undefined" ] || [ -z "$DENY_RESULT" ]; then
    echo "   ✅ No policy violations"
    DENY_COUNT=0
else
    DENY_COUNT=$(echo "$DENY_RESULT" | jq 'length' 2>/dev/null || echo "0")
    echo "   ❌ ${DENY_COUNT} violation(s) found:"
    echo "$DENY_RESULT" | jq -r '.[]' 2>/dev/null | while read -r msg; do
        echo "      • ${msg}"
    done
fi

echo ""

# --- Evaluate warn rules ---
echo "── Warning Rules (advisory) ──"
WARN_RESULT=$(opa eval \
    -d "${POLICIES_DIR}/" \
    -i "$SBOM_FILE" \
    'data.sbom.warn' \
    --format raw 2>/dev/null || echo "[]")

if [ "$WARN_RESULT" = "[]" ] || [ "$WARN_RESULT" = "undefined" ] || [ -z "$WARN_RESULT" ]; then
    echo "   ✅ No warnings"
    WARN_COUNT=0
else
    WARN_COUNT=$(echo "$WARN_RESULT" | jq 'length' 2>/dev/null || echo "0")
    echo "   ⚠️  ${WARN_COUNT} warning(s):"
    echo "$WARN_RESULT" | jq -r '.[]' 2>/dev/null | while read -r msg; do
        echo "      • ${msg}"
    done
fi

echo ""

# --- Evaluate info/stats ---
echo "── SBOM Statistics ──"
STATS=$(opa eval \
    -d "${POLICIES_DIR}/" \
    -i "$SBOM_FILE" \
    'data.sbom.stats' \
    --format raw 2>/dev/null || echo "{}")

if [ -n "$STATS" ] && [ "$STATS" != "undefined" ]; then
    echo "$STATS" | jq -r 'to_entries[] | "   \(.key): \(.value)"' 2>/dev/null || true
fi

echo ""

# --- Summary ---
echo "══════════════════════════════════════"
if [ "$DENY_COUNT" -gt 0 ]; then
    echo "  ❌ POLICY CHECK FAILED (${DENY_COUNT} violations)"
    exit 1
else
    echo "  ✅ POLICY CHECK PASSED (${WARN_COUNT} warnings)"
    exit 0
fi
