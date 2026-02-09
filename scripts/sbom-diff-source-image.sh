#!/usr/bin/env bash
# =============================================================================
# sbom-diff-source-image.sh - Compare source SBOM vs image SBOM
#
# Usage: ./scripts/sbom-diff-source-image.sh <sbom-dir>
#
# Answers the critical question:
#   "What's the gap between what my code declares and what's actually shipped?"
#
# Typical findings:
#   - OS packages in image not in source (expected: curl, libpq, etc.)
#   - Transitive deps in image not declared in source
#   - Source deps missing from image (build-only deps, test deps)
#   - Version mismatches between declared and installed
# =============================================================================
set -euo pipefail

SBOM_DIR="${1:?Usage: $0 <sbom-dir>}"
OUTPUT_DIR="${SBOM_DIR}/diff"

mkdir -p "$OUTPUT_DIR"

echo "🔍 Source vs Image SBOM Diff"
echo "═══════════════════════════════════════════════════════"
echo ""

# --- Find best available SBOMs ---
SOURCE_SBOM=""
IMAGE_SBOM=""

for f in "${SBOM_DIR}/source/sbom-source-cdxgen.json" \
         "${SBOM_DIR}/source/sbom-source-syft.json" \
         "${SBOM_DIR}/source/sbom-source-trivy.json"; do
    if [ -f "$f" ]; then
        SOURCE_SBOM="$f"
        break
    fi
done

for f in "${SBOM_DIR}/image/sbom-image-syft.json" \
         "${SBOM_DIR}/image/sbom-image-trivy.json"; do
    if [ -f "$f" ]; then
        IMAGE_SBOM="$f"
        break
    fi
done

if [ -z "$SOURCE_SBOM" ]; then
    echo "❌ No source SBOM found in ${SBOM_DIR}/source/"
    echo "   Run: task sbom:generate:source"
    exit 1
fi

if [ -z "$IMAGE_SBOM" ]; then
    echo "❌ No image SBOM found in ${SBOM_DIR}/image/"
    echo "   Run: task sbom:generate:image"
    exit 1
fi

echo "   Source SBOM: $(basename $SOURCE_SBOM)"
echo "   Image SBOM:  $(basename $IMAGE_SBOM)"
echo ""

# --- Extract component names ---
SOURCE_COMPONENTS=$(jq -r '.components[]? | "\(.name)@\(.version // "unknown")"' "$SOURCE_SBOM" | sort -u)
IMAGE_COMPONENTS=$(jq -r '.components[]? | "\(.name)@\(.version // "unknown")"' "$IMAGE_SBOM" | sort -u)

SOURCE_NAMES=$(jq -r '.components[]?.name' "$SOURCE_SBOM" | sort -u)
IMAGE_NAMES=$(jq -r '.components[]?.name' "$IMAGE_SBOM" | sort -u)

SOURCE_COUNT=$(echo "$SOURCE_NAMES" | wc -l | tr -d ' ')
[ -z "$SOURCE_NAMES" ] && SOURCE_COUNT=0
IMAGE_COUNT=$(echo "$IMAGE_NAMES" | wc -l | tr -d ' ')
[ -z "$IMAGE_NAMES" ] && IMAGE_COUNT=0

# --- Counts ---
echo "── Component Counts ──"
echo "   Source (declared): ${SOURCE_COUNT}"
echo "   Image (shipped):   ${IMAGE_COUNT}"
echo ""

# --- Only in source (not in image) ---
ONLY_SOURCE=$(comm -23 <(echo "$SOURCE_NAMES") <(echo "$IMAGE_NAMES"))
ONLY_SOURCE_COUNT=$(echo "$ONLY_SOURCE" | wc -l | tr -d ' ')
[ -z "$ONLY_SOURCE" ] && ONLY_SOURCE_COUNT=0

echo "── Only in SOURCE (declared but not shipped) ── [${ONLY_SOURCE_COUNT}]"
if [ "$ONLY_SOURCE_COUNT" -gt 0 ]; then
    echo "   These are typically build-only or test dependencies:"
    echo "$ONLY_SOURCE" | head -20 | while read -r name; do
        [ -z "$name" ] && continue
        VERSION=$(echo "$SOURCE_COMPONENTS" | grep "^${name}@" | head -1 | cut -d'@' -f2)
        echo "   • ${name} (${VERSION})"
    done || true
    [ "$ONLY_SOURCE_COUNT" -gt 20 ] && echo "   ... and $((ONLY_SOURCE_COUNT - 20)) more"
else
    echo "   (none)"
fi
echo ""

# --- Only in image (not in source) ---
ONLY_IMAGE=$(comm -13 <(echo "$SOURCE_NAMES") <(echo "$IMAGE_NAMES"))
ONLY_IMAGE_COUNT=$(echo "$ONLY_IMAGE" | wc -l | tr -d ' ')
[ -z "$ONLY_IMAGE" ] && ONLY_IMAGE_COUNT=0

echo "── Only in IMAGE (shipped but not declared) ── [${ONLY_IMAGE_COUNT}]"
if [ "$ONLY_IMAGE_COUNT" -gt 0 ]; then
    echo "   These are typically OS packages, transitive deps, or runtime libs:"
    echo "$ONLY_IMAGE" | head -30 | while read -r name; do
        [ -z "$name" ] && continue
        VERSION=$(echo "$IMAGE_COMPONENTS" | grep "^${name}@" | head -1 | cut -d'@' -f2)
        TYPE=$(jq -r --arg n "$name" '.components[] | select(.name == $n) | .type // "unknown"' "$IMAGE_SBOM" 2>/dev/null | head -1)
        echo "   • ${name} (${VERSION}) [${TYPE}]"
    done || true
    [ "$ONLY_IMAGE_COUNT" -gt 30 ] && echo "   ... and $((ONLY_IMAGE_COUNT - 30)) more"
else
    echo "   (none)"
fi
echo ""

# --- Common (in both) ---
COMMON=$(comm -12 <(echo "$SOURCE_NAMES") <(echo "$IMAGE_NAMES"))
COMMON_COUNT=$(echo "$COMMON" | wc -l | tr -d ' ')
[ -z "$COMMON" ] && COMMON_COUNT=0

echo "── Common (declared AND shipped) ── [${COMMON_COUNT}]"

# Check for version mismatches in common components
MISMATCHES=0
MISMATCH_DETAILS=""
while read -r name; do
    [ -z "$name" ] && continue
    SRC_VER=$(echo "$SOURCE_COMPONENTS" | grep "^${name}@" | head -1 | cut -d'@' -f2)
    IMG_VER=$(echo "$IMAGE_COMPONENTS" | grep "^${name}@" | head -1 | cut -d'@' -f2)
    if [ "$SRC_VER" != "$IMG_VER" ] && [ -n "$SRC_VER" ] && [ -n "$IMG_VER" ]; then
        MISMATCH_DETAILS="${MISMATCH_DETAILS}\n   ⚠️  ${name}: source=${SRC_VER} → image=${IMG_VER}"
        ((MISMATCHES++))
    fi
done <<< "$COMMON"

if [ "$MISMATCHES" -gt 0 ]; then
    echo "   Version mismatches found: ${MISMATCHES}"
    echo -e "$MISMATCH_DETAILS"
else
    echo "   ✅ No version mismatches detected"
fi
echo ""

# --- Save detailed diff ---
echo "$ONLY_SOURCE" > "${OUTPUT_DIR}/only-in-source.txt"
echo "$ONLY_IMAGE" > "${OUTPUT_DIR}/only-in-image.txt"
echo "$COMMON" > "${OUTPUT_DIR}/common.txt"

cat > "${OUTPUT_DIR}/diff-summary.json" << EOF
{
  "source_sbom": "$(basename $SOURCE_SBOM)",
  "image_sbom": "$(basename $IMAGE_SBOM)",
  "source_components": ${SOURCE_COUNT},
  "image_components": ${IMAGE_COUNT},
  "only_in_source": ${ONLY_SOURCE_COUNT},
  "only_in_image": ${ONLY_IMAGE_COUNT},
  "common": ${COMMON_COUNT},
  "version_mismatches": ${MISMATCHES}
}
EOF

# --- Summary ---
echo "═══════════════════════════════════════════════════════"
echo "  Source: ${SOURCE_COUNT} | Image: ${IMAGE_COUNT} | Common: ${COMMON_COUNT}"
echo "  Only source: ${ONLY_SOURCE_COUNT} | Only image: ${ONLY_IMAGE_COUNT} | Mismatches: ${MISMATCHES}"
echo ""
echo "  Detailed output → ${OUTPUT_DIR}/"
echo "═══════════════════════════════════════════════════════"

if [ "$ONLY_IMAGE_COUNT" -gt "$((SOURCE_COUNT * 2))" ]; then
    echo ""
    echo "  💡 Tip: Image has significantly more components than source."
    echo "     This is normal for container images (OS packages, system libs)."
    echo "     Focus vulnerability scanning on the IMAGE SBOM for full coverage."
fi
