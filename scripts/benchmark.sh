#!/usr/bin/env bash
# =============================================================================
# benchmark.sh - Comparative benchmark of SBOM tools (source + image)
#
# Usage: ./scripts/benchmark.sh <image> <output-dir>
#
# Compares:
#   Source generation: cdxgen vs Trivy-fs vs Syft-dir
#   Image generation:  Syft vs Trivy
#   Scanning:          Grype vs Trivy
# =============================================================================
set -euo pipefail

IMAGE="${1:?Usage: $0 <image> <output-dir>}"
OUTPUT_DIR="${2:-./output/benchmark}"
APP_DIR="./app"

mkdir -p "$OUTPUT_DIR"/{source,image,scans}

REPORT_FILE="${OUTPUT_DIR}/benchmark-report.json"

echo "🏁 SBOM Tool Benchmark"
echo "═══════════════════════════════════════════════════════"
echo "   Image:  ${IMAGE}"
echo "   Source: ${APP_DIR}/"
echo "   Output: ${OUTPUT_DIR}/"
echo ""

# Helper: time a command in ms
time_cmd() {
    local start end
    start=$(date +%s%N)
    eval "$@" > /dev/null 2>&1
    local exit_code=$?
    end=$(date +%s%N)
    echo $(( (end - start) / 1000000 ))
    return $exit_code
}

file_size_kb() { [ -f "$1" ] && du -k "$1" | cut -f1 || echo "0"; }
component_count() { jq '.components | length' "$1" 2>/dev/null || echo "0"; }

# ==========================================================================
# SOURCE SBOM BENCHMARK
# ==========================================================================
echo "── Source SBOM Generation (declared deps) ──"
echo ""

declare -A SRC_TIME SRC_SIZE SRC_COMP SRC_STATUS

# cdxgen
echo -n "   cdxgen...        "
if command -v cdxgen &>/dev/null; then
    SRC_TIME[cdxgen]=$(time_cmd "cdxgen -o ${OUTPUT_DIR}/source/sbom-cdxgen.json ${APP_DIR}")
    SRC_STATUS[cdxgen]="ok"
    SRC_SIZE[cdxgen]=$(file_size_kb "${OUTPUT_DIR}/source/sbom-cdxgen.json")
    SRC_COMP[cdxgen]=$(component_count "${OUTPUT_DIR}/source/sbom-cdxgen.json")
    echo "${SRC_TIME[cdxgen]}ms | ${SRC_SIZE[cdxgen]}KB | ${SRC_COMP[cdxgen]} components"
else
    SRC_STATUS[cdxgen]="not installed"; echo "SKIPPED"
fi

# Trivy fs
echo -n "   Trivy (fs)...    "
if command -v trivy &>/dev/null; then
    SRC_TIME[trivy]=$(time_cmd "trivy fs ${APP_DIR} --format cyclonedx --output ${OUTPUT_DIR}/source/sbom-trivy.json")
    SRC_STATUS[trivy]="ok"
    SRC_SIZE[trivy]=$(file_size_kb "${OUTPUT_DIR}/source/sbom-trivy.json")
    SRC_COMP[trivy]=$(component_count "${OUTPUT_DIR}/source/sbom-trivy.json")
    echo "${SRC_TIME[trivy]}ms | ${SRC_SIZE[trivy]}KB | ${SRC_COMP[trivy]} components"
else
    SRC_STATUS[trivy]="not installed"; echo "SKIPPED"
fi

# Syft dir
echo -n "   Syft (dir)...    "
if command -v syft &>/dev/null; then
    SRC_TIME[syft]=$(time_cmd "syft dir:${APP_DIR} -o cyclonedx-json=${OUTPUT_DIR}/source/sbom-syft.json")
    SRC_STATUS[syft]="ok"
    SRC_SIZE[syft]=$(file_size_kb "${OUTPUT_DIR}/source/sbom-syft.json")
    SRC_COMP[syft]=$(component_count "${OUTPUT_DIR}/source/sbom-syft.json")
    echo "${SRC_TIME[syft]}ms | ${SRC_SIZE[syft]}KB | ${SRC_COMP[syft]} components"
else
    SRC_STATUS[syft]="not installed"; echo "SKIPPED"
fi

echo ""

# ==========================================================================
# IMAGE SBOM BENCHMARK
# ==========================================================================
echo "── Image SBOM Generation (shipped content) ──"
echo ""

declare -A IMG_TIME IMG_SIZE IMG_COMP IMG_STATUS

# Syft
echo -n "   Syft...          "
if command -v syft &>/dev/null; then
    IMG_TIME[syft]=$(time_cmd "syft ${IMAGE} -o cyclonedx-json=${OUTPUT_DIR}/image/sbom-syft.json")
    IMG_STATUS[syft]="ok"
    IMG_SIZE[syft]=$(file_size_kb "${OUTPUT_DIR}/image/sbom-syft.json")
    IMG_COMP[syft]=$(component_count "${OUTPUT_DIR}/image/sbom-syft.json")
    echo "${IMG_TIME[syft]}ms | ${IMG_SIZE[syft]}KB | ${IMG_COMP[syft]} components"
else
    IMG_STATUS[syft]="not installed"; echo "SKIPPED"
fi

# Trivy
echo -n "   Trivy...         "
if command -v trivy &>/dev/null; then
    IMG_TIME[trivy]=$(time_cmd "trivy image ${IMAGE} --format cyclonedx --output ${OUTPUT_DIR}/image/sbom-trivy.json")
    IMG_STATUS[trivy]="ok"
    IMG_SIZE[trivy]=$(file_size_kb "${OUTPUT_DIR}/image/sbom-trivy.json")
    IMG_COMP[trivy]=$(component_count "${OUTPUT_DIR}/image/sbom-trivy.json")
    echo "${IMG_TIME[trivy]}ms | ${IMG_SIZE[trivy]}KB | ${IMG_COMP[trivy]} components"
else
    IMG_STATUS[trivy]="not installed"; echo "SKIPPED"
fi

echo ""

# ==========================================================================
# SOURCE vs IMAGE GAP
# ==========================================================================
echo "── Source vs Image Gap ──"
echo ""

BEST_SOURCE=$(ls "${OUTPUT_DIR}/source/sbom-cdxgen.json" "${OUTPUT_DIR}/source/sbom-syft.json" "${OUTPUT_DIR}/source/sbom-trivy.json" 2>/dev/null | head -1)
BEST_IMAGE=$(ls "${OUTPUT_DIR}/image/sbom-syft.json" "${OUTPUT_DIR}/image/sbom-trivy.json" 2>/dev/null | head -1)

if [ -n "$BEST_SOURCE" ] && [ -n "$BEST_IMAGE" ]; then
    SRC_NAMES=$(jq -r '.components[]?.name' "$BEST_SOURCE" | sort -u)
    IMG_NAMES=$(jq -r '.components[]?.name' "$BEST_IMAGE" | sort -u)

    ONLY_SRC=$(comm -23 <(echo "$SRC_NAMES") <(echo "$IMG_NAMES") | wc -l)
    ONLY_IMG=$(comm -13 <(echo "$SRC_NAMES") <(echo "$IMG_NAMES") | wc -l)
    COMMON=$(comm -12 <(echo "$SRC_NAMES") <(echo "$IMG_NAMES") | wc -l)

    echo "   Common:          ${COMMON}"
    echo "   Only in source:  ${ONLY_SRC} (build/test deps)"
    echo "   Only in image:   ${ONLY_IMG} (OS pkgs, transitive deps)"
    echo ""
    echo "   💡 Image typically has more components — this is expected."
    echo "      Scan BOTH for full coverage."
else
    echo "   ⚠️  Need both source and image SBOMs for gap analysis"
fi

echo ""

# ==========================================================================
# SCANNING BENCHMARK
# ==========================================================================
echo "── Vulnerability Scanning (on image SBOM) ──"
echo ""

REFERENCE_SBOM="${OUTPUT_DIR}/image/sbom-syft.json"

declare -A SCAN_TIME SCAN_VULNS SCAN_CRIT SCAN_HIGH SCAN_STATUS

# Grype
echo -n "   Grype...         "
if command -v grype &>/dev/null && [ -f "$REFERENCE_SBOM" ]; then
    SCAN_TIME[grype]=$(time_cmd "grype sbom:${REFERENCE_SBOM} -o json --file ${OUTPUT_DIR}/scans/scan-grype.json")
    SCAN_STATUS[grype]="ok"
    SCAN_VULNS[grype]=$(jq '.matches | length' "${OUTPUT_DIR}/scans/scan-grype.json" 2>/dev/null || echo "0")
    SCAN_CRIT[grype]=$(jq '[.matches[] | select(.vulnerability.severity == "Critical")] | length' "${OUTPUT_DIR}/scans/scan-grype.json" 2>/dev/null || echo "0")
    SCAN_HIGH[grype]=$(jq '[.matches[] | select(.vulnerability.severity == "High")] | length' "${OUTPUT_DIR}/scans/scan-grype.json" 2>/dev/null || echo "0")
    echo "${SCAN_TIME[grype]}ms | ${SCAN_VULNS[grype]} vulns (${SCAN_CRIT[grype]}C/${SCAN_HIGH[grype]}H)"
else
    SCAN_STATUS[grype]="not available"; echo "SKIPPED"
fi

# Trivy
echo -n "   Trivy...         "
if command -v trivy &>/dev/null && [ -f "$REFERENCE_SBOM" ]; then
    SCAN_TIME[trivy]=$(time_cmd "trivy sbom ${REFERENCE_SBOM} --format json --output ${OUTPUT_DIR}/scans/scan-trivy.json")
    SCAN_STATUS[trivy]="ok"
    SCAN_VULNS[trivy]=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "${OUTPUT_DIR}/scans/scan-trivy.json" 2>/dev/null || echo "0")
    SCAN_CRIT[trivy]=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "${OUTPUT_DIR}/scans/scan-trivy.json" 2>/dev/null || echo "0")
    SCAN_HIGH[trivy]=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "${OUTPUT_DIR}/scans/scan-trivy.json" 2>/dev/null || echo "0")
    echo "${SCAN_TIME[trivy]}ms | ${SCAN_VULNS[trivy]} vulns (${SCAN_CRIT[trivy]}C/${SCAN_HIGH[trivy]}H)"
else
    SCAN_STATUS[trivy]="not available"; echo "SKIPPED"
fi

echo ""

# ==========================================================================
# JSON REPORT
# ==========================================================================
cat > "$REPORT_FILE" << REPORT_EOF
{
  "benchmark_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "image": "${IMAGE}",
  "source_dir": "${APP_DIR}",
  "source_generation": {
    "cdxgen": { "status": "${SRC_STATUS[cdxgen]:-skipped}", "time_ms": ${SRC_TIME[cdxgen]:-0}, "size_kb": ${SRC_SIZE[cdxgen]:-0}, "components": ${SRC_COMP[cdxgen]:-0} },
    "trivy":  { "status": "${SRC_STATUS[trivy]:-skipped}",  "time_ms": ${SRC_TIME[trivy]:-0},  "size_kb": ${SRC_SIZE[trivy]:-0},  "components": ${SRC_COMP[trivy]:-0} },
    "syft":   { "status": "${SRC_STATUS[syft]:-skipped}",   "time_ms": ${SRC_TIME[syft]:-0},   "size_kb": ${SRC_SIZE[syft]:-0},   "components": ${SRC_COMP[syft]:-0} }
  },
  "image_generation": {
    "syft":  { "status": "${IMG_STATUS[syft]:-skipped}",  "time_ms": ${IMG_TIME[syft]:-0},  "size_kb": ${IMG_SIZE[syft]:-0},  "components": ${IMG_COMP[syft]:-0} },
    "trivy": { "status": "${IMG_STATUS[trivy]:-skipped}", "time_ms": ${IMG_TIME[trivy]:-0}, "size_kb": ${IMG_SIZE[trivy]:-0}, "components": ${IMG_COMP[trivy]:-0} }
  },
  "scanning": {
    "grype": { "status": "${SCAN_STATUS[grype]:-skipped}", "time_ms": ${SCAN_TIME[grype]:-0}, "total": ${SCAN_VULNS[grype]:-0}, "critical": ${SCAN_CRIT[grype]:-0}, "high": ${SCAN_HIGH[grype]:-0} },
    "trivy": { "status": "${SCAN_STATUS[trivy]:-skipped}", "time_ms": ${SCAN_TIME[trivy]:-0}, "total": ${SCAN_VULNS[trivy]:-0}, "critical": ${SCAN_CRIT[trivy]:-0}, "high": ${SCAN_HIGH[trivy]:-0} }
  }
}
REPORT_EOF

echo "═══════════════════════════════════════════════════════"
echo "✅ Benchmark complete"
echo "   Report: ${REPORT_FILE}"
echo "   Source SBOMs: ${OUTPUT_DIR}/source/"
echo "   Image SBOMs:  ${OUTPUT_DIR}/image/"
echo "   Scans:        ${OUTPUT_DIR}/scans/"
