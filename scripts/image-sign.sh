#!/usr/bin/env bash
# =============================================================================
# image-sign.sh - Sign a container image with cosign
#
# Usage: ./scripts/image-sign.sh <image> [cosign-key]
#
# Proves provenance: "this image was produced by this pipeline."
# Supports:
#   - GitHub Actions keyless (OIDC → Fulcio + Rekor)
#   - Azure DevOps keyless (Azure AD Workload Identity)
#   - Keypair (POC / air-gapped)
# =============================================================================
set -euo pipefail

IMAGE="${1:?Usage: $0 <image> [cosign-key]}"
COSIGN_KEY="${2:-cosign.key}"

echo "🔏 Signing image: ${IMAGE}"

# --- Resolve image digest ---
IMAGE_REF="$IMAGE"
DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || true)

if [ -z "$DIGEST" ]; then
    if command -v crane &>/dev/null; then
        DIGEST_SHA=$(crane digest "$IMAGE" 2>/dev/null || true)
        if [ -n "$DIGEST_SHA" ]; then
            DIGEST="${IMAGE%%:*}@${DIGEST_SHA}"
        fi
    fi
fi

if [ -n "$DIGEST" ]; then
    IMAGE_REF="$DIGEST"
    echo "   Digest: ${DIGEST}"
else
    echo "   ⚠️  Could not resolve digest, signing by tag"
fi

# --- Detect environment and sign ---

if [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
    echo "   Mode: GitHub Actions keyless (OIDC)"
    cosign sign --yes "$IMAGE_REF"

elif [ -n "${SYSTEM_OIDCREQUESTURI:-}" ]; then
    echo "   Mode: Azure DevOps keyless (Workload Identity)"
    AZURE_TOKEN=$(curl -s \
        -H "Content-Type: application/json" \
        -d '{}' \
        "${SYSTEM_OIDCREQUESTURI}?api-version=7.1&audience=sigstore" \
        -H "Authorization: Bearer ${SYSTEM_ACCESSTOKEN}" \
        | jq -r '.oidcToken')
    COSIGN_EXPERIMENTAL=1 cosign sign --yes \
        --identity-token "$AZURE_TOKEN" \
        "$IMAGE_REF"

elif [ -f "$COSIGN_KEY" ]; then
    echo "   Mode: Keypair (${COSIGN_KEY})"
    COSIGN_PASSWORD="" cosign sign --yes \
        --key "$COSIGN_KEY" \
        "$IMAGE_REF"

else
    echo "❌ No signing method available."
    echo "   Options:"
    echo "   - Run in GitHub Actions or Azure DevOps (keyless)"
    echo "   - Generate a keypair: task signing:init"
    exit 1
fi

echo ""
echo "✅ Image signed: ${IMAGE_REF}"
echo "   Verify with: cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com ${IMAGE_REF}"
