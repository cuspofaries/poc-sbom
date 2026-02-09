# =============================================================================
# Sample multi-stage app for Supply Chain POC
# Intentionally uses a mix of dependencies for SBOM richness
# =============================================================================

# -- Stage 1: Build --
FROM python:3.12-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

COPY . .

# -- Stage 2: Runtime --
FROM python:3.12-slim

LABEL maintainer="anthony@devopsmotion.com"
LABEL org.opencontainers.image.title="supply-chain-poc"
LABEL org.opencontainers.image.description="Sample app for SBOM benchmarking"

# Install some OS packages to enrich SBOM (and introduce known vulns for testing)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /install /usr/local
COPY --from=builder /build/*.py .

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost:8080/health || exit 1

USER 1000:1000

CMD ["python", "app.py"]
