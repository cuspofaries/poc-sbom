# Supply Chain Security POC — SBOM Automation Reference Implementation

A production-ready reference implementation for securing software supply chains using Software Bill of Materials (SBOM) generation, signing, attestation, vulnerability scanning, and policy enforcement.

## Table of Contents

- [Why This Matters](#why-this-matters)
- [Architecture Overview](#architecture-overview)
- [The Pipeline: A Deep Dive](#the-pipeline-a-deep-dive)
- [Core Concepts](#core-concepts)
- [Quick Start](#quick-start)
- [GitHub Actions Workflow Explained](#github-actions-workflow-explained)
- [Task Reference](#task-reference)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)
- [References](#references)

---

## Why This Matters

Modern software is built on layers of dependencies. A single container image can contain hundreds or thousands of packages—from your application code to system libraries, language runtimes, and transitive dependencies. **If you don't know what's in your software, you can't secure it.**

### The Supply Chain Security Problem

- **Log4Shell (CVE-2021-44228)**: Organizations scrambled to find which systems contained the vulnerable Log4j library. Those without SBOMs spent weeks manually auditing codebases.
- **SolarWinds**: Attackers compromised build systems to inject malicious code. Cryptographic attestation of build artifacts could have helped detect tampering.
- **Dependency Confusion**: Attackers publish malicious packages with names similar to internal dependencies. Policy enforcement can block unauthorized packages.

### What This POC Demonstrates

This project shows how to:

1. **Generate comprehensive SBOMs** for both source code and container images
2. **Cryptographically sign and attest** SBOMs to prevent tampering
3. **Scan for vulnerabilities** using industry-standard tools
4. **Enforce policies** as code with OPA (Open Policy Agent)
5. **Compare source vs. image** to detect supply chain drift
6. **Automate everything** in CI/CD with zero-trust principles

**This is not a tutorial—it's a reference implementation you can fork and adapt for production use.**

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        CI/CD Pipeline (GitHub Actions)                  │
│                                                                         │
│  ┌──────────┐    ┌──────────────┐    ┌─────────┐    ┌──────────┐      │
│  │  Source  │───▶│ Generate SBOM│───▶│  Sign   │───▶│   Scan   │──┐   │
│  │   Code   │    │  (Source)    │    │ & Attest│    │  (Grype) │  │   │
│  └──────────┘    └──────────────┘    └─────────┘    └──────────┘  │   │
│                                                                     │   │
│  ┌──────────┐    ┌──────────────┐    ┌─────────┐    ┌──────────┐  │   │
│  │Container │───▶│ Generate SBOM│───▶│  Sign   │───▶│   Scan   │──┤   │
│  │  Image   │    │  (Image)     │    │ & Attest│    │  (Trivy) │  │   │
│  └──────────┘    └──────────────┘    └─────────┘    └──────────┘  │   │
│                                                                     │   │
│                     ┌─────────────────┐                            │   │
│                     │  Source vs Image│◀───────────────────────────┘   │
│                     │      Diff       │                                │
│                     └────────┬────────┘                                │
│                              │                                         │
│                              ▼                                         │
│                     ┌─────────────────┐                                │
│                     │  Policy Check   │                                │
│                     │      (OPA)      │                                │
│                     └────────┬────────┘                                │
│                              │                                         │
│                              ▼                                         │
│                     ┌─────────────────┐                                │
│                     │  Upload Results │                                │
│                     │   (Artifacts)   │                                │
│                     └─────────────────┘                                │
└─────────────────────────────────────────────────────────────────────────┘
             │
             ▼
   ┌─────────────────────┐         ┌─────────────────────┐
   │  Dependency-Track   │         │   OCI Registry      │
   │  (Monitoring)       │         │   (Artifact Storage)│
   │  • Dashboard        │         │   • Signed SBOMs    │
   │  • VEX Support      │         │   • Attestations    │
   │  • Daily Rescans    │         │   • Signatures      │
   └─────────────────────┘         └─────────────────────┘
```

### Design Principles

1. **Zero Logic in CI YAML**: All pipeline logic lives in `Taskfile.yml` and shell scripts. The GitHub Actions workflow is just 104 lines of glue code that calls `task <target>`. This makes the pipeline portable to Azure DevOps, GitLab CI, or any other CI system in minutes.

2. **Defense in Depth**: Multiple layers of security controls:
   - SBOM generation (know what you ship)
   - Cryptographic signing (prove integrity)
   - Vulnerability scanning (find known CVEs)
   - Policy enforcement (block violations)
   - Continuous monitoring (detect new threats)

3. **Idempotent & Reproducible**: Every step can be run locally or in CI with identical results. No "works on my machine" problems.

4. **Tool Agnostic**: The POC uses Syft, Grype, Trivy, cdxgen, and OPA, but the scripts are designed to be swappable. Each tool generates CycloneDX 1.5 JSON—a standard format.

---

## The Pipeline: A Deep Dive

### Step-by-Step Breakdown

The GitHub Actions workflow (`.github/workflows/supply-chain.yml`) executes these steps in order:

#### 1. **Install Task** (~5 seconds)

```yaml
- name: Install Task
  run: sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin
```

**What it does**: Downloads the Task binary (a modern alternative to Make). Task is a task runner that executes targets defined in `Taskfile.yml`.

**Why**: We use Task instead of Make for better cross-platform support, cleaner syntax, and built-in dependency management.

---

#### 2. **Install SBOM Tools** (~45 seconds)

```bash
sudo task install
```

**What it does**: Installs all SBOM and security tools in parallel:

- **Syft** (v1.41.2): SBOM generator for containers and filesystems
- **Grype** (v0.107.1): Vulnerability scanner
- **Trivy** (v0.69.1): Multi-purpose security scanner
- **cdxgen**: Source code SBOM generator (supports Python, Node.js, Java, Go, etc.)
- **Cosign**: Cryptographic signing tool (Sigstore)
- **OPA**: Open Policy Agent for policy evaluation
- **ORAS**: OCI Registry as Storage (for pushing SBOMs to registries)

**How it works**: The `install` task in `Taskfile.yml` runs sub-tasks (`install:syft`, `install:grype`, etc.) that:

1. Download the latest binary from GitHub Releases
2. Verify checksums (where supported)
3. Install to `/usr/local/bin` with proper permissions
4. Use retry logic (3 attempts) to handle transient network errors

**Retry Example** (from `Taskfile.yml:69-87`):
```yaml
install:syft:
  desc: "Install Syft (SBOM generator)"
  cmds:
    - |
      for i in 1 2 3; do
        echo "Attempt $i to install syft..."
        if curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin; then
          echo "✅ Syft installed successfully"
          break
        else
          echo "⚠️  Attempt $i failed, retrying in 5 seconds..."
          sleep 5
        fi
        if [ $i -eq 3 ]; then
          echo "❌ Failed to install syft after 3 attempts"
          exit 1
        fi
      done
```

**Why retry logic?**: GitHub's CDN occasionally returns HTTP 502 errors. The retry logic makes the pipeline more resilient.

---

#### 3. **Build Image** (~30 seconds)

```bash
task build IMAGE_TAG=${{ github.sha }}
```

**What it does**: Builds the container image from `app/Dockerfile` and tags it with the git commit SHA.

**Command executed**:
```bash
docker build -t supply-chain-poc:9b6f9af ./app
```

**The Application**: A minimal Python web server (`app/app.py`) with intentionally diverse dependencies:

```python
# requirements.txt
flask==3.0.0           # Large dependency tree
requests==2.31.0       # HTTP client
pyyaml==6.0.1          # YAML parsing
cryptography==41.0.0   # Native libs (shows OS-level deps)
psycopg2-binary==2.9.9 # Database driver (adds libpq)
jinja2==3.1.2          # Intentionally older for vuln testing
```

**Why these dependencies?**: They create a rich SBOM with:
- Python packages (application layer)
- Native libraries (cryptography, psycopg2)
- Transitive dependencies (Flask pulls in Werkzeug, Click, etc.)
- Known CVEs for testing vulnerability scanning

---

#### 4. **Generate SBOMs (Source + Image, All Tools)** (~60 seconds)

```bash
task sbom:generate:all IMAGE_TAG=${{ github.sha }}
```

This step generates **6 different SBOMs** to compare tools:

| File | Tool | Target | Format |
|------|------|--------|--------|
| `output/sbom/source/sbom-source-cdxgen.json` | cdxgen | Source code | CycloneDX 1.5 |
| `output/sbom/source/sbom-source-trivy.json` | Trivy | Filesystem | CycloneDX 1.5 |
| `output/sbom/source/sbom-source-syft.json` | Syft | Directory | CycloneDX 1.5 |
| `output/sbom/image/sbom-image-syft.json` | Syft | Container | CycloneDX 1.5 |
| `output/sbom/image/sbom-image-trivy.json` | Trivy | Container | CycloneDX 1.5 |
| `output/sbom/image/buildkit/` | Docker BuildKit | Build-time | SPDX 2.3 |

**Example Output** (sbom-image-syft.json, truncated):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:...",
  "metadata": {
    "timestamp": "2026-02-09T23:14:32Z",
    "tools": [
      {
        "vendor": "anchore",
        "name": "syft",
        "version": "1.41.2"
      }
    ],
    "component": {
      "type": "container",
      "name": "supply-chain-poc",
      "version": "9b6f9af"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "flask",
      "version": "3.0.0",
      "purl": "pkg:pypi/flask@3.0.0",
      "licenses": [
        {
          "license": {
            "id": "BSD-3-Clause"
          }
        }
      ]
    },
    {
      "type": "operating-system",
      "name": "debian",
      "version": "12",
      "purl": "pkg:deb/debian/debian@12"
    },
    {
      "type": "library",
      "name": "openssl",
      "version": "3.0.11-1~deb12u2",
      "purl": "pkg:deb/debian/openssl@3.0.11-1~deb12u2"
    }
    // ... 2,900+ more components
  ]
}
```

**Key Fields Explained**:

- **`purl` (Package URL)**: Universal identifier for packages. Format: `pkg:<type>/<namespace>/<name>@<version>`. Example: `pkg:pypi/flask@3.0.0` uniquely identifies Flask 3.0.0 from PyPI.

- **`type`**: Component category:
  - `library`: Application dependencies (Flask, requests)
  - `operating-system`: Base OS packages (Debian, Alpine)
  - `file`: System files (`/etc/passwd`, `/usr/bin/bash`)

- **`licenses`**: SPDX license identifiers for compliance tracking.

**Why 6 SBOMs?**: Each tool has strengths:

- **cdxgen**: Best for source code analysis. Understands lockfiles (requirements.txt, package-lock.json).
- **Syft**: Fast, accurate for containers. Detects OS packages + language deps.
- **Trivy**: Deep security focus. Includes vulnerability data in SBOM metadata.
- **BuildKit**: Native Docker SBOM. Generated during `docker build --sbom=true`.

**The Benchmark** (`task benchmark`) measures:
- Execution time
- Memory usage
- Component count
- License detection accuracy
- False positive rate

---

#### 5. **Sign SBOM** (~10 seconds)

```bash
task sbom:sign IMAGE_TAG=${{ github.sha }}
```

**What it does**: Cryptographically signs the SBOM to prove it hasn't been tampered with.

**Signing Modes** (auto-detected):

| Mode | When | How | Output |
|------|------|-----|--------|
| **Attestation** (preferred) | Image pushed to registry | `cosign attest --predicate sbom.json <image>` | Signature stored in registry, linked to image digest |
| **Blob Signing** (fallback) | Local/CI without registry | `cosign sign-blob --key cosign.key sbom.json` | `sbom.json.bundle` file |

**In This Workflow**: Since the image isn't pushed to a registry, it uses **blob signing** with an ephemeral keypair.

**Steps**:

1. Generate keypair: `cosign generate-key-pair` (with `COSIGN_PASSWORD=""` for non-interactive mode)
   - Creates: `cosign.key` (private), `cosign.pub` (public)

2. Sign SBOM: `cosign sign-blob --key cosign.key --bundle sbom.json.bundle sbom.json`
   - Output: `sbom-image-syft.json.bundle`

3. Bundle contains:
   - The signature (base64-encoded)
   - The signing certificate
   - Timestamp from Rekor (Sigstore's transparency log)

**Verification** (later):

```bash
cosign verify-blob \
  --key cosign.pub \
  --bundle sbom-image-syft.json.bundle \
  sbom-image-syft.json
```

**Output**:
```
Verified OK
```

If the SBOM is modified (even changing a single byte), verification fails:

```bash
echo "tampering" >> sbom-image-syft.json
cosign verify-blob --key cosign.pub --bundle sbom.json.bundle sbom.json
# Error: invalid signature
```

**Why Signing Matters**:

- **Non-Repudiation**: Proves who generated the SBOM and when.
- **Integrity**: Detects tampering (accidental or malicious).
- **Compliance**: Required by NIST SSDF, SLSA Level 2+, and many security frameworks.

**Production Best Practice**: Use **keyless signing** with OIDC (OpenID Connect). GitHub Actions provides an OIDC token that Cosign uses to sign without managing keys:

```yaml
permissions:
  id-token: write  # Required for keyless signing

# In signing script:
COSIGN_EXPERIMENTAL=1 cosign sign <image>
```

No private keys to secure. Signatures are backed by Sigstore's Fulcio CA and logged to Rekor.

---

#### 7. **Scan Vulnerabilities (Source + Image)** (~45 seconds)

```bash
task sbom:scan:all
```

**What it does**: Scans both source and image SBOMs for known vulnerabilities (CVEs).

**Commands executed**:

```bash
# Scan image SBOM with Grype
grype sbom:output/sbom/image/sbom-image-syft.json \
  -o json \
  --file output/scans/scan-image-grype.json

# Scan image SBOM with Trivy
trivy sbom output/sbom/image/sbom-image-syft.json \
  --format json \
  --output output/scans/scan-image-trivy.json

# Scan source SBOM with Grype
grype sbom:output/sbom/source/sbom-source-cdxgen.json \
  -o json \
  --file output/scans/scan-source-grype.json
```

**Example Output** (scan-image-grype.json, truncated):

```json
{
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2023-5363",
        "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2023-5363",
        "severity": "High",
        "description": "Issue summary: A bug has been identified in the processing of key and initialisation vector (IV) lengths...",
        "cvss": [
          {
            "version": "3.1",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "metrics": {
              "baseScore": 7.5
            }
          }
        ]
      },
      "artifact": {
        "name": "openssl",
        "version": "3.0.11-1~deb12u2",
        "type": "deb",
        "purl": "pkg:deb/debian/openssl@3.0.11-1~deb12u2"
      },
      "matchDetails": [
        {
          "type": "exact-direct-match",
          "matcher": "dpkg-matcher",
          "searchedBy": {
            "distro": {
              "type": "debian",
              "version": "12"
            }
          }
        }
      ]
    }
    // ... 47 more vulnerabilities found
  ],
  "source": {
    "type": "sbom",
    "target": {
      "userInput": "output/sbom/image/sbom-image-syft.json"
    }
  },
  "descriptor": {
    "name": "grype",
    "version": "0.107.1",
    "db": {
      "built": "2026-02-09T12:34:01Z",
      "schemaVersion": 5
    }
  }
}
```

**Key Fields**:

- **`vulnerability.id`**: CVE identifier (e.g., CVE-2023-5363)
- **`vulnerability.severity`**: Critical, High, Medium, Low, Negligible
- **`vulnerability.cvss`**: CVSS score (0-10 scale)
- **`artifact.purl`**: Exact package with the vulnerability
- **`matchDetails.type`**: How the match was found:
  - `exact-direct-match`: Package version exactly matches vulnerable version
  - `exact-indirect-match`: Transitive dependency
  - `fuzzy-match`: Version range match

**Source vs. Image Scan Results**:

- **Source scan**: ~5 vulnerabilities (only declared dependencies)
- **Image scan**: ~48 vulnerabilities (includes OS packages, transitive deps)

**Why scan both?**

- **Source scan**: Fast feedback loop during development. If `requirements.txt` adds a known-bad package, fail the PR immediately.
- **Image scan**: Complete security posture. Detects vulnerabilities in:
  - Transitive dependencies (Flask → Werkzeug → MarkupSafe)
  - Base image (Debian packages)
  - System libraries (OpenSSL, zlib)

**Grype vs. Trivy**:

| Tool | Strength | Weakness |
|------|----------|----------|
| **Grype** | Fast, low false positives, great SBOM support | Smaller vulnerability database |
| **Trivy** | Comprehensive DB (including malware, secrets), multi-scanner | Can be noisy (more false positives) |

**Best Practice**: Run both in CI. Grype for gating (strict), Trivy for defense-in-depth.

---

#### 8. **Policy Check** (~3 seconds)

```bash
task sbom:policy
```

**What it does**: Evaluates the SBOM against security policies defined in `policies/sbom-compliance.rego` using OPA (Open Policy Agent).

**Example Policies**:

**DENY Rules** (fail the pipeline):

```rego
# Deny components without version
deny contains msg if {
  some component in input.components
  not component.version
  component.type != "file"  # Exclude system files
  msg := sprintf("Component '%s' has no version specified", [component.name])
}

# Deny blocked packages (known supply chain attacks)
blocked_packages := {
  "event-stream",    # Compromised in 2018
  "ua-parser-js",    # Compromised in 2021
  "colors",          # Sabotaged by maintainer
}

deny contains msg if {
  some component in input.components
  component.name in blocked_packages
  msg := sprintf("BLOCKED package: '%s' - known supply chain risk", [component.name])
}

# Deny if SBOM has zero components
deny contains msg if {
  count(input.components) == 0
  msg := "SBOM contains zero components - generation failed"
}
```

**WARN Rules** (advisory, don't fail):

```rego
# Warn on unapproved licenses
approved_licenses := {"MIT", "Apache-2.0", "BSD-3-Clause", "ISC"}

warn contains msg if {
  some component in input.components
  some license_entry in component.licenses
  license_id := license_entry.license.id
  not license_id in approved_licenses
  msg := sprintf("Unapproved license '%s' in '%s'", [license_id, component.name])
}

# Warn if too many components (possible bloat)
warn contains msg if {
  count(input.components) > 500
  msg := sprintf("High component count: %d - consider cleanup", [count(input.components)])
}
```

**Example Output**:

```
📋 Evaluating SBOM against policies...
   SBOM:     ./output/sbom/image/sbom-image-syft.json
   Policies: ./policies/

── Deny Rules (blocking) ──
   ✅ No violations found

── Warn Rules (advisory) ──
   ⚠️  2 warnings:
      • Unapproved license 'LGPL-2.1' in component 'chardet@5.1.0'
      • High component count: 2919 - consider dependency cleanup

── Statistics ──
   Total components: 2919
   Libraries:        185
   OS packages:      2715
   With version:     2917
   With purl:        2900
   With license:     2450
```

**Policy Customization**:

Edit `policies/sbom-compliance.rego` to add:

- **Custom license policies**: Block GPL, require commercial licenses
- **Vulnerability thresholds**: Deny if any CRITICAL CVE found
- **Dependency limits**: Block if >X transitive dependencies
- **Namespace restrictions**: Only allow packages from approved sources

**Why Policy as Code?**

- **Shift-Left Security**: Block violations before code reaches production
- **Audit Trail**: Policy changes are versioned in Git
- **Automation**: No manual security reviews for every PR
- **Consistency**: Same rules across all projects

---

#### 9. **Run Benchmark** (~120 seconds)

```bash
task benchmark IMAGE_TAG=${{ github.sha }}
```

**What it does**: Executes all SBOM generation tools and compares their performance and accuracy.

**Metrics Collected**:

```json
{
  "benchmark_results": {
    "cdxgen": {
      "execution_time_seconds": 12.4,
      "memory_mb": 145,
      "components_found": 22,
      "with_licenses": 22,
      "with_purls": 22,
      "unique_components": 22
    },
    "syft_dir": {
      "execution_time_seconds": 3.8,
      "memory_mb": 67,
      "components_found": 35,
      "with_licenses": 28,
      "with_purls": 35,
      "unique_components": 35
    },
    "syft_image": {
      "execution_time_seconds": 8.2,
      "memory_mb": 112,
      "components_found": 2919,
      "with_licenses": 2450,
      "with_purls": 2900,
      "unique_components": 2919
    },
    "trivy_fs": {
      "execution_time_seconds": 15.7,
      "memory_mb": 203,
      "components_found": 38,
      "with_licenses": 30,
      "with_purls": 38,
      "unique_components": 38
    },
    "trivy_image": {
      "execution_time_seconds": 18.3,
      "memory_mb": 245,
      "components_found": 2967,
      "with_licenses": 2501,
      "with_purls": 2950,
      "unique_components": 2967
    }
  }
}
```

**Analysis**:

| Tool | Speed | Accuracy | Use Case |
|------|-------|----------|----------|
| **Syft (image)** | ⚡⚡⚡ Fast (8s) | High precision | **Recommended for CI/CD** |
| **Trivy (image)** | ⚡⚡ Moderate (18s) | Highest recall | Defense-in-depth scanning |
| **cdxgen** | ⚡ Slow (12s) | Best for source | Development, pre-build |

**Why Benchmark?**

- **Informed Decisions**: Choose the right tool for your use case
- **Regression Testing**: Detect if tool performance degrades over time
- **Cost Analysis**: Faster tools = cheaper CI/CD

---

#### 10. **Upload Artifacts** (~15 seconds)

```yaml
- name: Upload artifacts
  uses: actions/upload-artifact@v4
  if: always()  # Upload even if previous steps failed
  with:
    name: sbom-outputs
    path: output/
    retention-days: 30
```

**What it does**: Uploads all generated files to GitHub Actions artifacts storage.

**Uploaded Files**:

```
output/
├── sbom/
│   ├── source/
│   │   ├── sbom-source-cdxgen.json
│   │   ├── sbom-source-trivy.json
│   │   └── sbom-source-syft.json
│   └── image/
│       ├── sbom-image-syft.json
│       ├── sbom-image-syft.json.bundle (signature)
│       ├── sbom-image-trivy.json
│       └── buildkit/
├── scans/
│   ├── scan-image-grype.json
│   ├── scan-image-trivy.json
│   └── scan-source-grype.json
├── benchmark/
│   └── benchmark-results.json
└── cosign.pub (public key for verification)
```

**Retention**: 30 days. After that, artifacts are deleted automatically.

**Downloading Artifacts**:

```bash
# Via GitHub CLI
gh run download <run-id> --name sbom-outputs

# Via GitHub UI
Actions → Latest Run → Artifacts → sbom-outputs (download zip)
```

**Why Upload Artifacts?**

- **Auditability**: Keep records of what was scanned and when
- **Incident Response**: If a vulnerability is found later, check historical SBOMs
- **Compliance**: SOC 2, ISO 27001, NIST require evidence of security controls

---

### Daily Rescan Job

```yaml
daily-rescan:
  if: github.event_name == 'schedule'
  runs-on: ubuntu-latest
```

**Trigger**: Runs at 2 AM UTC daily via cron schedule.

**What it does**:

1. Download the latest SBOM from artifacts
2. Rescan with Grype and Trivy (using fresh vulnerability databases)
3. Compare new results to previous scans
4. Alert if new HIGH/CRITICAL CVEs found

**Why Daily Rescans?**

New vulnerabilities are discovered constantly. An SBOM generated yesterday might have 0 CVEs. Today's scan might find 5 new ones.

**Example**: Log4Shell (CVE-2021-44228) was disclosed on Dec 9, 2021. Any SBOM generated before that date would show "no vulnerabilities" for Log4j 2.14.1. Running a rescan on Dec 10 would immediately flag it.

---

## Core Concepts

### What is an SBOM?

A **Software Bill of Materials (SBOM)** is a formal, machine-readable inventory of all components in a software artifact.

**Analogy**: Just like food labels list ingredients, an SBOM lists software ingredients.

**Why SBOMs Matter**:

- **U.S. Executive Order 14028** (May 2021): Requires SBOMs for software sold to federal agencies.
- **NIST Secure Software Development Framework (SSDF)**: Recommends SBOMs for all software.
- **SLSA (Supply Chain Levels for Software Artifacts)**: Level 2+ requires SBOMs.

**SBOM Standards**:

| Standard | Steward | Format | Adoption |
|----------|---------|--------|----------|
| **CycloneDX** | OWASP | JSON, XML | High (SBOM-focused, security-oriented) |
| **SPDX** | Linux Foundation | JSON, YAML, RDF | High (legal/licensing focus) |

**This POC uses CycloneDX 1.5** because:
- Native vulnerability extension (VEX support)
- Better tooling for security use cases
- Easier to parse and query with `jq`

---

### Source SBOM vs. Image SBOM

This is the most important concept in this POC.

#### Source SBOM

**What**: Inventory of dependencies declared in your source code.

**When**: Generated from:
- Lockfiles (`requirements.txt`, `package-lock.json`, `go.sum`)
- Manifest files (`pom.xml`, `build.gradle`, `Cargo.toml`)
- Filesystem scans (`pip list`, `npm list`)

**Tools**: cdxgen, Syft (dir mode), Trivy (fs mode)

**Example**: For this Python app, the source SBOM contains:

```json
{
  "components": [
    {"name": "flask", "version": "3.0.0"},
    {"name": "requests", "version": "2.31.0"},
    {"name": "pyyaml", "version": "6.0.1"},
    {"name": "cryptography", "version": "41.0.0"}
    // ... 18 more (22 total)
  ]
}
```

**Use Cases**:
- **Fast CI/CD feedback**: Scan during `git push`, before building
- **Dependency review**: What did this PR add?
- **License compliance**: Are we using GPL code?

---

#### Image SBOM

**What**: Inventory of *everything* in the container image.

**When**: Generated after `docker build` completes.

**Tools**: Syft (image mode), Trivy (image mode), Docker BuildKit

**Example**: For the same app, the image SBOM contains:

```json
{
  "components": [
    // Application dependencies (22 from source)
    {"name": "flask", "version": "3.0.0"},
    {"name": "requests", "version": "2.31.0"},

    // Transitive dependencies (not in requirements.txt)
    {"name": "werkzeug", "version": "3.0.1"},  // Flask dependency
    {"name": "markupsafe", "version": "2.1.3"}, // Jinja2 dependency

    // Operating system packages (2,715 from Debian base)
    {"name": "bash", "version": "5.2.15-2+b2"},
    {"name": "openssl", "version": "3.0.11-1~deb12u2"},
    {"name": "libc6", "version": "2.36-9+deb12u8"},

    // System files
    {"name": "/etc/passwd", "type": "file"},
    {"name": "/usr/bin/python3.11", "type": "file"}
    // ... 2,897 more (2,919 total)
  ]
}
```

**Use Cases**:
- **Vulnerability scanning**: The image is what runs in production
- **Runtime security**: What can an attacker access if they compromise the container?
- **Customer transparency**: "Here's exactly what we ship"

---

#### Source vs. Image: The Delta

**Key Question**: Why does the image have 2,897 more components than the source?

**Answer**:

1. **Transitive Dependencies**: Flask depends on Werkzeug, Click, Blinker, ItsDangerous, MarkupSafe. None are in `requirements.txt`.

2. **Base Image Packages**: `FROM python:3.11-slim` includes:
   - Debian OS (~2,500 packages)
   - Python runtime (~200 packages)
   - System utilities (bash, tar, gzip, etc.)

3. **Native Libraries**: `cryptography` is a Python package, but it depends on:
   - `openssl` (Debian package)
   - `libssl3` (shared library)
   - `libcrypto3` (crypto primitives)

**Why This Matters for Security**:

- **Log4Shell Example**: Your Java app might not directly use Log4j. But if your Docker base image (`FROM openjdk:11`) includes it, you're vulnerable.

- **The Diff Reveals Hidden Risk**:
  ```
  Only in IMAGE: openssl (3.0.11-1~deb12u2) — CVE-2023-5363 (High)
  ```
  Your `requirements.txt` doesn't mention OpenSSL. But it's in your image. Without SBOM diffing, you'd never find it.

---

### Signing and Attestation

#### Blob Signing

**What**: Sign a file (e.g., SBOM) with a private key. Anyone with the public key can verify the file hasn't changed.

**Command**:
```bash
cosign sign-blob --key cosign.key sbom.json --bundle sbom.json.bundle
```

**Output**: `sbom.json.bundle` (contains signature + certificate)

**Verification**:
```bash
cosign verify-blob --key cosign.pub --bundle sbom.json.bundle sbom.json
```

**Pros**:
- Works anywhere (local, CI, air-gapped)
- No infrastructure dependencies

**Cons**:
- Signature is in a separate file (can drift)
- No link to the image digest

---

#### Attestation (In-Toto Format)

**What**: Cryptographically bind an SBOM to a specific container image digest.

**Command**:
```bash
cosign attest \
  --predicate sbom.json \
  --type cyclonedx \
  ghcr.io/yourorg/app:sha256:abc123...
```

**How It Works**:

1. Cosign computes the image digest: `sha256:abc123...`
2. Creates an In-Toto attestation:
   ```json
   {
     "payloadType": "application/vnd.in-toto+json",
     "payload": {
       "subject": [
         {
           "name": "ghcr.io/yourorg/app",
           "digest": {"sha256": "abc123..."}
         }
       ],
       "predicateType": "https://cyclonedx.org/bom",
       "predicate": {
         // The SBOM goes here
       }
     }
   }
   ```
3. Signs the attestation with your key (or OIDC)
4. Pushes the signature to the OCI registry (same repo as the image)

**Storage**:

```
ghcr.io/yourorg/app
├── sha256:abc123... (image)
└── sha256:def456... (attestation, tagged with suffix)
```

**Verification**:

```bash
cosign verify-attestation \
  --type cyclonedx \
  --key cosign.pub \
  ghcr.io/yourorg/app:sha256:abc123...
```

Cosign:
1. Fetches the attestation from the registry
2. Verifies the signature
3. Checks that the SBOM's `subject.digest` matches the image digest

**Pros**:
- **Tamper-Proof**: Signature is immutable (stored in OCI registry)
- **Digest-Linked**: SBOM can't be swapped to a different image
- **Auditability**: Signatures are logged to Rekor (public transparency log)

**Cons**:
- Requires pushing image to a registry
- More complex setup

**When to Use What**:

| Scenario | Use |
|----------|-----|
| Local development | Blob signing |
| CI/CD without registry push | Blob signing |
| Staging/production deployments | Attestation |
| Customer deliverables | Attestation (strongest proof) |

---

### Policy as Code with OPA

**Open Policy Agent (OPA)** is a general-purpose policy engine. You write policies in **Rego** (a declarative language), and OPA evaluates data against those policies.

**Example Policy**:

```rego
package sbom

# Deny if SBOM has a component with a critical CVE
deny contains msg if {
  some vuln in input.vulnerabilities
  vuln.severity == "CRITICAL"
  msg := sprintf("Critical CVE found: %s in %s", [vuln.id, vuln.package])
}
```

**Evaluation**:

```bash
opa eval \
  --data policies/ \
  --input sbom-with-vulns.json \
  'data.sbom.deny'
```

**Output**:

```json
{
  "result": [
    {
      "expressions": [
        {
          "value": [
            "Critical CVE found: CVE-2024-1234 in openssl@3.0.8"
          ]
        }
      ]
    }
  ]
}
```

**Integration**:

The `sbom:policy` task in `Taskfile.yml` runs:

```bash
opa eval --fail-defined --data policies/ --input sbom.json 'data.sbom.deny'
```

**Flags**:
- `--fail-defined`: Exit with code 1 if `deny` returns any results
- `--data policies/`: Load all `.rego` files from `policies/`
- `--input sbom.json`: The SBOM to evaluate

**Custom Policies**:

You can extend `policies/sbom-compliance.rego` to:

**Block High/Critical CVEs**:
```rego
deny contains msg if {
  some vuln in input.vulnerabilities
  vuln.severity in {"CRITICAL", "HIGH"}
  msg := sprintf("High/Critical CVE: %s", [vuln.id])
}
```

**Enforce Dependency Limits**:
```rego
deny contains msg if {
  package_count := count([c | some c in input.components; c.type == "library"])
  package_count > 100
  msg := sprintf("Too many dependencies: %d (max: 100)", [package_count])
}
```

**Require Signed SBOMs**:
```rego
deny contains msg if {
  not input.metadata.properties[_].name == "cdx:signature"
  msg := "SBOM is not signed"
}
```

---

## Quick Start

### Prerequisites

- **Docker** (20.10+)
- **curl**, **jq** (standard tools)
- **Task** (optional, but recommended)

### Installation

```bash
# Clone the repository
git clone https://github.com/cuspofaries/poc-sbom.git
cd poc-sbom

# Install Task (if not already installed)
sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin

# Install all SBOM tools
sudo task install

# Verify installation
task install:verify
```

**Expected output**:

```
✅ Task installed: go-task version v3.36.0
✅ Syft installed: syft 1.41.2
✅ Grype installed: grype 0.107.1
✅ Trivy installed: trivy 0.69.1
✅ cdxgen installed: @cyclonedx/cdxgen 10.9.8
✅ Cosign installed: cosign v2.4.1
✅ OPA installed: opa 0.68.0
✅ ORAS installed: oras 1.2.0
```

---

### Running the Pipeline

**1. Build the container image**:

```bash
task build
```

**Output**:

```
docker build -t supply-chain-poc:latest ./app
[+] Building 12.3s (9/9) FINISHED
 => [1/4] FROM docker.io/library/python:3.11-slim
 => [2/4] COPY requirements.txt /app/
 => [3/4] RUN pip install --no-cache-dir -r /app/requirements.txt
 => [4/4] COPY . /app/
 => exporting to image
✅ Image built: supply-chain-poc:latest
```

**2. Generate SBOMs**:

```bash
task sbom:generate:all
```

**Output**:

```
📦 Generating Source SBOMs (all tools)...
   ✅ cdxgen → output/sbom/source/sbom-source-cdxgen.json (22 components)
   ✅ Trivy → output/sbom/source/sbom-source-trivy.json (38 components)
   ✅ Syft → output/sbom/source/sbom-source-syft.json (35 components)

📦 Generating Image SBOMs (all tools)...
   ✅ Syft → output/sbom/image/sbom-image-syft.json (2919 components)
   ✅ Trivy → output/sbom/image/sbom-image-trivy.json (2967 components)
   ✅ BuildKit → output/sbom/image/buildkit/ (SPDX format)
```

**3. Sign the SBOM**:

```bash
task sbom:sign
```

**Output**:

```
🔐 Signing SBOM for supply-chain-poc:latest...
   SBOM SHA256: 63aeb3996ca3b0c9202c55a0f808c4215278070917ef2b370977091486bda367

── Attempting attestation (digest-linked) ──

── Attestation unavailable, falling back to blob signing ──
   (image not pushed to registry, or registry unreachable)

Using payload from: ./output/sbom/image/sbom-image-syft.json
Signing artifact...
✅ SBOM signed as blob → ./output/sbom/image/sbom-image-syft.json.bundle
   ℹ️  For stronger guarantees, push image to registry and use: task sbom:attest
```

**5. Scan for vulnerabilities**:

```bash
task sbom:scan:all
```

**Output**:

```
🔍 Scanning SBOMs for vulnerabilities...
   ✅ Image scan (Grype) → output/scans/scan-image-grype.json (48 vulnerabilities)
   ✅ Image scan (Trivy) → output/scans/scan-image-trivy.json (52 vulnerabilities)
   ✅ Source scan (Grype) → output/scans/scan-source-grype.json (5 vulnerabilities)
```

**6. Enforce policies**:

```bash
task sbom:policy
```

**Output**:

```
📋 Evaluating SBOM against policies...
   SBOM:     ./output/sbom/image/sbom-image-syft.json
   Policies: ./policies/

── Deny Rules (blocking) ──
   ✅ No violations found

── Warn Rules (advisory) ──
   ⚠️  1 warning:
      • High component count: 2919 - consider dependency cleanup
```

**7. Run full pipeline**:

```bash
task pipeline
```

**Or skip manual steps and run everything**:

```bash
task pipeline:full
```

This runs: `build` → `sbom:generate:all` → `sbom:sign` → `sbom:scan:all` → `sbom:policy` → `benchmark`

---

## GitHub Actions Workflow Explained

The workflow file is at `.github/workflows/supply-chain.yml`.

### Trigger Conditions

```yaml
on:
  push:
    branches: [main]          # Every push to main
  pull_request:
    branches: [main]          # Every PR targeting main
  schedule:
    - cron: '0 2 * * *'       # Daily at 2 AM UTC
  workflow_dispatch:           # Manual trigger from GitHub UI
```

**Why these triggers?**

- **push/PR**: Immediate feedback on code changes
- **schedule**: Daily rescans to catch new CVEs
- **workflow_dispatch**: Ad-hoc testing during development

---

### Permissions

```yaml
permissions:
  contents: read              # Read repository code
  packages: write             # Push to GitHub Container Registry
  id-token: write             # Get OIDC token for keyless signing
  security-events: write      # Upload to GitHub Security tab
```

**Why `id-token: write`?**

GitHub Actions provides an **OIDC (OpenID Connect) token** that Cosign can use for keyless signing. This eliminates the need to manage signing keys.

**How it works**:

1. GitHub issues a short-lived (15 minutes) JWT token
2. Cosign exchanges the token with Sigstore's Fulcio CA for a signing certificate
3. The signature is logged to Rekor (public transparency log)
4. No private keys to secure or rotate

---

### Environment Variables

```yaml
env:
  IMAGE_NAME: supply-chain-poc
  IMAGE_TAG: ${{ github.sha }}          # Git commit SHA
  REGISTRY: ghcr.io/${{ github.repository_owner }}
```

**Why use `github.sha` as the tag?**

- **Immutability**: Every commit gets a unique tag
- **Traceability**: `docker pull ghcr.io/yourorg/app:9b6f9af` → exact commit
- **Rollback**: Revert to a specific commit's image

---

### Job: build-and-scan

**Runs on**: `ubuntu-latest` (currently Ubuntu 22.04)

**Steps**:

1. **Checkout**: Clones the repository
2. **Install Task**: Downloads task binary from https://taskfile.dev
3. **Install SBOM tools**: Runs `sudo task install` (Syft, Grype, Trivy, etc.)
4. **Build image**: `task build IMAGE_TAG=9b6f9af`
5. **Generate SBOMs**: `task sbom:generate:all IMAGE_TAG=9b6f9af`
6. **Sign SBOM**: `task sbom:sign IMAGE_TAG=9b6f9af`
7. **Scan vulnerabilities**: `task sbom:scan:all`
8. **Policy check**: `task sbom:policy`
9. **Run benchmark**: `task benchmark IMAGE_TAG=9b6f9af`
10. **Upload artifacts**: Saves `output/` to GitHub Actions artifacts

**Total runtime**: ~2.5 minutes

---

### Job: daily-rescan

**Trigger**: Only runs on the daily cron schedule (`if: github.event_name == 'schedule'`)

**What it does**:

```yaml
steps:
  - name: Download latest SBOM
    uses: actions/download-artifact@v4
    with:
      name: sbom-outputs
      path: output/

  - name: Rescan for new vulnerabilities
    run: task sbom:scan:all
```

**Why download the old SBOM?**

The SBOM itself doesn't change. But the vulnerability database updates daily. Rescanning the same SBOM with fresh CVE data finds newly-disclosed vulnerabilities.

**Example**:

- **Jan 1**: Scan finds 0 critical CVEs in OpenSSL 3.0.11
- **Jan 5**: New CVE-2024-XXXX disclosed for OpenSSL 3.0.11
- **Jan 6 (daily rescan)**: Scan now finds 1 critical CVE
- **Alert**: Send Slack message to security team

---

## Task Reference

### Installation

```bash
# Install all tools
sudo task install

# Install individual tools
sudo task install:syft
sudo task install:grype
sudo task install:trivy
sudo task install:cdxgen
sudo task install:cosign
sudo task install:opa
sudo task install:oras

# Verify installation
task install:verify
```

---

### SBOM Generation

```bash
# Generate source + image SBOMs (default tools)
task sbom:generate

# Generate source SBOMs (all tools)
task sbom:generate:source

# Generate source SBOM (specific tool)
task sbom:generate:source:cdxgen
task sbom:generate:source:trivy
task sbom:generate:source:syft

# Generate image SBOMs (all tools)
task sbom:generate:image
task sbom:generate:image:trivy
task sbom:generate:image:docker  # Docker BuildKit (SPDX format)

# Generate ALL SBOMs (source + image, all tools)
task sbom:generate:all

```

---

### Signing & Attestation

```bash
# Generate signing keypair (POC only)
task signing:init
# Output: cosign.key, cosign.pub

# Auto-detect: attest if registry available, else blob signing
task sbom:sign

# Force blob signing
task sbom:sign:blob

# Attest SBOM to image digest (requires registry push)
task sbom:attest

# Verify signature
task sbom:verify

# Verify blob signature
task sbom:verify:blob

# Demo: tamper with SBOM and verify detection
task sbom:tamper:test
```

---

### Vulnerability Scanning

```bash
# Scan image SBOM with Grype (default)
task sbom:scan

# Scan image SBOM with Trivy
task sbom:scan:trivy

# Scan source SBOM
task sbom:scan:source

# Scan both source + image with all tools
task sbom:scan:all
```

**Output files**:

- `output/scans/scan-image-grype.json`
- `output/scans/scan-image-trivy.json`
- `output/scans/scan-source-grype.json`

---

### Policy Evaluation

```bash
# Evaluate SBOM against OPA policies
task sbom:policy
```

**Edit policies**:

```bash
vim policies/sbom-compliance.rego
```

**Test policies locally**:

```bash
opa eval \
  --data policies/ \
  --input output/sbom/image/sbom-image-syft.json \
  'data.sbom.deny'
```

---

### Monitoring & Pipelines

```bash
# Start Dependency-Track
task dtrack:up
# Access: http://localhost:8081 (admin/admin)

# Upload SBOM to Dependency-Track
task sbom:upload

# Stop Dependency-Track
task dtrack:down

# Run full pipeline (without build)
task pipeline

# Run full pipeline with build + benchmark
task pipeline:full

# Benchmark all SBOM tools
task benchmark
```

---

### Utility Commands

```bash
# List all available tasks
task --list

# Clean all generated files
task clean

# Build the container image
task build

# Build with custom tag
task build IMAGE_TAG=v1.2.3
```

---

## Troubleshooting

### Issue: `task: command not found`

**Cause**: Task is not installed or not in `$PATH`.

**Solution**:

```bash
sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin
```

Or install via package manager:

```bash
# macOS
brew install go-task

# Arch Linux
pacman -S go-task-bin

# Ubuntu/Debian (via snap)
snap install task --classic
```

---

### Issue: `permission denied` when installing tools

**Cause**: Tools are installed to `/usr/local/bin`, which requires root access.

**Solution**:

```bash
sudo task install
```

**Alternative**: Install to a user-writable directory:

```bash
export INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
export PATH="$INSTALL_DIR:$PATH"

# Modify Taskfile.yml to use $INSTALL_DIR instead of /usr/local/bin
```

---

### Issue: `Error: signing ./output/sbom/sbom.json: create bundle file: open : no such file or directory`

**Cause**: Using an older version of Cosign that doesn't support the `--bundle` flag.

**Solution**: Update Cosign to v2.0+:

```bash
sudo task install:cosign
```

---

### Issue: SBOMs have 0 components

**Possible causes**:

1. **Wrong path**: Check that the tool is scanning the correct directory.

   ```bash
   # Incorrect
   cdxgen /tmp/empty-dir

   # Correct
   cdxgen ./app
   ```

2. **No dependencies detected**: For Python apps, ensure `requirements.txt` or `pyproject.toml` exists.

3. **Tool-specific issue**: Try a different tool:

   ```bash
   # If cdxgen fails, try Syft
   task sbom:generate:source:syft
   ```

---

### Issue: High vulnerability count (500+ CVEs)

**Cause**: You're scanning the **image SBOM**, which includes OS packages. Many CVEs are in base image dependencies (Debian, Alpine, etc.).

**Is this a problem?**

Not necessarily. Most OS CVEs have CVSS scores < 5.0 (Medium) and are mitigated by:

- Default firewall rules
- Non-root user
- Read-only filesystems

**Solutions**:

1. **Filter by severity**:

   ```bash
   grype sbom.json --fail-on critical --fail-on high
   ```

2. **Use distroless base images** (no shell, no package manager):

   ```dockerfile
   FROM gcr.io/distroless/python3-debian12
   ```

3. **Update base image regularly**:

   ```bash
   docker pull python:3.11-slim
   task build
   ```

---

### Issue: Policy check fails with "Component 'bash' has no version"

**Cause**: The policy `deny` rule checks for missing versions:

```rego
deny contains msg if {
  some component in input.components
  not component.version
  msg := sprintf("Component '%s' has no version", [component.name])
}
```

System files (type: `file`) don't have versions.

**Solution**: Already fixed in this repo. The policy now excludes files:

```rego
deny contains msg if {
  some component in input.components
  not component.version
  component.type != "file"  # Exclude system files
  msg := sprintf("Component '%s' has no version", [component.name])
}
```

---

### Issue: `cosign verify-blob` fails with "invalid signature"

**Possible causes**:

1. **Wrong public key**: Ensure you're using the correct `cosign.pub`.

   ```bash
   cosign verify-blob \
     --key cosign.pub \
     --bundle sbom.json.bundle \
     sbom.json
   ```

2. **SBOM was modified**: Even changing whitespace breaks the signature.

   ```bash
   # Re-generate the SBOM
   task sbom:generate
   task sbom:sign
   ```

3. **Bundle file is corrupted**:

   ```bash
   # Check if bundle is valid JSON
   jq . sbom.json.bundle

   # Regenerate signature
   rm sbom.json.bundle
   task sbom:sign:blob
   ```

---

### Issue: Docker build fails with "ERROR [internal] load metadata for docker.io/library/python:3.11-slim"

**Cause**: Docker daemon is not running or can't reach Docker Hub.

**Solution**:

```bash
# Check Docker status
docker info

# If Docker is not running (Linux)
sudo systemctl start docker

# If Docker is not running (macOS)
open -a Docker

# If rate-limited by Docker Hub, login
docker login
```

---

## Best Practices

### 1. Always Scan the Image SBOM in Production

**Why**: The image is what runs. Source SBOMs are incomplete.

**Example**:

```yaml
# ❌ BAD
- name: Scan
  run: grype sbom:output/sbom/source/sbom-source-cdxgen.json

# ✅ GOOD
- name: Scan
  run: grype sbom:output/sbom/image/sbom-image-syft.json
```

---

### 2. Use Keyless Signing in CI/CD

**Why**: No secrets to manage. OIDC tokens are short-lived (15 minutes).

**How**:

```yaml
permissions:
  id-token: write

# In signing step:
env:
  COSIGN_EXPERIMENTAL: 1
run: cosign sign <image>
```

---

### 3. Pin Tool Versions

**Why**: Reproducible builds. If Syft v1.50 introduces a bug, you want to stick with v1.41.

**How**:

Edit `Taskfile.yml`:

```yaml
vars:
  SYFT_VERSION: "1.41.2"

tasks:
  install:syft:
    cmds:
      - curl -sSfL https://github.com/anchore/syft/releases/download/v{{.SYFT_VERSION}}/syft_{{.SYFT_VERSION}}_linux_amd64.tar.gz | tar -xz
```

---

### 4. Enforce Policies Before Deployment

**Why**: Catch violations early (shift-left).

**How**:

```yaml
- name: Policy Check
  run: task sbom:policy

- name: Deploy
  if: success()  # Only deploy if policy passed
  run: kubectl apply -f deployment.yaml
```

---

### 5. Store SBOMs with Images

**Why**: The SBOM and image are coupled. Storing them together ensures they don't drift.

**How**: Use attestation instead of blob signing:

```bash
cosign attest \
  --predicate sbom.json \
  --type cyclonedx \
  ghcr.io/yourorg/app:sha256:abc123
```

The SBOM is now stored in the same OCI registry as the image:

```
ghcr.io/yourorg/app
├── sha256:abc123... (image)
└── sha256:def456... (SBOM attestation)
```

---

### 6. Automate Dependency Updates

**Why**: 80% of vulnerabilities are in outdated dependencies.

**How**: Use **Renovate** (included in this repo):

```json
// renovate.json
{
  "extends": ["config:base"],
  "schedule": ["before 3am on Monday"],
  "automerge": true,
  "automergeType": "pr",
  "packageRules": [
    {
      "matchUpdateTypes": ["patch"],
      "automerge": true
    }
  ]
}
```

Renovate will:
- Check for updates weekly
- Create PRs automatically
- Run CI/CD on each PR
- Auto-merge patch updates if CI passes

---

### 7. Run Daily Rescans

**Why**: New CVEs are disclosed daily. An SBOM generated yesterday might have new vulnerabilities today.

**How**: Already implemented in this repo:

```yaml
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM UTC
```

---

### 8. Use Distroless or Minimal Base Images

**Why**: Fewer components = smaller attack surface.

**Example**:

```dockerfile
# ❌ BAD: 2,900+ components
FROM python:3.11-slim

# ✅ BETTER: ~200 components
FROM python:3.11-alpine

# ✅ BEST: ~50 components
FROM gcr.io/distroless/python3-debian12
```

---

### 9. Fail Fast on Critical CVEs

**Why**: Don't deploy known-vulnerable software.

**How**:

```bash
grype sbom.json --fail-on critical --fail-on high
```

If any Critical or High CVE is found, exit code 1 (fails CI/CD).

---

### 10. Monitor SBOMs in Production

**Why**: Continuous visibility into your software supply chain.

**How**: Use **Dependency-Track**:

```bash
task dtrack:up
task sbom:upload
```

Dependency-Track provides:
- Dashboard of all components
- Automated vulnerability monitoring
- VEX (Vulnerability Exploitability eXchange) support
- License compliance reports
- Trending (component growth over time)

---

## References

### Standards & Specifications

- **CycloneDX**: https://cyclonedx.org/
- **SPDX**: https://spdx.dev/
- **PURL (Package URL)**: https://github.com/package-url/purl-spec
- **In-Toto Attestation**: https://github.com/in-toto/attestation

### Government Frameworks

- **NIST SSDF (Secure Software Development Framework)**: https://csrc.nist.gov/publications/detail/sp/800-218/final
- **NIST SP 800-161 (Supply Chain Risk Management)**: https://csrc.nist.gov/publications/detail/sp/800-161/rev-1/final
- **Executive Order 14028**: https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/
- **SLSA (Supply Chain Levels for Software Artifacts)**: https://slsa.dev/

### Tools

- **Syft**: https://github.com/anchore/syft
- **Grype**: https://github.com/anchore/grype
- **Trivy**: https://github.com/aquasecurity/trivy
- **cdxgen**: https://github.com/CycloneDX/cdxgen
- **Cosign**: https://github.com/sigstore/cosign
- **OPA**: https://www.openpolicyagent.org/
- **Dependency-Track**: https://dependencytrack.org/
- **Task**: https://taskfile.dev/

### Learning Resources

- **CNCF SBOM Guide**: https://www.cncf.io/blog/2024/03/14/a-guide-to-sboms/
- **OWASP Dependency-Track**: https://owasp.org/www-project-dependency-track/
- **Sigstore Documentation**: https://docs.sigstore.dev/
- **OPA Policy Language**: https://www.openpolicyagent.org/docs/latest/policy-language/

### Incident Case Studies

- **Log4Shell (CVE-2021-44228)**: https://en.wikipedia.org/wiki/Log4Shell
- **SolarWinds Supply Chain Attack**: https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a
- **Dependency Confusion**: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

---

## Contributing

This is a reference implementation. Fork it, adapt it, make it yours.

If you find bugs or have improvements, open an issue or PR at:
https://github.com/cuspofaries/poc-sbom

---

## License

MIT License. See `LICENSE` file for details.

---

## Acknowledgments

Built with tools from:
- [Anchore](https://anchore.com/) (Syft, Grype)
- [Aqua Security](https://www.aquasec.com/) (Trivy)
- [OWASP](https://owasp.org/) (CycloneDX, Dependency-Track)
- [Sigstore](https://sigstore.dev/) (Cosign)
- [CNCF](https://www.cncf.io/) (OPA)

Inspired by the work of Kelsey Hightower, who taught us that the best documentation is the one you can run.
