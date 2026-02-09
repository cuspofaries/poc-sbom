# 🔐 Supply Chain Security POC — SBOM Toolchain

POC de benchmarking et d'évaluation des outils liés à la sécurisation de la chaîne d'approvisionnement logiciel, avec focus sur la gestion des **SBOM** (Software Bill of Materials).

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         CI/CD Pipeline                               │
│                    (GitHub / Azure DevOps)                            │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  BUILD → GENERATE SBOMs → ATTEST → SCAN → POLICY → STORE            │
│           ├─ Source SBOM   (Cosign) (Grype)  (OPA)  (OCI Reg)        │
│           │  (cdxgen/Trivy/Syft)                                     │
│           └─ Image SBOM                                              │
│              (Syft/Trivy)          ↕ DIFF                            │
│                                (source vs image)                     │
│                                                                      │
│                    ↓ Upload                                           │
│           ┌───────────────────┐                                      │
│           │ Dependency-Track  │ ← Monitoring continu                 │
│           │  (Dashboard/VEX)  │ ← Rescan quotidien                   │
│           └───────────────────┘                                      │
│                                                                      │
│           ┌───────────────────┐                                      │
│           │    Renovate       │ ← Mise à jour auto des deps          │
│           └───────────────────┘                                      │
└──────────────────────────────────────────────────────────────────────┘
```

## Concept clé : Source SBOM vs Image SBOM

| | Source SBOM | Image SBOM |
|---|---|---|
| **Quand** | Avant/pendant le build | Après build de l'image |
| **Quoi** | Dépendances déclarées (requirements.txt, package.json...) | Tout ce qui est embarqué (OS packages, libs système, transitifs) |
| **Question** | "Qu'est-ce que mon code déclare ?" | "Qu'est-ce qui est réellement livré ?" |
| **Outils** | cdxgen, Trivy (fs), Syft (dir) | Syft, Trivy (image) |
| **Usage** | SCA, licences, gating rapide | Scan vulnérabilités complet, compliance |

Le **diff source/image** révèle l'écart entre le déclaré et le livré — c'est un point clé pour le client.

## Prérequis

- Docker + Docker Compose
- [Task](https://taskfile.dev/installation/) (go-task)
- jq, curl

```bash
# Installer Task
sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin

# Installer tous les outils SBOM
sudo task install

# Vérifier l'installation
task install:verify
```

## Quickstart

```bash
# 1. Build l'image de test
task build

# 2. Pipeline complet (source + image SBOM → sign → scan → policy → diff)
task pipeline

# 3. Benchmark comparatif des outils
task benchmark
```

## Commandes disponibles

```
task --list
```

### Génération

| Commande | Description |
|---|---|
| `task sbom:generate` | Génère source + image SBOM (outils par défaut) |
| `task sbom:generate:source` | Source SBOM avec tous les outils disponibles |
| `task sbom:generate:source:cdxgen` | Source SBOM — cdxgen |
| `task sbom:generate:source:trivy` | Source SBOM — Trivy (fs) |
| `task sbom:generate:source:syft` | Source SBOM — Syft (dir) |
| `task sbom:generate:image` | Image SBOM — Syft (défaut) |
| `task sbom:generate:image:trivy` | Image SBOM — Trivy |
| `task sbom:generate:image:docker` | Image SBOM — Docker BuildKit natif |
| `task sbom:generate:all` | Tous les outils, source + image |
| `task sbom:diff` | Compare source vs image SBOM |

### Signature & Attestation

| Commande | Description |
|---|---|
| `task sbom:attest` | Atteste la SBOM au digest de l'image (nécessite registry) |
| `task sbom:sign` | Auto : attest si registry dispo, blob sinon |
| `task sbom:sign:blob` | Signe la SBOM comme fichier standalone |
| `task sbom:verify` | Vérifie signature et intégrité |
| `task sbom:verify:blob` | Vérifie signature blob |
| `task sbom:tamper:test` | Démo de détection d'altération |

### Scan & Policies

| Commande | Description |
|---|---|
| `task sbom:scan` | Scan vulnérabilités image SBOM (Grype) |
| `task sbom:scan:trivy` | Scan vulnérabilités image SBOM (Trivy) |
| `task sbom:scan:source` | Scan vulnérabilités source SBOM |
| `task sbom:scan:all` | Tous les scanners, source + image |
| `task sbom:policy` | Évaluation OPA |

### Monitoring & Pipeline

| Commande | Description |
|---|---|
| `task dtrack:up` | Démarre Dependency-Track |
| `task sbom:upload` | Upload vers Dependency-Track |
| `task benchmark` | Benchmark comparatif complet |
| `task pipeline` | Pipeline complet |
| `task pipeline:full` | Pipeline + build + benchmark |

## Stack d'outils

| Fonction | Outil | Rôle |
|---|---|---|
| Orchestration | **Taskfile** (go-task) | Task runner portable |
| Source SBOM | **cdxgen**, Trivy, Syft | Dépendances déclarées |
| Image SBOM | **Syft**, Trivy | Contenu réel embarqué |
| Format | **CycloneDX 1.5** | Standard SBOM |
| Attestation | **Cosign** (Sigstore) | Lie SBOM au digest image |
| Scan vuln | **Grype**, Trivy | Détection CVE |
| Politique | **OPA** (Rego) | Policy-as-code |
| Monitoring | **Dependency-Track** | Dashboard, VEX, alertes |
| Updates | **Renovate** | PRs automatiques |
| Stockage | **OCI / ORAS** | Artifacts registry |

## Signing : Attestation vs Blob

| | Attestation (`sbom:attest`) | Blob (`sbom:sign:blob`) |
|---|---|---|
| **Force** | Lie SBOM au digest de l'image | Prouve que le fichier n'a pas changé |
| **Preuve** | "Cette SBOM décrit cette image" | "Ce fichier n'a pas été modifié" |
| **Stockage** | Dans le registry, à côté de l'image | Fichier .sig à côté du .json |
| **Requis** | Image poussée dans un registry | Rien (fonctionne en local) |
| **Recommandé** | Production, CI/CD | POC local, dev |

Le script `sbom:sign` auto-détecte : il tente l'attestation d'abord, et tombe en fallback sur blob si le registry n'est pas disponible.

## Portabilité GitHub → Azure DevOps

- Toute la logique est dans `Taskfile.yml` + `scripts/`
- Les pipelines CI ne font qu'appeler `task <target>`
- Migration = réécrire ~30 lignes de YAML

Pipelines fournis :
- `.github/workflows/supply-chain.yml`
- `azure-pipelines/pipeline.yml`

Les scripts de signing auto-détectent l'environnement CI (GitHub OIDC / Azure AD / keypair local).

## Structure du projet

```
.
├── Taskfile.yml                     # Point d'entrée unique
├── app/                             # Application de test
│   ├── Dockerfile
│   ├── app.py
│   └── requirements.txt
├── scripts/
│   ├── sbom-generate-source.sh      # Génération source SBOM
│   ├── sbom-attest.sh               # Attestation digest (fort)
│   ├── sbom-sign.sh                 # Auto-detect attest/blob
│   ├── sbom-verify.sh               # Vérification intégrité
│   ├── sbom-tamper-test.sh          # Démo altération
│   ├── sbom-diff-source-image.sh    # Diff source vs image
│   ├── sbom-policy.sh               # Évaluation OPA
│   ├── sbom-upload-dtrack.sh        # Upload Dependency-Track
│   └── benchmark.sh                 # Benchmark comparatif
├── policies/
│   └── sbom-compliance.rego         # Règles OPA
├── renovate.json
├── docker-compose.dtrack.yml
├── .github/workflows/               # GitHub Actions
├── azure-pipelines/                  # Azure DevOps
└── output/                           # Résultats (gitignored)
    ├── sbom/
    │   ├── source/                   # SBOMs source
    │   └── image/                    # SBOMs image
    ├── scans/
    └── benchmark/
```
