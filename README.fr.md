# POC Sécurité de la Chaîne d'Approvisionnement — Implémentation de Référence pour l'Automatisation SBOM

Une implémentation de référence prête pour la production permettant de sécuriser les chaînes d'approvisionnement logicielles via la génération de SBOM (Software Bill of Materials), la signature, l'attestation, l'analyse des vulnérabilités et l'application de politiques.

## Table des Matières

- [Pourquoi C'est Important](#pourquoi-cest-important)
- [Vue d'Ensemble de l'Architecture](#vue-densemble-de-larchitecture)
- [Le Pipeline : Analyse Approfondie](#le-pipeline--analyse-approfondie)
- [Concepts Fondamentaux](#concepts-fondamentaux)
- [Démarrage Rapide](#démarrage-rapide)
- [Explication du Workflow GitHub Actions](#explication-du-workflow-github-actions)
- [Référence des Tâches](#référence-des-tâches)
- [Dépannage](#dépannage)
- [Bonnes Pratiques](#bonnes-pratiques)
- [Références](#références)

---

## Pourquoi C'est Important

Les logiciels modernes sont construits sur des couches de dépendances. Une seule image conteneur peut contenir des centaines ou des milliers de paquets—depuis votre code applicatif jusqu'aux bibliothèques système, runtimes de langages et dépendances transitives. **Si vous ne savez pas ce qui se trouve dans votre logiciel, vous ne pouvez pas le sécuriser.**

### Le Problème de la Sécurité de la Chaîne d'Approvisionnement

- **Log4Shell (CVE-2021-44228)** : Les organisations ont dû chercher frénétiquement quels systèmes contenaient la bibliothèque Log4j vulnérable. Celles sans SBOM ont passé des semaines à auditer manuellement leurs bases de code.
- **SolarWinds** : Des attaquants ont compromis les systèmes de build pour injecter du code malveillant. L'attestation cryptographique des artefacts de build aurait pu aider à détecter la falsification.
- **Dependency Confusion** : Des attaquants publient des paquets malveillants avec des noms similaires aux dépendances internes. L'application de politiques peut bloquer les paquets non autorisés.

### Ce que Démontre ce POC

Ce projet montre comment :

1. **Générer des SBOM complets** pour le code source et les images conteneur
2. **Signer et attester cryptographiquement** les SBOM pour empêcher la falsification
3. **Analyser les vulnérabilités** avec des outils standards de l'industrie
4. **Appliquer des politiques** sous forme de code avec OPA (Open Policy Agent)
5. **Tout automatiser** en CI/CD avec des principes zero-trust

**Ce n'est pas un tutoriel—c'est une implémentation de référence que vous pouvez forker et adapter pour une utilisation en production.**

---

## Vue d'Ensemble de l'Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Pipeline CI/CD (GitHub Actions)                  │
│                                                                         │
│  ┌──────────┐    ┌──────────────┐    ┌─────────┐    ┌──────────┐      │
│  │  Code    │───▶│ Génération   │───▶│  Signer │───▶│  Scanner │──┐   │
│  │  Source  │    │ SBOM (Source)│    │& Attester│    │  (Trivy) │  │   │
│  └──────────┘    └──────────────┘    └─────────┘    └──────────┘  │   │
│                                                                     │   │
│  ┌──────────┐    ┌──────────────┐    ┌─────────┐    ┌──────────┐  │   │
│  │ Image    │───▶│ Génération   │───▶│  Signer │───▶│  Scanner │──┤   │
│  │Conteneur │    │ SBOM (Image) │    │& Attester│    │  (Trivy) │  │   │
│  └──────────┘    └──────────────┘    └─────────┘    └──────────┘  │   │
│                                                                     │   │
│                     ┌─────────────────┐                              │   │
│                     │ Vérification    │◀─────────────────────────────┘   │
│                     │   Politiques    │                                  │
│                     │      (OPA)      │                                  │
│                     └────────┬────────┘                                  │
│                              │                                          │
│                              ▼                                          │
│                     ┌─────────────────┐                                  │
│                     │  Téléversement  │                                  │
│                     │   Résultats     │                                  │
│                     │  (Artefacts)    │                                  │
│                     └─────────────────┘                                  │
└─────────────────────────────────────────────────────────────────────────┘
             │
             ▼
   ┌─────────────────────┐         ┌─────────────────────┐
   │  Dependency-Track   │         │  Registre OCI       │
   │  (Monitoring)       │         │  (Stockage)         │
   │  • Tableau de bord  │         │  • SBOM signés      │
   │  • Support VEX      │         │  • Attestations     │
   │  • Rescans quotid.  │         │  • Signatures       │
   └─────────────────────┘         └─────────────────────┘
```

### Principes de Conception

1. **Zéro Logique dans le YAML CI** : Toute la logique du pipeline réside dans `Taskfile.yml` et les scripts shell. Le workflow GitHub Actions ne fait que 104 lignes de code de liaison qui appelle `task <cible>`. Cela rend le pipeline portable vers Azure DevOps, GitLab CI, ou tout autre système CI en quelques minutes.

2. **Défense en Profondeur** : Plusieurs couches de contrôles de sécurité :
   - Génération SBOM (savoir ce que vous livrez)
   - Signature cryptographique (prouver l'intégrité)
   - Analyse des vulnérabilités (trouver les CVE connus)
   - Application de politiques (bloquer les violations)
   - Monitoring continu (détecter les nouvelles menaces)

3. **Idempotent & Reproductible** : Chaque étape peut être exécutée localement ou en CI avec des résultats identiques. Pas de problème "ça marche sur ma machine".

4. **Agnostique aux Outils** : Ce POC utilise Trivy, cdxgen et OPA, mais les scripts sont conçus pour être interchangeables. Trivy gère à la fois la génération SBOM et l'analyse des vulnérabilités. Chaque outil génère du CycloneDX 1.5 JSON—un format standard.

---

## Le Pipeline : Analyse Approfondie

### Décomposition Étape par Étape

Le workflow GitHub Actions (`.github/workflows/supply-chain.yml`) exécute ces étapes dans l'ordre :

#### 1. **Installation de Task** (~5 secondes)

```yaml
- name: Install Task
  run: sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin
```

**Ce qu'il fait** : Télécharge le binaire Task (une alternative moderne à Make). Task est un exécuteur de tâches qui exécute les cibles définies dans `Taskfile.yml`.

**Pourquoi** : Nous utilisons Task au lieu de Make pour un meilleur support multi-plateforme, une syntaxe plus claire et une gestion intégrée des dépendances.

---

#### 2. **Installation des Outils SBOM** (~45 secondes)

```bash
sudo task install
```

**Ce qu'il fait** : Installe tous les outils SBOM et de sécurité en parallèle :

- **Trivy** (v0.69.1) : Scanner de sécurité multi-usage (génération SBOM + analyse de vulnérabilités)
- **cdxgen** : Générateur SBOM pour code source (supporte Python, Node.js, Java, Go, etc.)
- **Cosign** : Outil de signature cryptographique (Sigstore)
- **OPA** : Open Policy Agent pour l'évaluation de politiques
- **ORAS** : OCI Registry as Storage (pour pousser les SBOM vers les registres)

**Comment ça marche** : La tâche `install` dans `Taskfile.yml` exécute des sous-tâches (`install:trivy`, `install:cdxgen`, etc.) qui :

1. Téléchargent le dernier binaire depuis GitHub Releases
2. Vérifient les checksums (quand supporté)
3. Installent dans `/usr/local/bin` avec les permissions appropriées
4. Utilisent une logique de retry (3 tentatives) pour gérer les erreurs réseau transitoires

**Pourquoi la logique de retry ?** : Le CDN de GitHub renvoie occasionnellement des erreurs HTTP 502. La logique de retry rend le pipeline plus résilient.

---

#### 3. **Construction de l'Image** (~30 secondes)

```bash
task build IMAGE_TAG=${{ github.sha }}
```

**Ce qu'il fait** : Construit l'image conteneur depuis `app/Dockerfile` et la tagge avec le SHA du commit git.

**Commande exécutée** :
```bash
docker build -t supply-chain-poc:9b6f9af ./app
```

**L'Application** : Un serveur web Python minimal (`app/app.py`) avec des dépendances intentionnellement diverses :

```python
# requirements.txt
flask==3.0.0           # Arbre de dépendances important
requests==2.31.0       # Client HTTP
pyyaml==6.0.1          # Parsing YAML
cryptography==41.0.0   # Bibliothèques natives (montre les deps OS)
psycopg2-binary==2.9.9 # Pilote base de données (ajoute libpq)
jinja2==3.1.2          # Intentionnellement plus ancien pour test vulnérabilités
```

**Pourquoi ces dépendances ?** : Elles créent un SBOM riche avec :
- Paquets Python (couche application)
- Bibliothèques natives (cryptography, psycopg2)
- Dépendances transitives (Flask tire Werkzeug, Click, etc.)
- CVE connus pour tester l'analyse des vulnérabilités

---

#### 4. **Génération des SBOM (Source + Image, Tous les Outils)** (~60 secondes)

```bash
task sbom:generate:all IMAGE_TAG=${{ github.sha }}
```

Cette étape génère **4 SBOM différents** pour comparer les outils :

| Fichier | Outil | Cible | Format |
|---------|-------|-------|--------|
| `output/sbom/source/sbom-source-cdxgen.json` | cdxgen | Code source | CycloneDX 1.5 |
| `output/sbom/source/sbom-source-trivy.json` | Trivy | Système de fichiers | CycloneDX 1.5 |
| `output/sbom/image/sbom-image-trivy.json` | Trivy | Conteneur | CycloneDX 1.5 |
| `output/sbom/image/buildkit/` | Docker BuildKit | Build-time | SPDX 2.3 |

**Exemple de Sortie** (sbom-image-trivy.json, tronqué) :

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:...",
  "metadata": {
    "timestamp": "2026-02-09T23:14:32Z",
    "tools": [
      {
        "vendor": "aquasecurity",
        "name": "trivy",
        "version": "0.69.1"
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
    // ... 2 900+ composants supplémentaires
  ]
}
```

**Champs Clés Expliqués** :

- **`purl` (Package URL)** : Identifiant universel pour les paquets. Format : `pkg:<type>/<namespace>/<name>@<version>`. Exemple : `pkg:pypi/flask@3.0.0` identifie de manière unique Flask 3.0.0 depuis PyPI.

- **`type`** : Catégorie du composant :
  - `library` : Dépendances applicatives (Flask, requests)
  - `operating-system` : Paquets OS de base (Debian, Alpine)
  - `file` : Fichiers système (`/etc/passwd`, `/usr/bin/bash`)

- **`licenses`** : Identifiants de licence SPDX pour la conformité.

**Pourquoi 4 SBOM ?** : Chaque outil a ses forces :

- **cdxgen** : Meilleur pour l'analyse du code source. Comprend les lockfiles (requirements.txt, package-lock.json).
- **Trivy** : Focus sécurité approfondi. Gère à la fois la génération SBOM et l'analyse des vulnérabilités. Inclut les données de vulnérabilités dans les métadonnées SBOM.
- **BuildKit** : SBOM natif Docker. Généré pendant `docker build --sbom=true`.

---

#### 5. **Signature du SBOM** (~10 secondes)

```bash
task sbom:sign IMAGE_TAG=${{ github.sha }}
```

**Ce qu'il fait** : Signe cryptographiquement le SBOM pour prouver qu'il n'a pas été falsifié.

**Modes de Signature** (auto-détectés) :

| Mode | Quand | Comment | Sortie |
|------|-------|---------|--------|
| **Attestation** (préféré) | Image poussée vers registre | `cosign attest --predicate sbom.json <image>` | Signature stockée dans registre, liée au digest de l'image |
| **Signature Blob** (fallback) | Local/CI sans registre | `cosign sign-blob --key cosign.key sbom.json` | Fichier `sbom.json.bundle` |

**Dans ce Workflow** : Comme l'image n'est pas poussée vers un registre, il utilise **la signature blob** avec une paire de clés éphémère.

**Étapes** :

1. Générer la paire de clés : `cosign generate-key-pair` (avec `COSIGN_PASSWORD=""` pour le mode non-interactif)
   - Crée : `cosign.key` (privée), `cosign.pub` (publique)

2. Signer le SBOM : `cosign sign-blob --key cosign.key --bundle sbom.json.bundle sbom.json`
   - Sortie : `sbom-image-trivy.json.bundle`

3. Le bundle contient :
   - La signature (encodée en base64)
   - Le certificat de signature
   - Timestamp depuis Rekor (journal de transparence Sigstore)

**Vérification** (plus tard) :

```bash
cosign verify-blob \
  --key cosign.pub \
  --bundle sbom-image-trivy.json.bundle \
  sbom-image-trivy.json
```

**Sortie** :
```
Verified OK
```

Si le SBOM est modifié (même en changeant un seul octet), la vérification échoue :

```bash
echo "tampering" >> sbom-image-trivy.json
cosign verify-blob --key cosign.pub --bundle sbom.json.bundle sbom.json
# Error: invalid signature
```

**Pourquoi la Signature Est Importante** :

- **Non-Répudiation** : Prouve qui a généré le SBOM et quand.
- **Intégrité** : Détecte la falsification (accidentelle ou malveillante).
- **Conformité** : Requis par NIST SSDF, SLSA Level 2+, et de nombreux frameworks de sécurité.

**Bonne Pratique Production** : Utilisez **la signature keyless** avec OIDC (OpenID Connect). GitHub Actions fournit un token OIDC que Cosign utilise pour signer sans gérer de clés :

```yaml
permissions:
  id-token: write  # Requis pour la signature keyless

# Dans le script de signature :
COSIGN_EXPERIMENTAL=1 cosign sign <image>
```

Pas de clés privées à sécuriser. Les signatures sont adossées par le CA Fulcio de Sigstore et enregistrées dans Rekor.

---

#### 7. **Scan des Vulnérabilités (Source + Image)** (~45 secondes)

```bash
task sbom:scan:all
```

**Ce qu'il fait** : Scanne les SBOM source et image pour les vulnérabilités connues (CVE).

**Commandes exécutées** :

```bash
# Scanner le SBOM image avec Trivy
trivy sbom output/sbom/image/sbom-image-trivy.json \
  --format json \
  --output output/scans/scan-image-trivy.json

# Scanner le SBOM source avec Trivy
trivy sbom output/sbom/source/sbom-source-cdxgen.json \
  --format json \
  --output output/scans/scan-source-trivy.json
```

**Exemple de Sortie** (scan-image-trivy.json, tronqué) :

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
    // ... 47 vulnérabilités supplémentaires trouvées
  ],
  "source": {
    "type": "sbom",
    "target": {
      "userInput": "output/sbom/image/sbom-image-trivy.json"
    }
  },
  "descriptor": {
    "name": "trivy",
    "version": "0.69.1",
    "db": {
      "built": "2026-02-09T12:34:01Z",
      "schemaVersion": 5
    }
  }
}
```

**Champs Clés** :

- **`vulnerability.id`** : Identifiant CVE (ex: CVE-2023-5363)
- **`vulnerability.severity`** : Critical, High, Medium, Low, Negligible
- **`vulnerability.cvss`** : Score CVSS (échelle 0-10)
- **`artifact.purl`** : Paquet exact avec la vulnérabilité
- **`matchDetails.type`** : Comment la correspondance a été trouvée :
  - `exact-direct-match` : Version du paquet correspond exactement à la version vulnérable
  - `exact-indirect-match` : Dépendance transitive
  - `fuzzy-match` : Correspondance de plage de version

**Résultats Scan Source vs. Image** :

- **Scan source** : ~5 vulnérabilités (seulement dépendances déclarées)
- **Scan image** : ~48 vulnérabilités (inclut paquets OS, deps transitives)

**Pourquoi scanner les deux ?**

- **Scan source** : Boucle de feedback rapide pendant le développement. Si `requirements.txt` ajoute un paquet connu-mauvais, fail la PR immédiatement.
- **Scan image** : Posture de sécurité complète. Détecte les vulnérabilités dans :
  - Dépendances transitives (Flask -> Werkzeug -> MarkupSafe)
  - Image de base (paquets Debian)
  - Bibliothèques système (OpenSSL, zlib)

---

#### 8. **Vérification des Politiques** (~3 secondes)

```bash
task sbom:policy
```

**Ce qu'il fait** : Évalue le SBOM contre les politiques de sécurité définies dans `policies/sbom-compliance.rego` en utilisant OPA (Open Policy Agent).

**Exemples de Politiques** :

**Règles DENY** (échouent le pipeline) :

```rego
# Refuser les composants sans version
deny contains msg if {
  some component in input.components
  not component.version
  component.type != "file"  # Exclure les fichiers système
  msg := sprintf("Component '%s' has no version specified", [component.name])
}

# Refuser les paquets bloqués (attaques connues de la chaîne d'approvisionnement)
blocked_packages := {
  "event-stream",    # Compromis en 2018
  "ua-parser-js",    # Compromis en 2021
  "colors",          # Saboté par le mainteneur
}

deny contains msg if {
  some component in input.components
  component.name in blocked_packages
  msg := sprintf("BLOCKED package: '%s' - known supply chain risk", [component.name])
}

# Refuser si le SBOM a zéro composant
deny contains msg if {
  count(input.components) == 0
  msg := "SBOM contains zero components - generation failed"
}
```

**Règles WARN** (advisory, n'échouent pas) :

```rego
# Avertir sur les licences non approuvées
approved_licenses := {"MIT", "Apache-2.0", "BSD-3-Clause", "ISC"}

warn contains msg if {
  some component in input.components
  some license_entry in component.licenses
  license_id := license_entry.license.id
  not license_id in approved_licenses
  msg := sprintf("Unapproved license '%s' in '%s'", [license_id, component.name])
}

# Avertir si trop de composants (possible bloat)
warn contains msg if {
  count(input.components) > 500
  msg := sprintf("High component count: %d - consider cleanup", [count(input.components)])
}
```

**Exemple de Sortie** :

```
📋 Évaluation du SBOM contre les politiques...
   SBOM:     ./output/sbom/image/sbom-image-trivy.json
   Policies: ./policies/

── Règles Deny (bloquantes) ──
   ✅ Aucune violation trouvée

── Règles Warn (advisory) ──
   ⚠️  2 avertissements:
      • Licence non approuvée 'LGPL-2.1' dans le composant 'chardet@5.1.0'
      • Nombre élevé de composants: 2967 - envisagez un nettoyage des dépendances

── Statistiques ──
   Total composants: 2919
   Bibliothèques:    185
   Paquets OS:       2715
   Avec version:     2917
   Avec purl:        2900
   Avec licence:     2450
```

**Personnalisation des Politiques** :

Éditez `policies/sbom-compliance.rego` pour ajouter :

- **Politiques de licence personnalisées** : Bloquer GPL, exiger des licences commerciales
- **Seuils de vulnérabilités** : Refuser si une CVE CRITIQUE est trouvée
- **Limites de dépendances** : Bloquer si >X dépendances transitives
- **Restrictions de namespace** : Autoriser seulement les paquets de sources approuvées

**Pourquoi Politique en tant que Code ?**

- **Shift-Left Security** : Bloquer les violations avant que le code n'atteigne la production
- **Piste d'Audit** : Les changements de politique sont versionnés dans Git
- **Automatisation** : Pas de revues de sécurité manuelles pour chaque PR
- **Cohérence** : Mêmes règles pour tous les projets

**Politiques Custom par Repo (Socle + Fusion)** :

Les repos consommateurs peuvent ajouter des règles OPA spécifiques au projet **en plus** des politiques de base. Le reusable workflow détecte automatiquement un dossier `policies/` dans le repo consommateur et fusionne les deux ensembles de règles.

Fonctionnement :
1. **Socle** (`poc-sbom/policies/`) : Toujours appliqué, non-overridable
2. **Custom** (`<repo-consommateur>/policies/`) : Optionnel, fusionné par OPA

Pour ajouter des politiques custom, créez un dossier `policies/` dans votre repo avec des fichiers `.rego` utilisant `package sbom` :

```rego
# mon-app/policies/project-policies.rego
package sbom

import rego.v1

project_blocked := {"moment", "request"}

deny contains msg if {
    some component in input.components
    component.name in project_blocked
    msg := sprintf("[project] '%s' n'est pas autorisé", [component.name])
}
```

**Contrainte** : Ne pas redéfinir les variables du socle (`approved_licenses`, `blocked_packages`). OPA lancerait une erreur de conflit. Créez plutôt de nouvelles règles avec vos propres variables.

---

#### 9. **Téléversement des Artefacts** (~15 secondes)

```yaml
- name: Upload artifacts
  uses: actions/upload-artifact@v4
  if: always()  # Téléverser même si les étapes précédentes ont échoué
  with:
    name: sbom-outputs
    path: output/
    retention-days: 30
```

**Ce qu'il fait** : Téléverse tous les fichiers générés vers le stockage d'artefacts GitHub Actions.

**Fichiers Téléversés** :

```
output/
├── sbom/
│   ├── source/
│   │   ├── sbom-source-cdxgen.json
│   │   └── sbom-source-trivy.json
│   └── image/
│       ├── sbom-image-trivy.json
│       ├── sbom-image-trivy.json.bundle (signature)
│       └── buildkit/
├── scans/
│   ├── scan-image-trivy.json
│   └── scan-source-trivy.json
└── cosign.pub (clé publique pour vérification)
```

**Rétention** : 30 jours. Après cela, les artefacts sont automatiquement supprimés.

**Téléchargement des Artefacts** :

```bash
# Via GitHub CLI
gh run download <run-id> --name sbom-outputs

# Via GitHub UI
Actions → Latest Run → Artifacts → sbom-outputs (télécharger zip)
```

**Pourquoi Téléverser les Artefacts ?**

- **Auditabilité** : Conserver des enregistrements de ce qui a été scanné et quand
- **Réponse aux Incidents** : Si une vulnérabilité est trouvée plus tard, vérifier les SBOM historiques
- **Conformité** : SOC 2, ISO 27001, NIST exigent des preuves de contrôles de sécurité

---

### Job de Rescan Quotidien

```yaml
daily-rescan:
  if: github.event_name == 'schedule'
  runs-on: ubuntu-latest
```

**Déclencheur** : S'exécute à 2h UTC quotidiennement via la planification cron.

**Ce qu'il fait** :

1. Télécharge le dernier SBOM des artefacts
2. Rescanne avec Trivy (en utilisant des bases de données de vulnérabilités fraîches)
3. Compare les nouveaux résultats aux scans précédents
4. Alerte si de nouvelles CVE HIGH/CRITICAL sont trouvées

**Pourquoi les Rescans Quotidiens ?**

De nouvelles vulnérabilités sont découvertes constamment. Un SBOM généré hier peut avoir 0 CVE. Le scan d'aujourd'hui peut en trouver 5 nouvelles.

**Exemple** : Log4Shell (CVE-2021-44228) a été divulgué le 9 décembre 2021. Tout SBOM généré avant cette date montrerait "pas de vulnérabilités" pour Log4j 2.14.1. Exécuter un rescan le 10 décembre l'aurait immédiatement signalé.

---

## Concepts Fondamentaux

### Qu'est-ce qu'un SBOM ?

Un **Software Bill of Materials (SBOM)** est un inventaire formel, lisible par machine, de tous les composants dans un artefact logiciel.

**Analogie** : Tout comme les étiquettes alimentaires listent les ingrédients, un SBOM liste les ingrédients logiciels.

**Pourquoi les SBOM Sont Importants** :

- **Executive Order 14028 des États-Unis** (Mai 2021) : Exige des SBOM pour les logiciels vendus aux agences fédérales.
- **NIST Secure Software Development Framework (SSDF)** : Recommande les SBOM pour tous les logiciels.
- **SLSA (Supply Chain Levels for Software Artifacts)** : Niveau 2+ nécessite des SBOM.

**Standards SBOM** :

| Standard | Gestionnaire | Format | Adoption |
|----------|--------------|--------|----------|
| **CycloneDX** | OWASP | JSON, XML | Élevée (focalisé SBOM, orienté sécurité) |
| **SPDX** | Linux Foundation | JSON, YAML, RDF | Élevée (focus légal/licensing) |

**Ce POC utilise CycloneDX 1.5** parce que :
- Extension native de vulnérabilités (support VEX)
- Meilleurs outils pour cas d'usage sécurité
- Plus facile à parser et interroger avec `jq`

---

### SBOM Source vs. SBOM Image

C'est le concept le plus important de ce POC.

#### SBOM Source

**Quoi** : Inventaire des dépendances déclarées dans votre code source.

**Quand** : Généré depuis :
- Lockfiles (`requirements.txt`, `package-lock.json`, `go.sum`)
- Fichiers manifestes (`pom.xml`, `build.gradle`, `Cargo.toml`)
- Scans du système de fichiers (`pip list`, `npm list`)

**Outils** : cdxgen, Trivy (mode fs)

**Exemple** : Pour cette app Python, le SBOM source contient :

```json
{
  "components": [
    {"name": "flask", "version": "3.0.0"},
    {"name": "requests", "version": "2.31.0"},
    {"name": "pyyaml", "version": "6.0.1"},
    {"name": "cryptography", "version": "41.0.0"}
    // ... 18 de plus (22 au total)
  ]
}
```

**Cas d'Usage** :
- **Feedback CI/CD rapide** : Scanner pendant `git push`, avant de construire
- **Revue des dépendances** : Qu'est-ce que cette PR a ajouté ?
- **Conformité des licences** : Utilisons-nous du code GPL ?

---

#### SBOM Image

**Quoi** : Inventaire de *tout* dans l'image conteneur.

**Quand** : Généré après la complétion de `docker build`.

**Outils** : Trivy (mode image), Docker BuildKit

**Exemple** : Pour la même app, le SBOM image contient :

```json
{
  "components": [
    // Dépendances applicatives (22 depuis la source)
    {"name": "flask", "version": "3.0.0"},
    {"name": "requests", "version": "2.31.0"},

    // Dépendances transitives (pas dans requirements.txt)
    {"name": "werkzeug", "version": "3.0.1"},  // Dépendance Flask
    {"name": "markupsafe", "version": "2.1.3"}, // Dépendance Jinja2

    // Paquets système d'exploitation (2 715 depuis la base Debian)
    {"name": "bash", "version": "5.2.15-2+b2"},
    {"name": "openssl", "version": "3.0.11-1~deb12u2"},
    {"name": "libc6", "version": "2.36-9+deb12u8"},

    // Fichiers système
    {"name": "/etc/passwd", "type": "file"},
    {"name": "/usr/bin/python3.11", "type": "file"}
    // ... 2 897 de plus (2 919 au total)
  ]
}
```

**Cas d'Usage** :
- **Scan des vulnérabilités** : L'image est ce qui tourne en production
- **Sécurité runtime** : À quoi un attaquant peut-il accéder s'il compromet le conteneur ?
- **Transparence client** : "Voici exactement ce que nous livrons"

---

#### Source vs. Image : Le Delta

**Question Clé** : Pourquoi l'image a-t-elle 2 897 composants de plus que la source ?

**Réponse** :

1. **Dépendances Transitives** : Flask dépend de Werkzeug, Click, Blinker, ItsDangerous, MarkupSafe. Aucun n'est dans `requirements.txt`.

2. **Paquets de l'Image de Base** : `FROM python:3.11-slim` inclut :
   - Debian OS (~2 500 paquets)
   - Python runtime (~200 paquets)
   - Utilitaires système (bash, tar, gzip, etc.)

3. **Bibliothèques Natives** : `cryptography` est un paquet Python, mais il dépend de :
   - `openssl` (paquet Debian)
   - `libssl3` (bibliothèque partagée)
   - `libcrypto3` (primitives crypto)

**Pourquoi C'est Important pour la Sécurité** :

- **Exemple Log4Shell** : Votre app Java pourrait ne pas utiliser directement Log4j. Mais si votre image Docker de base (`FROM openjdk:11`) l'inclut, vous êtes vulnérable.

- **Le Diff Révèle le Risque Caché** :
  ```
  Seulement dans IMAGE: openssl (3.0.11-1~deb12u2) — CVE-2023-5363 (High)
  ```
  Votre `requirements.txt` ne mentionne pas OpenSSL. Mais c'est dans votre image. Sans diff SBOM, vous ne le trouveriez jamais.

---

### Signature et Attestation

#### Signature Blob

**Quoi** : Signer un fichier (ex: SBOM) avec une clé privée. Quiconque a la clé publique peut vérifier que le fichier n'a pas changé.

**Commande** :
```bash
cosign sign-blob --key cosign.key sbom.json --bundle sbom.json.bundle
```

**Sortie** : `sbom.json.bundle` (contient signature + certificat)

**Vérification** :
```bash
cosign verify-blob --key cosign.pub --bundle sbom.json.bundle sbom.json
```

**Avantages** :
- Fonctionne partout (local, CI, air-gapped)
- Pas de dépendances d'infrastructure

**Inconvénients** :
- La signature est dans un fichier séparé (peut dériver)
- Pas de lien au digest de l'image

---

#### Attestation (Format In-Toto)

**Quoi** : Lier cryptographiquement un SBOM à un digest d'image conteneur spécifique.

**Commande** :
```bash
cosign attest \
  --predicate sbom.json \
  --type cyclonedx \
  ghcr.io/yourorg/app:sha256:abc123...
```

**Comment Ça Marche** :

1. Cosign calcule le digest de l'image : `sha256:abc123...`
2. Crée une attestation In-Toto :
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
         // Le SBOM va ici
       }
     }
   }
   ```
3. Signe l'attestation avec votre clé (ou OIDC)
4. Pousse la signature vers le registre OCI (même repo que l'image)

**Stockage** :

```
ghcr.io/yourorg/app
├── sha256:abc123... (image)
└── sha256:def456... (attestation, taggée avec suffixe)
```

**Vérification** :

```bash
cosign verify-attestation \
  --type cyclonedx \
  --key cosign.pub \
  ghcr.io/yourorg/app:sha256:abc123...
```

Cosign :
1. Récupère l'attestation depuis le registre
2. Vérifie la signature
3. Vérifie que le `subject.digest` du SBOM correspond au digest de l'image

**Avantages** :
- **Inviolable** : La signature est immuable (stockée dans le registre OCI)
- **Lié au Digest** : Le SBOM ne peut pas être échangé vers une image différente
- **Auditabilité** : Les signatures sont enregistrées dans Rekor (journal de transparence public)

**Inconvénients** :
- Nécessite de pousser l'image vers un registre
- Configuration plus complexe

**Quand Utiliser Quoi** :

| Scénario | Utiliser |
|----------|----------|
| Développement local | Signature blob |
| CI/CD sans push registre | Signature blob |
| Déploiements staging/production | Attestation |
| Livrables clients | Attestation (preuve la plus forte) |

---

### Politique en tant que Code avec OPA

**Open Policy Agent (OPA)** est un moteur de politiques généraliste. Vous écrivez des politiques en **Rego** (un langage déclaratif), et OPA évalue les données contre ces politiques.

**Exemple de Politique** :

```rego
package sbom

# Refuser si le SBOM a un composant avec une CVE critique
deny contains msg if {
  some vuln in input.vulnerabilities
  vuln.severity == "CRITICAL"
  msg := sprintf("Critical CVE found: %s in %s", [vuln.id, vuln.package])
}
```

**Évaluation** :

```bash
opa eval \
  --data policies/ \
  --input sbom-with-vulns.json \
  'data.sbom.deny'
```

**Sortie** :

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

**Intégration** :

La tâche `sbom:policy` dans `Taskfile.yml` exécute :

```bash
opa eval --fail-defined --data policies/ --input sbom.json 'data.sbom.deny'
```

**Flags** :
- `--fail-defined` : Sortir avec le code 1 si `deny` retourne des résultats
- `--data policies/` : Charger tous les fichiers `.rego` depuis `policies/`
- `--input sbom.json` : Le SBOM à évaluer

**Politiques Personnalisées** :

Vous pouvez étendre le socle en éditant `policies/sbom-compliance.rego`, ou — pour les repos consommateurs utilisant le reusable workflow — ajouter des règles spécifiques au projet dans votre propre dossier `policies/`.

**Bloquer les CVE High/Critical** :
```rego
deny contains msg if {
  some vuln in input.vulnerabilities
  vuln.severity in {"CRITICAL", "HIGH"}
  msg := sprintf("High/Critical CVE: %s", [vuln.id])
}
```

**Appliquer des Limites de Dépendances** :
```rego
deny contains msg if {
  package_count := count([c | some c in input.components; c.type == "library"])
  package_count > 100
  msg := sprintf("Too many dependencies: %d (max: 100)", [package_count])
}
```

**Exiger des SBOM Signés** :
```rego
deny contains msg if {
  not input.metadata.properties[_].name == "cdx:signature"
  msg := "SBOM is not signed"
}
```

### Politiques Custom par Repo

Le reusable workflow supporte un modèle **socle + fusion** pour les politiques OPA :

```
poc-sbom/policies/              ← Socle (toujours appliqué, non-overridable)
├── sbom-compliance.rego        ← approved_licenses, blocked_packages, règles deny/warn

repo-consommateur/policies/     ← Custom (optionnel, fusionné avec le socle)
├── project-policies.rego       ← Règles deny/warn spécifiques au projet
```

**Fonctionnement** :

1. Le reusable workflow checkout le repo du toolchain SBOM et le repo consommateur
2. Si `policies/` existe dans le repo consommateur, OPA charge les deux répertoires (`-d socle/ -d custom/`)
3. Les règles des deux répertoires sont fusionnées : tous les ensembles `deny` et `warn` sont combinés
4. Les règles du socle ne peuvent pas être écrasées — elles sont toujours appliquées

**Ajouter des Politiques Custom à Votre Repo** :

1. Créer un dossier `policies/` dans votre repository
2. Ajouter des fichiers `.rego` utilisant `package sbom` et `import rego.v1`
3. Ajouter de nouvelles règles `deny contains ...` ou `warn contains ...`
4. Push — le reusable workflow les détectera et les fusionnera automatiquement

**Exemple** (`policies/project-policies.rego`) :

```rego
package sbom

import rego.v1

# Bloquer les paquets obsolètes dans ce projet
project_blocked := {"moment", "request"}

deny contains msg if {
    some component in input.components
    component.name in project_blocked
    msg := sprintf("[project] Le paquet '%s' n'est pas autorisé", [component.name])
}

# Avertir sur les licences GPL-3.0
warn contains msg if {
    some component in input.components
    some license_entry in component.licenses
    license_entry.license.id == "GPL-3.0-only"
    msg := sprintf("[project] GPL-3.0 trouvé dans '%s' — revue requise", [component.name])
}
```

**Important** : Ne **pas** redéfinir les variables du socle (`approved_licenses`, `blocked_packages`). OPA ne supporte pas la redéfinition de variables dans le même package — il lèvera une erreur de conflit. Créez plutôt vos propres variables (ex : `project_blocked`).

**Sans politiques custom** : Si votre repo n'a pas de dossier `policies/`, seules les règles du socle sont appliquées. Aucun changement nécessaire — entièrement rétrocompatible.

---

## Démarrage Rapide

### Prérequis

- **Docker** (20.10+)
- **curl**, **jq** (outils standards)
- **Task** (optionnel, mais recommandé)

### Installation

```bash
# Cloner le repository
git clone https://github.com/cuspofaries/poc-sbom.git
cd poc-sbom

# Installer Task (si pas déjà installé)
sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin

# Installer tous les outils SBOM
sudo task install

# Vérifier l'installation
task install:verify
```

**Sortie attendue** :

```
✅ Task installed: go-task version v3.36.0
✅ Trivy installed: trivy 0.69.1
✅ cdxgen installed: @cyclonedx/cdxgen 10.9.8
✅ Cosign installed: cosign v2.4.1
✅ OPA installed: opa 0.68.0
✅ ORAS installed: oras 1.2.0
```

---

### Exécution du Pipeline

**1. Construire l'image conteneur** :

```bash
task build
```

**Sortie** :

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

**2. Générer les SBOM** :

```bash
task sbom:generate:all
```

**Sortie** :

```
📦 Génération des SBOM Source (tous les outils)...
   ✅ cdxgen → output/sbom/source/sbom-source-cdxgen.json (22 composants)
   ✅ Trivy → output/sbom/source/sbom-source-trivy.json (38 composants)

📦 Génération des SBOM Image (tous les outils)...
   ✅ Trivy → output/sbom/image/sbom-image-trivy.json (2967 composants)
   ✅ BuildKit → output/sbom/image/buildkit/ (format SPDX)
```

**3. Signer le SBOM** :

```bash
task sbom:sign
```

**Sortie** :

```
🔐 Signature du SBOM pour supply-chain-poc:latest...
   SBOM SHA256: 63aeb3996ca3b0c9202c55a0f808c4215278070917ef2b370977091486bda367

── Tentative d'attestation (lié au digest) ──

── Attestation non disponible, fallback vers signature blob ──
   (image non poussée vers registre, ou registre inaccessible)

Using payload from: ./output/sbom/image/sbom-image-trivy.json
Signing artifact...
✅ SBOM signé en tant que blob → ./output/sbom/image/sbom-image-trivy.json.bundle
   ℹ️  Pour de meilleures garanties, poussez l'image vers le registre et utilisez: task sbom:attest
```

**5. Scanner les vulnérabilités** :

```bash
task sbom:scan:all
```

**Sortie** :

```
🔍 Scan des SBOM pour les vulnérabilités...
   ✅ Scan image (Trivy) → output/scans/scan-image-trivy.json (52 vulnérabilités)
   ✅ Scan source (Trivy) → output/scans/scan-source-trivy.json (5 vulnérabilités)
```

**6. Appliquer les politiques** :

```bash
task sbom:policy
```

**Sortie** :

```
📋 Évaluation du SBOM contre les politiques...
   SBOM:     ./output/sbom/image/sbom-image-trivy.json
   Policies: ./policies/

── Règles Deny (bloquantes) ──
   ✅ Aucune violation trouvée

── Règles Warn (advisory) ──
   ⚠️  1 avertissement:
      • Nombre élevé de composants: 2967 - envisagez un nettoyage des dépendances
```

**7. Exécuter le pipeline complet** :

```bash
task pipeline
```

**Ou sauter les étapes manuelles et tout exécuter** :

```bash
task pipeline:full
```

Cela exécute : `build` → `sbom:generate:all` → `sbom:sign` → `sbom:scan:all` → `sbom:policy`

---

## Explication du Workflow GitHub Actions

Le fichier workflow est à `.github/workflows/supply-chain.yml`.

### Conditions de Déclenchement

```yaml
on:
  push:
    branches: [main]          # Chaque push sur main
  pull_request:
    branches: [main]          # Chaque PR ciblant main
  schedule:
    - cron: '0 2 * * *'       # Quotidien à 2h UTC
  workflow_dispatch:           # Déclenchement manuel depuis l'UI GitHub
```

**Pourquoi ces déclencheurs ?**

- **push/PR** : Feedback immédiat sur les changements de code
- **schedule** : Rescans quotidiens pour attraper les nouvelles CVE
- **workflow_dispatch** : Tests ad-hoc pendant le développement

---

### Permissions

```yaml
permissions:
  contents: read              # Lire le code du repository
  packages: write             # Pousser vers GitHub Container Registry
  id-token: write             # Obtenir le token OIDC pour signature keyless
  security-events: write      # Téléverser vers l'onglet Security GitHub
```

**Pourquoi `id-token: write` ?**

GitHub Actions fournit un **token OIDC (OpenID Connect)** que Cosign peut utiliser pour la signature keyless. Cela élimine le besoin de gérer des clés de signature.

**Comment ça marche** :

1. GitHub émet un token JWT à courte durée de vie (15 minutes)
2. Cosign échange le token avec le CA Fulcio de Sigstore pour un certificat de signature
3. La signature est enregistrée dans Rekor (journal de transparence public)
4. Pas de clés privées à sécuriser ou faire tourner

---

### Variables d'Environnement

```yaml
env:
  IMAGE_NAME: supply-chain-poc
  IMAGE_TAG: ${{ github.sha }}          # SHA du commit Git
  REGISTRY: ghcr.io/${{ github.repository_owner }}
```

**Pourquoi utiliser `github.sha` comme tag ?**

- **Immutabilité** : Chaque commit obtient un tag unique
- **Traçabilité** : `docker pull ghcr.io/yourorg/app:9b6f9af` → commit exact
- **Rollback** : Revenir à l'image d'un commit spécifique

---

### Job : build-and-scan

**S'exécute sur** : `ubuntu-latest` (actuellement Ubuntu 22.04)

**Étapes** :

1. **Checkout** : Clone le repository
2. **Install Task** : Télécharge le binaire task depuis https://taskfile.dev
3. **Install SBOM tools** : Exécute `sudo task install` (Trivy, cdxgen, Cosign, etc.)
4. **Build image** : `task build IMAGE_TAG=9b6f9af`
5. **Generate SBOMs** : `task sbom:generate:all IMAGE_TAG=9b6f9af`
6. **Sign SBOM** : `task sbom:sign IMAGE_TAG=9b6f9af`
7. **Scan vulnerabilities** : `task sbom:scan:all`
8. **Policy check** : `task sbom:policy`
9. **Upload artifacts** : Sauvegarde `output/` vers les artefacts GitHub Actions

**Temps d'exécution total** : ~2,5 minutes

---

### Job : daily-rescan

**Déclencheur** : S'exécute seulement sur la planification cron quotidienne (`if: github.event_name == 'schedule'`)

**Ce qu'il fait** :

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

**Pourquoi télécharger l'ancien SBOM ?**

Le SBOM lui-même ne change pas. Mais la base de données de vulnérabilités se met à jour quotidiennement. Rescanner le même SBOM avec des données CVE fraîches trouve les vulnérabilités nouvellement divulguées.

**Exemple** :

- **1er janv** : Le scan trouve 0 CVE critiques dans OpenSSL 3.0.11
- **5 janv** : Nouvelle CVE-2024-XXXX divulguée pour OpenSSL 3.0.11
- **6 janv (rescan quotidien)** : Le scan trouve maintenant 1 CVE critique
- **Alerte** : Envoyer un message Slack à l'équipe sécurité

---

## Référence des Tâches

### Installation

```bash
# Installer tous les outils
sudo task install

# Installer des outils individuels
sudo task install:trivy
sudo task install:cdxgen
sudo task install:cosign
sudo task install:opa
sudo task install:oras

# Vérifier l'installation
task install:verify
```

---

### Génération SBOM

```bash
# Générer les SBOM source + image (outils par défaut)
task sbom:generate

# Générer les SBOM source (tous les outils)
task sbom:generate:source

# Générer le SBOM source (outil spécifique)
task sbom:generate:source:cdxgen
task sbom:generate:source:trivy

# Générer les SBOM image (tous les outils)
task sbom:generate:image
task sbom:generate:image:trivy
task sbom:generate:image:docker  # Docker BuildKit (format SPDX)

# Générer TOUS les SBOM (source + image, tous les outils)
task sbom:generate:all

```

---

### Signature & Attestation

```bash
# Générer la paire de clés de signature (POC seulement)
task signing:init
# Sortie: cosign.key, cosign.pub

# Auto-détection: attester si registre disponible, sinon signature blob
task sbom:sign

# Forcer la signature blob
task sbom:sign:blob

# Attester le SBOM au digest de l'image (nécessite push registre)
task sbom:attest

# Vérifier la signature
task sbom:verify

# Vérifier la signature blob
task sbom:verify:blob

# Démo: falsifier le SBOM et vérifier la détection
task sbom:tamper:test
```

---

### Scan des Vulnérabilités

```bash
# Scanner le SBOM image avec Trivy
task sbom:scan

# Scanner le SBOM source avec Trivy
task sbom:scan:source

# Scanner source + image
task sbom:scan:all
```

**Fichiers de sortie** :

- `output/scans/scan-image-trivy.json`
- `output/scans/scan-source-trivy.json`

---

### Évaluation des Politiques

```bash
# Évaluer le SBOM contre les politiques OPA
task sbom:policy
```

**Éditer les politiques** :

```bash
vim policies/sbom-compliance.rego
```

**Tester les politiques localement** :

```bash
opa eval \
  --data policies/ \
  --input output/sbom/image/sbom-image-trivy.json \
  'data.sbom.deny'
```

---

### Monitoring & Pipelines

```bash
# Démarrer Dependency-Track
task dtrack:up
# Accès: http://localhost:8081 (admin/admin)

# Téléverser le SBOM vers Dependency-Track
task sbom:upload

# Arrêter Dependency-Track
task dtrack:down

# Exécuter le pipeline complet (sans build)
task pipeline

# Exécuter le pipeline complet avec build
task pipeline:full
```

---

### Commandes Utilitaires

```bash
# Lister toutes les tâches disponibles
task --list

# Nettoyer tous les fichiers générés
task clean

# Construire l'image conteneur
task build

# Construire avec un tag personnalisé
task build IMAGE_TAG=v1.2.3
```

---

## Dépannage

### Problème : `task: command not found`

**Cause** : Task n'est pas installé ou pas dans `$PATH`.

**Solution** :

```bash
sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin
```

Ou installer via le gestionnaire de paquets :

```bash
# macOS
brew install go-task

# Arch Linux
pacman -S go-task-bin

# Ubuntu/Debian (via snap)
snap install task --classic
```

---

### Problème : `permission denied` lors de l'installation des outils

**Cause** : Les outils sont installés dans `/usr/local/bin`, qui nécessite un accès root.

**Solution** :

```bash
sudo task install
```

**Alternative** : Installer dans un répertoire accessible en écriture par l'utilisateur :

```bash
export INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
export PATH="$INSTALL_DIR:$PATH"

# Modifier Taskfile.yml pour utiliser $INSTALL_DIR au lieu de /usr/local/bin
```

---

### Problème : `Error: signing ./output/sbom/sbom.json: create bundle file: open : no such file or directory`

**Cause** : Utilisation d'une version plus ancienne de Cosign qui ne supporte pas le flag `--bundle`.

**Solution** : Mettre à jour Cosign vers v2.0+ :

```bash
sudo task install:cosign
```

---

### Problème : Les SBOM ont 0 composants

**Causes possibles** :

1. **Mauvais chemin** : Vérifiez que l'outil scanne le bon répertoire.

   ```bash
   # Incorrect
   cdxgen /tmp/empty-dir

   # Correct
   cdxgen ./app
   ```

2. **Aucune dépendance détectée** : Pour les apps Python, assurez-vous que `requirements.txt` ou `pyproject.toml` existe.

3. **Problème spécifique à l'outil** : Essayez un outil différent :

   ```bash
   # Si cdxgen échoue, essayez Trivy
   task sbom:generate:source:trivy
   ```

---

### Problème : Nombre élevé de vulnérabilités (500+ CVE)

**Cause** : Vous scannez le **SBOM image**, qui inclut les paquets OS. De nombreuses CVE sont dans les dépendances de l'image de base (Debian, Alpine, etc.).

**Est-ce un problème ?**

Pas nécessairement. La plupart des CVE OS ont des scores CVSS < 5.0 (Medium) et sont atténuées par :

- Règles de pare-feu par défaut
- Utilisateur non-root
- Systèmes de fichiers en lecture seule

**Solutions** :

1. **Filtrer par sévérité** :

   ```bash
   trivy sbom sbom.json --severity CRITICAL,HIGH --exit-code 1
   ```

2. **Utiliser des images de base distroless** (pas de shell, pas de gestionnaire de paquets) :

   ```dockerfile
   FROM gcr.io/distroless/python3-debian12
   ```

3. **Mettre à jour régulièrement l'image de base** :

   ```bash
   docker pull python:3.11-slim
   task build
   ```

---

### Problème : La vérification des politiques échoue avec "Component 'bash' has no version"

**Cause** : La règle `deny` de la politique vérifie les versions manquantes :

```rego
deny contains msg if {
  some component in input.components
  not component.version
  msg := sprintf("Component '%s' has no version", [component.name])
}
```

Les fichiers système (type: `file`) n'ont pas de versions.

**Solution** : Déjà corrigé dans ce repo. La politique exclut maintenant les fichiers :

```rego
deny contains msg if {
  some component in input.components
  not component.version
  component.type != "file"  # Exclure les fichiers système
  msg := sprintf("Component '%s' has no version", [component.name])
}
```

---

### Problème : `cosign verify-blob` échoue avec "invalid signature"

**Causes possibles** :

1. **Mauvaise clé publique** : Assurez-vous d'utiliser le bon `cosign.pub`.

   ```bash
   cosign verify-blob \
     --key cosign.pub \
     --bundle sbom.json.bundle \
     sbom.json
   ```

2. **Le SBOM a été modifié** : Même changer un espace blanc casse la signature.

   ```bash
   # Régénérer le SBOM
   task sbom:generate
   task sbom:sign
   ```

3. **Le fichier bundle est corrompu** :

   ```bash
   # Vérifier si le bundle est du JSON valide
   jq . sbom.json.bundle

   # Régénérer la signature
   rm sbom.json.bundle
   task sbom:sign:blob
   ```

---

### Problème : Le build Docker échoue avec "ERROR [internal] load metadata for docker.io/library/python:3.11-slim"

**Cause** : Le daemon Docker ne tourne pas ou ne peut pas atteindre Docker Hub.

**Solution** :

```bash
# Vérifier le statut de Docker
docker info

# Si Docker ne tourne pas (Linux)
sudo systemctl start docker

# Si Docker ne tourne pas (macOS)
open -a Docker

# Si rate-limité par Docker Hub, se connecter
docker login
```

---

## Bonnes Pratiques

### 1. Toujours Scanner le SBOM Image en Production

**Pourquoi** : L'image est ce qui tourne. Les SBOM source sont incomplets.

**Exemple** :

```yaml
# ❌ MAUVAIS
- name: Scan
  run: trivy sbom output/sbom/source/sbom-source-cdxgen.json

# ✅ BON
- name: Scan
  run: trivy sbom output/sbom/image/sbom-image-trivy.json
```

---

### 2. Utiliser la Signature Keyless en CI/CD

**Pourquoi** : Pas de secrets à gérer. Les tokens OIDC sont à courte durée de vie (15 minutes).

**Comment** :

```yaml
permissions:
  id-token: write

# Dans l'étape de signature :
env:
  COSIGN_EXPERIMENTAL: 1
run: cosign sign <image>
```

---

### 3. Fixer les Versions des Outils

**Pourquoi** : Builds reproductibles. Si Trivy v0.70 introduit un bug, vous voulez rester avec v0.69.1.

**Comment** :

Éditer `Taskfile.yml` :

```yaml
vars:
  TRIVY_VERSION: "0.69.1"

tasks:
  install:trivy:
    cmds:
      - curl -sSfL https://github.com/aquasecurity/trivy/releases/download/v{{.TRIVY_VERSION}}/trivy_{{.TRIVY_VERSION}}_Linux-64bit.tar.gz | tar -xz
```

---

### 4. Appliquer les Politiques Avant le Déploiement

**Pourquoi** : Attraper les violations tôt (shift-left).

**Comment** :

```yaml
- name: Policy Check
  run: task sbom:policy

- name: Deploy
  if: success()  # Déployer seulement si la politique a réussi
  run: kubectl apply -f deployment.yaml
```

---

### 5. Stocker les SBOM avec les Images

**Pourquoi** : Le SBOM et l'image sont couplés. Les stocker ensemble garantit qu'ils ne dérivent pas.

**Comment** : Utiliser l'attestation au lieu de la signature blob :

```bash
cosign attest \
  --predicate sbom.json \
  --type cyclonedx \
  ghcr.io/yourorg/app:sha256:abc123
```

Le SBOM est maintenant stocké dans le même registre OCI que l'image :

```
ghcr.io/yourorg/app
├── sha256:abc123... (image)
└── sha256:def456... (attestation SBOM)
```

---

### 6. Automatiser les Mises à Jour de Dépendances

**Pourquoi** : 80% des vulnérabilités sont dans des dépendances obsolètes.

**Comment** : Utiliser **Renovate** (inclus dans ce repo) :

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

Renovate va :
- Vérifier les mises à jour hebdomadairement
- Créer des PR automatiquement
- Exécuter CI/CD sur chaque PR
- Auto-merge les mises à jour de patch si CI passe

---

### 7. Exécuter des Rescans Quotidiens

**Pourquoi** : De nouvelles CVE sont divulguées quotidiennement. Un SBOM généré hier peut avoir de nouvelles vulnérabilités aujourd'hui.

**Comment** : Déjà implémenté dans ce repo :

```yaml
on:
  schedule:
    - cron: '0 2 * * *'  # Quotidien à 2h UTC
```

---

### 8. Utiliser des Images de Base Distroless ou Minimales

**Pourquoi** : Moins de composants = surface d'attaque plus petite.

**Exemple** :

```dockerfile
# ❌ MAUVAIS: 2 900+ composants
FROM python:3.11-slim

# ✅ MIEUX: ~200 composants
FROM python:3.11-alpine

# ✅ MEILLEUR: ~50 composants
FROM gcr.io/distroless/python3-debian12
```

---

### 9. Échouer Rapidement sur les CVE Critiques

**Pourquoi** : Ne pas déployer de logiciels avec des vulnérabilités connues.

**Comment** :

```bash
trivy sbom sbom.json --severity CRITICAL,HIGH --exit-code 1
```

Si une CVE Critique ou Haute est trouvée, code de sortie 1 (échoue CI/CD).

---

### 10. Monitorer les SBOM en Production

**Pourquoi** : Visibilité continue sur votre chaîne d'approvisionnement logicielle.

**Comment** : Utiliser **Dependency-Track** :

```bash
task dtrack:up
task sbom:upload
```

Dependency-Track fournit :
- Tableau de bord de tous les composants
- Monitoring automatisé des vulnérabilités
- Support VEX (Vulnerability Exploitability eXchange)
- Rapports de conformité des licences
- Tendances (croissance des composants au fil du temps)

---

## Références

### Standards & Spécifications

- **CycloneDX** : https://cyclonedx.org/
- **SPDX** : https://spdx.dev/
- **PURL (Package URL)** : https://github.com/package-url/purl-spec
- **In-Toto Attestation** : https://github.com/in-toto/attestation

### Frameworks Gouvernementaux

- **NIST SSDF (Secure Software Development Framework)** : https://csrc.nist.gov/publications/detail/sp/800-218/final
- **NIST SP 800-161 (Supply Chain Risk Management)** : https://csrc.nist.gov/publications/detail/sp/800-161/rev-1/final
- **Executive Order 14028** : https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/
- **SLSA (Supply Chain Levels for Software Artifacts)** : https://slsa.dev/

### Outils

- **Trivy** : https://github.com/aquasecurity/trivy
- **cdxgen** : https://github.com/CycloneDX/cdxgen
- **Cosign** : https://github.com/sigstore/cosign
- **OPA** : https://www.openpolicyagent.org/
- **Dependency-Track** : https://dependencytrack.org/
- **Task** : https://taskfile.dev/

### Ressources d'Apprentissage

- **Guide SBOM CNCF** : https://www.cncf.io/blog/2024/03/14/a-guide-to-sboms/
- **OWASP Dependency-Track** : https://owasp.org/www-project-dependency-track/
- **Documentation Sigstore** : https://docs.sigstore.dev/
- **Langage de Politique OPA** : https://www.openpolicyagent.org/docs/latest/policy-language/

### Études de Cas d'Incidents

- **Log4Shell (CVE-2021-44228)** : https://en.wikipedia.org/wiki/Log4Shell
- **Attaque Supply Chain SolarWinds** : https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a
- **Dependency Confusion** : https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

---

## Contribuer

Ceci est une implémentation de référence. Forkez-la, adaptez-la, faites-la vôtre.

Si vous trouvez des bugs ou avez des améliorations, ouvrez une issue ou une PR sur :
https://github.com/cuspofaries/poc-sbom

---

## Licence

Licence MIT. Voir le fichier `LICENSE` pour les détails.

---

## Remerciements

Construit avec des outils de :
- [Aqua Security](https://www.aquasec.com/) (Trivy)
- [OWASP](https://owasp.org/) (CycloneDX, Dependency-Track)
- [Sigstore](https://sigstore.dev/) (Cosign)
- [CNCF](https://www.cncf.io/) (OPA)

Inspiré par le travail de Kelsey Hightower, qui nous a appris que la meilleure documentation est celle que vous pouvez exécuter.
