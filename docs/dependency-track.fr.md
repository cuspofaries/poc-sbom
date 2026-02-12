# Integration Dependency-Track

Dependency-Track assure le monitoring continu des vulnerabilites dans vos SBOMs. A chaque execution du pipeline, le SBOM image est uploade vers Dependency-Track, qui suit ensuite les nouvelles CVE au fur et a mesure de leur publication.

---

## Prerequis

- Une instance Dependency-Track accessible (auto-hebergee ou managee)
- Une cle API avec les permissions suivantes :
  - **BOM_UPLOAD**
  - **PROJECT_CREATION_UPLOAD** (requis si `autoCreate` est active)

### Obtenir une cle API

1. Se connecter a Dependency-Track
2. Aller dans **Administration > Access Management > Teams**
3. Selectionner ou creer une equipe (ex : "Automation")
4. Verifier que l'equipe a les permissions **BOM_UPLOAD** et **PROJECT_CREATION_UPLOAD**
5. Copier la cle API depuis la page de l'equipe

---

## GitHub Actions

Le pipeline utilise l'action officielle [`DependencyTrack/gh-upload-sbom`](https://github.com/DependencyTrack/gh-upload-sbom).

### 1. Ajouter le secret

Aller dans les **Settings > Secrets and variables > Actions** du repo GitHub et creer un secret :

| Nom | Valeur |
|-----|--------|
| `DTRACK_API_KEY` | Votre cle API Dependency-Track |

### 2. Etape du workflow

L'etape dans `.github/workflows/supply-chain.yml` :

```yaml
- name: Push SBOM to Dependency-Track
  uses: DependencyTrack/gh-upload-sbom@v3
  with:
    serverHostname: dep-api.example.com
    apiKey: ${{ secrets.DTRACK_API_KEY }}
    projectName: ${{ env.IMAGE_NAME }}
    projectVersion: ${{ env.IMAGE_TAG }}
    bomFilename: output/sbom/image/sbom-image-syft.json
    autoCreate: true
```

### 3. Parametres de l'action

| Parametre | Requis | Default | Description |
|-----------|--------|---------|-------------|
| `serverHostname` | Oui | - | Adresse du serveur Dependency-Track (sans protocole) |
| `apiKey` | Oui | - | Cle API pour l'authentification |
| `projectName` | Oui* | - | Nom du projet dans Dependency-Track |
| `projectVersion` | Oui* | - | Version du projet (typiquement le SHA git) |
| `bomFilename` | Non | `bom.xml` | Chemin vers le fichier SBOM |
| `autoCreate` | Non | `false` | Creation automatique du projet s'il n'existe pas |
| `protocol` | Non | `https` | `https` ou `http` |
| `port` | Non | `443` | Port du serveur |

\* Soit `projectName` + `projectVersion`, soit un UUID `project` est requis.

---

## Utilisation locale (Taskfile)

### Demarrer une instance locale Dependency-Track

```bash
task dtrack:up
```

Cela demarre deux conteneurs via `docker-compose.dtrack.yml` :

| Service | Port | Description |
|---------|------|-------------|
| API Server | `8081` | API REST |
| Frontend | `8082` | Interface web |

Identifiants par defaut : **admin / admin** (a changer a la premiere connexion).

Le premier demarrage prend 2-3 minutes pendant la synchronisation de la base NVD.

### Uploader un SBOM manuellement

```bash
task sbom:upload \
  DTRACK_URL=http://localhost:8081 \
  DTRACK_API_KEY=votre-cle-api \
  DTRACK_PROJECT=supply-chain-poc
```

Cela execute `scripts/sbom-upload-dtrack.sh` qui :
1. Verifie que Dependency-Track est accessible
2. Encode le SBOM en base64
3. Upload via `PUT /api/v1/bom`
4. Retourne un token de traitement

### Arreter l'instance

```bash
task dtrack:down
```

---

## Depannage

| Erreur | Cause | Solution |
|--------|-------|----------|
| **HTTP 401** | Cle API invalide ou expiree | Verifier la cle dans Dependency-Track > Administration > Teams |
| **HTTP 403** | Permissions manquantes | Verifier que l'equipe a BOM_UPLOAD et PROJECT_CREATION_UPLOAD |
| **HTTP 415** | Mauvais content type | Utiliser l'action GitHub officielle ou encoder le BOM en base64 dans un body JSON |
| **Connection refused** | Serveur inaccessible | Verifier le hostname et que l'instance est bien demarree |
