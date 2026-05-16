---
name: build-and-release
description: >-
  Use when preparing a release, modifying CI/CD pipelines, or working with
  version management. Covers Azure Pipelines structure, tag-based releases,
  version stamping, and publishing to Ansible Galaxy and PyPI.
---

# Build and Release

## Pipeline Overview

The repository uses two separate Azure Pipelines — one per component. Each
pipeline only triggers when its own component's files change. Both pipelines
exclude `README.md` and `AGENTS.md` from triggers.

```
collection/azure-pipelines.yml
├── PRValidation          # Builds collection tarball, no publishing
└── BuildCollection       # Builds + publishes to Galaxy + GitHub Release

credential_type_plugin/azure-pipelines.yml
├── PRValidation          # Builds wheel, validates with twine check
└── BuildCredPlugin       # Builds + publishes to PyPI + GitHub Release
```

Both use `ubuntu-latest` with Python 3.12.

---

## Trigger Configuration

### Collection pipeline triggers on:

- **Branches:** `main`, `release-*`
- **Tags:** `collection-v*`
- **Paths:** `collection/`, `pipeline-templates/`

### Credential plugin pipeline triggers on:

- **Branches:** `main`, `release-*`
- **Tags:** `credplugin-v*`
- **Paths:** `credential_type_plugin/`, `pipeline-templates/`

### Job conditions

- **PRValidation** runs only for pull requests (`Build.Reason == 'PullRequest'`)
- **Build/Publish** runs for everything except PRs (merges to main, tag pushes)

---

## Shared Templates

Build logic lives in `pipeline-templates/`:

### `global-variables.yml`

Defines three boolean variables used for conditional publishing:

```yaml
isTagBuild: startsWith(Build.SourceBranch, 'refs/tags/')
isCollectionTag: startsWith(Build.SourceBranch, 'refs/tags/collection-v')
isCredPluginTag: startsWith(Build.SourceBranch, 'refs/tags/credplugin-v')
```

### `build-collection-steps.yml`

1. Install `ansible-core` and `antsibull-changelog`
2. Run `versionnumber.ps1 -Component collection` to stamp version
3. `ansible-galaxy collection build`
4. Publish pipeline artifact: `SafeguardCollection-$(Build.BuildId)`

### `build-credplugin-steps.yml`

1. Install `pip`, `wheel`, `build`, `twine`
2. Run `versionnumber.ps1 -Component credplugin` to stamp version
3. `python3 -m build`
4. `twine check dist/*` to validate the distribution
5. Publish pipeline artifact: `SafeguardCredentialType-$(Build.BuildId)`

---

## Version Management

### Source of truth

- **Collection:** `collection/oneidentity/safeguard/galaxy.yml` → `version:` field
- **Credential plugin:** `credential_type_plugin/pyproject.toml` → `version =` field
- **Current version:** `2.0.0` (for both)

### `versionnumber.ps1`

The version stamping script reads the version from the metadata file and
produces the package version. Parameters:

```powershell
versionnumber.ps1 -Component <collection|credplugin> -BuildId <id> -TagName <name> -IsTagBuild <bool>
```

**Tag builds** (e.g. `collection-v2.0.0`):
- Strips the component prefix from the tag → `2.0.0`
- Writes this version back into the metadata file
- Sets pipeline variables: `PackageVersion`, `ReleaseTag`

**Dev builds** (merge to `main` or `release-*`):
- Appends a prerelease suffix using the `BuildId`:
  - Collection: `2.0.0-dev.360928` (SemVer, required by Ansible Galaxy)
  - Credential plugin: `2.0.0.dev360928` (PEP 440, required by PyPI)
- Sets `ReleaseTag` with `dev/` prefix to avoid re-triggering tag-based
  pipeline triggers (e.g. `dev/collection-v2.0.0-dev.360928`)

### Version bumping

When preparing a new release, bump the version in the metadata file
(`galaxy.yml` or `pyproject.toml`). The pipeline reads this and either uses
it as-is (tag builds) or appends a dev suffix. No placeholder is needed —
`versionnumber.ps1` handles everything.

---

## Release Workflow

### Releasing the collection

```bash
git tag collection-v2.1.0
git push origin collection-v2.1.0
```

This triggers the collection pipeline which:
1. Stamps `galaxy.yml` with `2.1.0`
2. Builds the collection tarball
3. Creates a GitHub Release (full release, not prerelease)
4. Fetches the Galaxy API key from Azure Key Vault (`SafeguardBuildSecrets` → `AnsibleGalaxyApiKey1`)
5. Publishes to Ansible Galaxy via `ansible-galaxy collection publish`

### Releasing the credential type plugin

```bash
git tag credplugin-v2.1.0
git push origin credplugin-v2.1.0
```

This triggers the credential plugin pipeline which:
1. Stamps `pyproject.toml` with `2.1.0`
2. Builds the wheel and sdist
3. Creates a GitHub Release
4. Authenticates via `TwineAuthenticate` using the `pypiOneIdentity` service connection
5. Publishes to PyPI via `twine upload`

### Dev builds (automatic)

Every merge to `main` or `release-*` creates a prerelease GitHub Release
with a `dev/` prefixed tag. These are not published to Galaxy or PyPI.

---

## Service Connections

| Service | Connection | Details |
|---------|-----------|---------|
| GitHub | `PangaeaBuild-GitHub` | Used for GitHub Releases (shared with PySafeguard) |
| Ansible Galaxy | Azure Key Vault | `SafeguardBuildSecrets` vault → `AnsibleGalaxyApiKey1` secret |
| PyPI | `pypiOneIdentity` | Twine authentication service connection |
| Azure | `SafeguardOpenSource` | Subscription for Key Vault access |

---

## What CI Enforces

### On every PR:
- Collection tarball builds successfully
- Credential plugin wheel builds and passes `twine check`

### On merge to main/release-*:
- Same builds as PR validation
- GitHub prerelease created with dev-suffixed version

### On tag push:
- Same builds
- GitHub full release created
- Published to Galaxy (collection) or PyPI (credential plugin)
