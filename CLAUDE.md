# eol_deps

## What this does

`eol_dep_scanner.py` scans a Semgrep deployment for deprecated/EOL supply chain dependencies. For each project it:
1. Creates an async SBOM export job via the Semgrep API
2. Polls until complete and downloads the SBOM
3. Checks each component against deps.dev for deprecation status
4. Annotates deprecated components in-place in the SBOM JSON
5. Tags the project with `EOL DEP` in Semgrep if deprecated deps are found
6. Writes a `summary.json` cross-project report

## Commands

```bash
# All projects in the deployment
python3 eol_dep_scanner.py --token <SEMGREP_APP_TOKEN>

# Specific projects only
python3 eol_dep_scanner.py --token <SEMGREP_APP_TOKEN> --projects org/repo1 org/repo2

# Custom output directory and concurrency
python3 eol_dep_scanner.py --token <SEMGREP_APP_TOKEN> --output-dir ./output --concurrency 20
```

## Dependencies

- Python 3.10+
- `requests` (`pip install requests`) — only external dependency

## API endpoints used

| Purpose | Endpoint |
|---|---|
| Resolve deployment | `GET /api/v1/deployments` |
| List projects (cursor-paginated) | `GET /api/v1/deployments/{slug}/projects?page_size=100&cursor=...` |
| Create SBOM export job | `POST /api/sca/deployments/{id}/sbom_async` |
| Poll job status + get result | `GET /api/tasks/v2/{taskTokenJwt}` |
| Tag project | `PUT /api/v1/deployments/{slug}/projects/{name}/tags` |

**Note on SBOM APIs:** Two SBOM export APIs exist. The v1 API (`/api/v1/deployments/{id}/sbom/export`) hangs indefinitely when no SCA data exists for a project. The script uses the v2 flow: `POST /api/sca/deployments/{id}/sbom_async` → `GET /api/tasks/v2/{taskTokenJwt}` — the SBOM is returned in `taskResult.resultString` when `status == TASK_STATUS_COMPLETED`.

## Known limitations

- **Requires SCA scan data.** If a project has only been scanned with SAST rules (no supply chain analysis), the SBOM export job will hang in `IN_PROGRESS` indefinitely and eventually time out. There is no API to check upfront whether SCA data exists for a project.
- **Deprecation coverage by ecosystem:** npm has the strongest signal via deps.dev (explicit deprecated flag). PyPI, Go, NuGet, Cargo are also covered. Maven has no first-class deprecation concept — coverage there is limited to packages with published advisories.
- **deps.dev does not cover Dart/pub.** Flutter projects scanned by `sca-flutter` will have components with `pkg:pub/...` purls that are silently skipped during the deprecation check.
- **Tags are additive.** `EOL DEP` is added but no tags are removed.

## Output

```
<output-dir>/
  org__repo.sbom.json    # Annotated CycloneDX SBOM (one per project)
  summary.json           # Cross-project report
```

Deprecated components in the SBOM receive `eol-dep:deprecated` and `eol-dep:deprecation-message` properties.

## Repo

https://github.com/r2c-CSE/eol_deps
