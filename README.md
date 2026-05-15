# eol_deps

Scans a Semgrep deployment for deprecated or end-of-life (EOL) supply chain dependencies using the Semgrep SBOM export API and [deps.dev](https://deps.dev).

For each project scanned:
- Exports the existing CycloneDX SBOM from Semgrep (no re-scan required)
- Checks every component against the deps.dev API for deprecation status
- Annotates deprecated components in-place with `eol-dep:deprecated` and `eol-dep:deprecation-message` properties
- Tags the project with `EOL DEP` in Semgrep if any deprecated dependencies are found
- Writes a cross-project summary report

Supports Maven, npm, PyPI, Go, NuGet, and Cargo ecosystems. Runs up to 50 export jobs in parallel.

## Requirements

- Python 3.10+
- `requests` (`pip install requests`)
- A Semgrep API token with access to the target deployment

## Usage

```bash
# Scan all projects in a deployment
python eol_dep_scanner.py --token <SEMGREP_APP_TOKEN>

# Scan specific projects
python eol_dep_scanner.py --token <SEMGREP_APP_TOKEN> --projects org/repo1 org/repo2

# Custom output directory
python eol_dep_scanner.py --token <SEMGREP_APP_TOKEN> --output-dir ./quinto-scan

# Adjust parallelism (default: 50)
python eol_dep_scanner.py --token <SEMGREP_APP_TOKEN> --concurrency 20
```

## Output

```
./sbom-eol-scan/
  org__repo1.sbom.json   # Annotated CycloneDX SBOM (original export + deprecation properties)
  org__repo2.sbom.json
  ...
  summary.json           # Cross-project deprecation report
```

### Annotated component example

Deprecated components in the SBOM receive additional `properties` entries:

```json
{
  "type": "library",
  "name": "some-package",
  "version": "1.2.3",
  "purl": "pkg:npm/some-package@1.2.3",
  "properties": [
    { "name": "eol-dep:deprecated", "value": "true" },
    { "name": "eol-dep:deprecation-message", "value": "Use some-other-package instead." }
  ]
}
```

### summary.json example

```json
{
  "deployment": "my-org",
  "total_projects_scanned": 142,
  "projects_with_deprecated_deps": 17,
  "results": [
    {
      "project": "org/repo1",
      "status": "ok",
      "deprecated_deps": [
        { "package": "some-package", "message": "Use some-other-package instead." }
      ]
    },
    ...
  ]
}
```

## Notes

- **Deprecation coverage by ecosystem:** npm has the strongest signal (explicit deprecated flag). PyPI, Go, NuGet, and Cargo are also well covered. Maven does not have a first-class deprecation concept — coverage there is limited to packages with published advisories.
- **Projects must have an existing SBOM** in Semgrep (i.e. an SCA scan has already run). Projects with no SBOM will be reported as `sbom_failed` in the summary.
- **Tags are additive** — the `EOL DEP` tag is added but existing tags are not removed.
