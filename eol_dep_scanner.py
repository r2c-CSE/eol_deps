#!/usr/bin/env python3
"""
Scan a Semgrep deployment for deprecated/EOL dependencies.

For each project (or a named subset):
  1. Creates a CycloneDX SBOM export job via the Semgrep API
  2. Polls until complete and downloads the SBOM
  3. Checks each component against deps.dev for deprecation status
  4. Annotates deprecated components in-place and writes to --output-dir
  5. Tags the project with "EOL DEP" if any deprecated dependencies are found

Writes <output-dir>/summary.json with a cross-project deprecation report.

Usage:
    python scripts/eol_dep_scanner.py --token <TOKEN> [--projects org/repo ...] [--output-dir ./sbom-output]
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests

SEMGREP_BASE = "https://semgrep.dev"
SEMGREP_API = f"{SEMGREP_BASE}/api/v1"
DEPS_DEV_API = "https://api.deps.dev/v3alpha"
EOL_DEP_TAG = "EOL DEP"
EXPORT_CONCURRENCY = 50
POLL_INTERVAL_S = 5
POLL_TIMEOUT_S = 300

PURL_TO_DEPS_DEV: dict[str, str] = {
    "maven": "MAVEN",
    "npm": "NPM",
    "pypi": "PYPI",
    "golang": "GO",
    "nuget": "NUGET",
    "cargo": "CARGO",
}

_dep_cache: dict[tuple[str, str], tuple[bool, str]] = {}
_dep_cache_lock = threading.Lock()


# ── Semgrep API ───────────────────────────────────────────────────────────────

def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def fetch_deployment(token: str) -> dict[str, Any]:
    resp = requests.get(f"{SEMGREP_API}/deployments", headers=_headers(token), timeout=30)
    resp.raise_for_status()
    deployments = resp.json().get("deployments", [])
    if not deployments:
        raise SystemExit("No deployments found for this token.")
    return deployments[0]


def list_all_projects(token: str, deployment_slug: str) -> list[dict[str, Any]]:
    projects: list[dict[str, Any]] = []
    cursor: str | None = None
    page_size = 100
    while True:
        params: dict[str, Any] = {"page_size": page_size}
        if cursor:
            params["cursor"] = cursor
        resp = requests.get(
            f"{SEMGREP_API}/deployments/{deployment_slug}/projects",
            headers=_headers(token),
            params=params,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("projects", [])
        projects.extend(batch)
        cursor = data.get("cursor")
        if not cursor or len(batch) < page_size:
            break
    return projects


def create_sbom_export(token: str, deployment_id: int, repository_id: int) -> str:
    resp = requests.post(
        f"{SEMGREP_BASE}/api/sca/deployments/{deployment_id}/sbom_async",
        headers=_headers(token),
        json={
            "repositoryId": repository_id,
            "formatVersion": {"format": "SBOM_FORMAT_CYCLONEDX", "version": "1.5"},
            "sbomOutputFormat": "SBOM_OUTPUT_FORMAT_JSON",
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["taskTokenJwt"]


def poll_sbom_export(token: str, task_token_jwt: str) -> dict[str, Any]:
    """Poll the v2 task endpoint; return parsed SBOM dict when complete."""
    deadline = time.monotonic() + POLL_TIMEOUT_S
    while time.monotonic() < deadline:
        resp = requests.get(
            f"{SEMGREP_BASE}/api/tasks/v2/{task_token_jwt}",
            headers=_headers(token),
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        status = data.get("status", "")
        if status == "TASK_STATUS_COMPLETED":
            result_string = data.get("taskResult", {}).get("resultString", "")
            return json.loads(result_string)
        if status == "TASK_STATUS_FAILED":
            raise RuntimeError(f"SBOM export failed: {data.get('error', 'unknown')}")
        time.sleep(POLL_INTERVAL_S)
    raise TimeoutError(f"SBOM export timed out after {POLL_TIMEOUT_S}s")


def add_tag(token: str, deployment_slug: str, project_name: str) -> None:
    encoded = urllib.parse.quote(project_name, safe="")
    resp = requests.put(
        f"{SEMGREP_API}/deployments/{deployment_slug}/projects/{encoded}/tags",
        headers=_headers(token),
        json={"tags": [EOL_DEP_TAG]},
        timeout=30,
    )
    resp.raise_for_status()


# ── deps.dev deprecation lookup ───────────────────────────────────────────────

def parse_purl(purl: str) -> tuple[str, str, str] | None:
    """Return (deps_dev_system, package_name, version) or None if unsupported."""
    if not purl.startswith("pkg:"):
        return None
    rest = purl[4:]
    at = rest.rfind("@")
    if at == -1:
        return None
    version = urllib.parse.unquote(rest[at + 1:].split("?")[0].split("#")[0])
    type_and_path = rest[:at]
    slash = type_and_path.index("/")
    purl_type = type_and_path[:slash]
    path = urllib.parse.unquote(type_and_path[slash + 1:])
    system = PURL_TO_DEPS_DEV.get(purl_type)
    if not system:
        return None
    if purl_type == "maven":
        parts = path.split("/", 1)
        package_name = ":".join(parts) if len(parts) == 2 else path
    else:
        package_name = path
    return system, package_name, version


def _fetch_deprecated(system: str, package_name: str, session: requests.Session) -> tuple[bool, str]:
    encoded = urllib.parse.quote(package_name, safe="")
    url = f"{DEPS_DEV_API}/systems/{system}/packages/{encoded}"
    for attempt in range(3):
        try:
            resp = session.get(url, timeout=15)
            if resp.status_code == 404:
                return False, ""
            if resp.status_code == 429:
                time.sleep(2 ** attempt)
                continue
            resp.raise_for_status()
            data = resp.json()
            return bool(data.get("isDeprecated", False)), data.get("deprecationMessage", "")
        except Exception:
            if attempt == 2:
                return False, ""
    return False, ""


def check_deprecated(
    system: str, package_name: str, session: requests.Session
) -> tuple[bool, str]:
    key = (system, package_name)
    with _dep_cache_lock:
        if key in _dep_cache:
            return _dep_cache[key]
    result = _fetch_deprecated(system, package_name, session)
    with _dep_cache_lock:
        _dep_cache[key] = result
    return result


# ── SBOM annotation ───────────────────────────────────────────────────────────

def annotate_sbom(sbom: dict[str, Any], deprecated: dict[str, str]) -> int:
    count = 0
    for component in sbom.get("components", []):
        purl = component.get("purl", "")
        parsed = parse_purl(purl) if purl else None
        if not parsed:
            continue
        _, pkg_name, _ = parsed
        if pkg_name not in deprecated:
            continue
        props: list[dict[str, str]] = component.setdefault("properties", [])
        props.append({"name": "eol-dep:deprecated", "value": "true"})
        msg = deprecated[pkg_name]
        if msg:
            props.append({"name": "eol-dep:deprecation-message", "value": msg})
        count += 1
    return count


# ── Per-project pipeline ──────────────────────────────────────────────────────

def process_project(
    project: dict[str, Any],
    token: str,
    deployment_id: int,
    deployment_slug: str,
    output_dir: Path,
    session: requests.Session,
) -> dict[str, Any]:
    name: str = project["name"]
    repo_id: int = project["id"]
    result: dict[str, Any] = {"project": name, "status": "ok", "deprecated_deps": []}

    try:
        task_token_jwt = create_sbom_export(token, deployment_id, repo_id)
        sbom = poll_sbom_export(token, task_token_jwt)
    except Exception as exc:
        result["status"] = "sbom_failed"
        result["error"] = str(exc)
        return result

    deprecated: dict[str, str] = {}
    for component in sbom.get("components", []):
        purl = component.get("purl", "")
        if not purl:
            continue
        parsed = parse_purl(purl)
        if not parsed:
            continue
        system, pkg_name, _ = parsed
        if pkg_name in deprecated:
            continue
        is_dep, msg = check_deprecated(system, pkg_name, session)
        if is_dep:
            deprecated[pkg_name] = msg

    if deprecated:
        annotate_sbom(sbom, deprecated)
        result["deprecated_deps"] = [
            {"package": k, "message": v} for k, v in deprecated.items()
        ]
        try:
            add_tag(token, deployment_slug, name)
        except Exception as exc:
            result["tag_error"] = str(exc)

    safe_name = name.replace("/", "__")
    (output_dir / f"{safe_name}.sbom.json").write_text(json.dumps(sbom, indent=2))

    return result


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan Semgrep projects for deprecated/EOL dependencies."
    )
    parser.add_argument("--token", required=True, help="Semgrep API token")
    parser.add_argument(
        "--projects", nargs="*", metavar="ORG/REPO",
        help="Specific project names to scan (default: all projects)",
    )
    parser.add_argument(
        "--output-dir", default="./sbom-eol-scan",
        help="Directory for annotated SBOMs and summary report (default: ./sbom-eol-scan)",
    )
    parser.add_argument(
        "--concurrency", type=int, default=EXPORT_CONCURRENCY,
        help=f"Parallel export jobs (default: {EXPORT_CONCURRENCY})",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Fetching deployment...", flush=True)
    deployment = fetch_deployment(args.token)
    deployment_id: int = int(deployment["id"])
    deployment_slug: str = deployment["slug"]
    print(f"Deployment: {deployment['name']} (id={deployment_id}, slug={deployment_slug})")

    print("Fetching projects...", flush=True)
    all_projects = list_all_projects(args.token, deployment_slug)

    if args.projects:
        filter_set = set(args.projects)
        projects = [p for p in all_projects if p["name"] in filter_set]
        missing = filter_set - {p["name"] for p in projects}
        if missing:
            print(f"Warning: projects not found: {', '.join(sorted(missing))}", file=sys.stderr)
    else:
        projects = all_projects

    print(f"Scanning {len(projects)} project(s) with concurrency={args.concurrency}...")

    session = requests.Session()
    results: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = {
            executor.submit(
                process_project,
                project, args.token, deployment_id, deployment_slug, output_dir, session,
            ): project["name"]
            for project in projects
        }
        for i, future in enumerate(as_completed(futures), 1):
            name = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {"project": name, "status": "error", "error": str(exc), "deprecated_deps": []}
            results.append(result)
            dep_count = len(result.get("deprecated_deps", []))
            label = f"{dep_count} deprecated dep(s)" if dep_count else "clean"
            if result.get("status") not in ("ok",):
                label = result.get("status", "error")
            print(f"  [{i}/{len(projects)}] {name}: {label}")

    flagged = [r for r in results if r.get("deprecated_deps")]
    summary = {
        "deployment": deployment["name"],
        "total_projects_scanned": len(projects),
        "projects_with_deprecated_deps": len(flagged),
        "results": sorted(results, key=lambda r: r["project"]),
    }
    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))

    print(f"\n{len(flagged)}/{len(projects)} projects have deprecated dependencies.")
    print(f"Summary: {summary_path}")
    print(f"Annotated SBOMs: {output_dir}/")


if __name__ == "__main__":
    main()
