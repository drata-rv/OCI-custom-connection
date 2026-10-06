"""Build the AWS Lambda deployment package: dependencies for Linux, a pruned OCI SDK, the
oci_drata code, and your config.yaml.

    python deploy/build_lambda_package.py --config config.yaml [--arch x86_64|arm64]

Writes ``dist/lambda/`` (what deploy/template.yaml's CodeUri points at) and
``dist/oci-drata-lambda.zip`` (for manual upload). Needs network access to PyPI, not Docker:
pip downloads Linux wheels for the target architecture even from macOS or Windows.

``--arch host`` installs for this machine instead and imports the result, which checks that the
pruned SDK still provides everything the collectors use (it cannot run Linux wheels).
"""

from __future__ import annotations

import argparse
import ast
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src" / "oci_drata"
REQUIREMENTS = REPO_ROOT / "deploy" / "requirements-lambda.txt"

PYTHON_VERSION = "3.12"
# AL2023 (python3.12 runtime) has glibc 2.34, so manylinux2014 and manylinux_2_28 wheels both load.
PIP_PLATFORMS = {
    "x86_64": ["manylinux2014_x86_64", "manylinux_2_28_x86_64"],
    "arm64": ["manylinux2014_aarch64", "manylinux_2_28_aarch64"],
}
UNZIPPED_LIMIT_MB = 250  # AWS Lambda: unzipped package incl. layers
ZIPPED_UPLOAD_LIMIT_MB = 50  # direct upload; larger goes through S3 (sam deploy does that)

# oci/ sub-packages the SDK needs regardless of which services are used.
SDK_BASE_PACKAGES = {"_vendor", "auth", "circuit_breaker", "pagination", "retry", "dns", "work_requests"}


def services_used() -> set[str]:
    """OCI SDK service packages the collectors reference (``oci.core``, ``oci.identity``, ...)."""

    used: set[str] = set()
    for path in (SRC / "collection").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "oci"
            ):
                used.add(node.value.attr)
    return used


def prune_oci_sdk(oci_dir: Path) -> tuple[list[str], list[str]]:
    """Deletes every oci/ sub-package that is neither plumbing nor a service this project uses.
    ``import oci`` is lazy per service, so what stays imports unchanged. Returns (kept, removed)."""

    keep = SDK_BASE_PACKAGES | services_used()
    missing = {name for name in keep if not (oci_dir / name).is_dir()}
    if missing:
        raise SystemExit(f"installed oci SDK has no package(s) {sorted(missing)} -- cannot prune safely")
    removed = []
    for child in sorted(oci_dir.iterdir()):
        if child.is_dir() and child.name not in keep:
            shutil.rmtree(child)
            removed.append(child.name)
    return sorted(keep), removed


def size_mb(path: Path) -> float:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file()) / 1e6


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True, help="your config.yaml (see deploy/config.lambda.example.yaml)")
    parser.add_argument("--arch", choices=[*PIP_PLATFORMS, "host"], default="x86_64",
                        help="must match the function's Architectures in template.yaml")
    parser.add_argument("--out", default=str(REPO_ROOT / "dist"))
    args = parser.parse_args()

    sys.path.insert(0, str(REPO_ROOT / "src"))
    from oci_drata.config import load_config  # fail on a bad config now, not after deploying

    load_config(args.config)

    out = Path(args.out)
    package = out / "lambda"
    zip_path = out / "oci-drata-lambda.zip"
    shutil.rmtree(package, ignore_errors=True)
    package.mkdir(parents=True)

    pip = [sys.executable, "-m", "pip", "install", "--no-deps", "--quiet", "--target", str(package),
           "-r", str(REQUIREMENTS)]
    if args.arch != "host":
        pip += ["--implementation", "cp", "--python-version", PYTHON_VERSION, "--only-binary=:all:"]
        for platform in PIP_PLATFORMS[args.arch]:
            pip += ["--platform", platform]
    print(f"installing dependencies ({args.arch}) ...")
    subprocess.run(pip, check=True)

    kept, removed = prune_oci_sdk(package / "oci")
    print(f"pruned oci SDK: kept {len(kept)} packages, removed {len(removed)} unused services")

    shutil.rmtree(package / "bin", ignore_errors=True)  # console scripts of dependencies
    shutil.copytree(SRC, package / "oci_drata", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy(args.config, package / "config.yaml")
    for cache in package.rglob("__pycache__"):
        shutil.rmtree(cache)

    if args.arch == "host":
        env = {**os.environ, "PYTHONPATH": str(package)}
        subprocess.run(
            [sys.executable, "-c",
             "import oci_drata.lambda_handler, oci_drata.runner; print('import check passed from', oci_drata.__file__)"],
            check=True, env=env, cwd=out,
        )

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(package.rglob("*")):
            if file.is_file():
                archive.write(file, file.relative_to(package))
    unzipped, zipped = size_mb(package), zip_path.stat().st_size / 1e6
    print(f"package: {package} ({unzipped:.0f} MB unzipped)\nzip:     {zip_path} ({zipped:.1f} MB)")
    if unzipped > UNZIPPED_LIMIT_MB:
        print(f"ERROR: {unzipped:.0f} MB unzipped exceeds Lambda's {UNZIPPED_LIMIT_MB} MB limit", file=sys.stderr)
        return 1
    if zipped > ZIPPED_UPLOAD_LIMIT_MB:
        print(f"note: over {ZIPPED_UPLOAD_LIMIT_MB} MB zipped -- upload via S3 (sam deploy does this)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
