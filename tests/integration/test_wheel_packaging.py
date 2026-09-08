from __future__ import annotations

import importlib.util
import subprocess
import sys
import venv
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("build") is None, reason="requires the 'build' package (pip install -e .[dev])"
)


def test_default_schema_loads_from_installed_wheel_outside_repo_checkout(tmp_path: Path) -> None:
    dist_dir = tmp_path / "dist"
    build_result = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "-o", str(dist_dir), str(REPO_ROOT)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert build_result.returncode == 0, build_result.stderr

    wheels = list(dist_dir.glob("*.whl"))
    assert len(wheels) == 1, wheels

    venv_dir = tmp_path / "venv"
    venv.create(venv_dir, with_pip=True)
    venv_python = venv_dir / "bin" / "python"

    install_result = subprocess.run(
        [str(venv_python), "-m", "pip", "install", "-q", str(wheels[0])],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert install_result.returncode == 0, install_result.stderr

    run_result = subprocess.run(
        [
            str(venv_python),
            "-c",
            "from oci_drata.validation.schema import load_schema; "
            "s = load_schema(); "
            "assert s['title'] == 'OCI evidence snapshot', s",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(tmp_path),  # not the repo checkout -- proves no filesystem-relative fallback
    )
    assert run_result.returncode == 0, run_result.stderr
