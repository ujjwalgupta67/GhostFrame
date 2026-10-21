import subprocess
import sys
import zipfile
from pathlib import Path

from scripts.build_release import ARCHIVE_ROOT, build_release, collect_release_files, verify_archive
from ghostframe import __version__
from ghostframe.reporting import GHOSTFRAME_VERSION


def _write(path: Path, text: str = "x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text, encoding="utf-8")


def test_clean_package_excludes_virtualenv_caches_reports_and_secrets(tmp_path):
    _write(tmp_path / "app.py", "print('app')")
    _write(tmp_path / "README.md", "readme")
    _write(tmp_path / "requirements.txt", "streamlit")
    _write(tmp_path / "requirements-dev.txt", "pytest")
    _write(tmp_path / "start.sh", "#!/bin/sh")
    _write(tmp_path / "start.bat", "@echo off")
    _write(tmp_path / "ghostframe" / "core.py", "VALUE = 1")
    _write(tmp_path / "tests" / "test_core.py", "def test_ok(): pass")
    _write(tmp_path / ".streamlit" / "config.toml", "[server]")
    _write(tmp_path / "scripts" / "build_release.py", "# script")
    _write(tmp_path / ".venv" / "bin" / "python", "binary")
    _write(tmp_path / "ghostframe" / "__pycache__" / "core.pyc", "compiled")
    _write(tmp_path / ".pytest_cache" / "state", "cache")
    _write(tmp_path / "__MACOSX" / "junk", "junk")
    _write(tmp_path / ".DS_Store", "junk")
    _write(tmp_path / ".env", "SECRET=value")
    _write(tmp_path / ".env.local", "SECRET=value")
    _write(tmp_path / "wallet.key", "private")
    _write(tmp_path / ".anvil" / "state.json", "mnemonic")
    _write(tmp_path / "broadcast" / "tx.json", "transaction")
    _write(tmp_path / ".streamlit" / "secrets.toml", "SECRET=value")
    _write(tmp_path / "report_ghostframe_report.html", "private")
    _write(tmp_path / "uploads" / "personal.pdf", "private")
    _write(tmp_path / ".ghostframe" / "evidence" / "private.gfe", "encrypted-private")
    _write(tmp_path / "tests" / "fixture.gfp", "private-package")
    output = tmp_path / "outside" / "release.zip"
    names = build_release(tmp_path, output)
    size, count = verify_archive(output)
    assert size > 0 and count == len(names)
    joined = "\n".join(names)
    for forbidden in (".venv", ".ghostframe", ".anvil", "broadcast", "wallet.key", "__pycache__", ".pytest_cache", "__MACOSX", ".DS_Store", ".env", "secrets.toml", "personal.pdf", "ghostframe_report", ".gfe", ".gfp"):
        assert forbidden not in joined
    assert f"{ARCHIVE_ROOT}/ghostframe/core.py" in names


def test_current_project_collection_never_includes_local_venv():
    root = Path(__file__).resolve().parent.parent
    relative = [path.relative_to(root).as_posix() for path in collect_release_files(root)]
    assert relative
    assert not any(
        name.startswith((".venv/", ".ghostframe/"))
        or "__pycache__" in name
        or name.endswith((".pyc", ".gfe", ".gfp"))
        for name in relative
    )


def test_release_version_is_consistent_and_docs_are_packaged():
    assert __version__ == GHOSTFRAME_VERSION == "2.2.0"
    assert ARCHIVE_ROOT == "GhostFrame-2.2.0"
    root = Path(__file__).resolve().parent.parent
    relative = {path.relative_to(root).as_posix() for path in collect_release_files(root)}
    assert {"RELEASE_NOTES.md", "docs/ARCHITECTURE.md", "docs/THREAT_MODEL.md", "docs/SECURITY_REVIEW.md", "docs/REPRODUCIBILITY.md", "docs/ACCEPTANCE_MATRIX.md"} <= relative


def test_documented_deployment_script_starts_directly():
    root = Path(__file__).resolve().parent.parent
    completed = subprocess.run(
        [sys.executable, str(root / "scripts" / "deploy_local_anchor.py"), "--help"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0
    assert "Deploy GhostFrameAnchor" in completed.stdout
