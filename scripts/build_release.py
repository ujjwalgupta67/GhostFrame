from __future__ import annotations

import argparse
import runpy
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


VERSION = runpy.run_path(str(Path(__file__).resolve().parent.parent / "ghostframe" / "version.py"))["__version__"]
ARCHIVE_ROOT = f"GhostFrame-{VERSION}"
ROOT_FILES = {
    ".gitignore", "DEMO.md", "README.md", "RELEASE_NOTES.md", "app.py", "requirements.txt", "requirements-dev.txt", "requirements-blockchain.txt", "start.bat", "start.sh",
    "LICENSE", "LICENSE.md", "LICENSE.txt",
}
SOURCE_DIRS = {"ghostframe", "tests", "scripts", ".streamlit", "docs"}
EXCLUDED_DIRS = {".venv", "venv", ".ghostframe", ".anvil", "anvil-state", "broadcast", "cache", "out", "__pycache__", ".pytest_cache", "__MACOSX", ".git", "dist", "reports", "uploads", "test-output", "test_output"}
EXCLUDED_FILES = {".DS_Store", ".env", "secrets.toml"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".tmp", ".log", ".zip", ".gfe", ".gfp", ".key", ".pem"}


def is_excluded(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    if any(part in EXCLUDED_DIRS for part in relative.parts):
        return True
    if path.name in EXCLUDED_FILES or path.suffix.lower() in EXCLUDED_SUFFIXES:
        return True
    if path.name.startswith(".env."):
        return True
    lowered = path.name.lower()
    if lowered.endswith(("_ghostframe_report.html", "_ghostframe_report.json", "_sanitized.pdf", "_sanitized.docx", "_sanitized.jpg", "_sanitized.png")):
        return True
    return False


def collect_release_files(root: Path) -> list[Path]:
    root = root.resolve(); files: list[Path] = []
    for name in sorted(ROOT_FILES):
        candidate = root / name
        if candidate.is_file() and not is_excluded(candidate, root):
            files.append(candidate)
    for directory in sorted(SOURCE_DIRS):
        base = root / directory
        if not base.is_dir():
            continue
        for candidate in sorted(base.rglob("*")):
            if candidate.is_file() and not is_excluded(candidate, root):
                files.append(candidate)
    return sorted(set(files), key=lambda path: path.relative_to(root).as_posix())


def build_release(root: Path, output: Path) -> list[str]:
    root = root.resolve(); output = output.resolve(); output.parent.mkdir(parents=True, exist_ok=True)
    files = collect_release_files(root)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for source in files:
            relative = source.relative_to(root).as_posix()
            info = zipfile.ZipInfo(f"{ARCHIVE_ROOT}/{relative}", date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if relative == "start.sh" else 0o644) << 16
            archive.writestr(info, source.read_bytes())
    return [f"{ARCHIVE_ROOT}/{path.relative_to(root).as_posix()}" for path in files]


def verify_archive(archive_path: Path) -> tuple[int, int]:
    forbidden = EXCLUDED_DIRS | EXCLUDED_FILES
    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"Unsafe archive member: {name}")
            if any(part in forbidden for part in path.parts) or path.suffix.lower() in EXCLUDED_SUFFIXES:
                raise ValueError(f"Excluded content found: {name}")
        with tempfile.TemporaryDirectory(prefix="ghostframe_release_check_") as temp:
            archive.extractall(temp)
            extracted = Path(temp) / ARCHIVE_ROOT
            if not (extracted / "app.py").is_file() or not (extracted / "ghostframe" / "core.py").is_file():
                raise ValueError("Archive is missing required application source files.")
    return archive_path.stat().st_size, len(names)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a clean source-only GhostFrame release archive.")
    parser.add_argument("--output", type=Path, default=Path("dist") / f"GhostFrame-{VERSION}-source.zip")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    contents = build_release(root, args.output)
    size, count = verify_archive(args.output.resolve())
    print(f"Created: {args.output.resolve()}")
    print(f"Compressed size: {size} bytes")
    print(f"Entry count: {count}")
    print("Contents:")
    for name in contents:
        print(name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
