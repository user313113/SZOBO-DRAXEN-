"""Build a phone-friendly source bundle without reports, caches or Git data.

Run from any directory: python3 /path/to/tools/package_terminal.py
No installer or third-party dependencies are needed to launch the ZIP contents.
"""

import argparse
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
PREFIX = "SZOBO-DRAXEN-terminal"


def build_package(destination=None, *, root=ROOT):
    root = Path(root)
    destination = Path(destination) if destination is not None else root / "reports/releases" / (PREFIX + ".zip")
    files = [root / name for name in ("README.md", "CHANGELOG.md", "pyproject.toml", "start.sh")]
    files += sorted((root / "draxen").rglob("*.py"))
    # The offline tool catalog ships with the app so option 05 works out of the box.
    files.append(root / "data" / "test_tools.json")
    # A positive allowlist deliberately excludes .git, local reports and secrets.
    for source in files:
        if source.is_symlink() or not source.is_file():
            raise ValueError("Paket kaynağı normal dosya olmalı: " + str(source))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(destination, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for source in files:
            archive.write(source, str(Path(PREFIX) / source.relative_to(root)))
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Güncel terminal uygulamasını temiz kaynak ZIP'i olarak paketle")
    parser.add_argument("--output", type=Path, help="ZIP dosyası (varsayılan reports/releases/SZOBO-DRAXEN-terminal.zip)")
    print(build_package(parser.parse_args().output))
