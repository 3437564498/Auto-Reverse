"""Fetch pinned public analysis/compiler tools into work/, preserving proxy/CA.

No input, candidate, tool plugin or recovered library is executed by this installer.
Archives are verified before extraction; existing tool directories are retained.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.request
import zipfile


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def unpack_zip(archive, destination):
    root = Path(destination).resolve()
    with zipfile.ZipFile(archive) as bundle:
        for entry in bundle.infolist():
            target = root / entry.filename
            if not target.resolve().is_relative_to(root):
                raise ValueError("archive member escapes extraction directory")
            mode = entry.external_attr >> 16
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            elif stat.S_ISLNK(mode):
                link = bundle.read(entry).decode("utf-8")
                if Path(link).is_absolute() or not (target.parent / link).resolve().is_relative_to(root):
                    raise ValueError("archive symlink escapes extraction directory")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(link)
            elif stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
                raise ValueError("unsupported archive member type")
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(entry) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod((mode & 0o755) or 0o644)


def install(name, pin, output):
    archive = output / pin["archive"]
    installed = output / pin["directory"]
    if not archive.exists():
        temporary = archive.with_suffix(archive.suffix + ".download")
        try:
            # urllib honors inherited HTTPS_PROXY and configured system CA trust.
            with urllib.request.urlopen(pin["url"], timeout=30) as response, temporary.open("xb") as stream:
                shutil.copyfileobj(response, stream, length=1024 * 1024)
            temporary.replace(archive)
        finally:
            temporary.unlink(missing_ok=True)
    actual = digest(archive)
    if actual != pin["sha256"]:
        raise ValueError(f"{name} archive does not match the pinned SHA256")
    if installed.is_symlink():
        raise ValueError("installed tool directory is a symlink")
    existing = installed.exists()
    if existing and not installed.is_dir():
        raise ValueError("installed tool path is not a directory")
    if not installed.exists():
        with tempfile.TemporaryDirectory(prefix=f"{name}-extract-", dir=output) as folder:
            staging = Path(folder)
            if zipfile.is_zipfile(archive):
                unpack_zip(archive, staging)
            else:
                with tarfile.open(archive) as bundle:
                    bundle.extractall(staging, filter="data")
            extracted = staging / pin["directory"]
            if not extracted.is_dir() or extracted.is_symlink():
                raise ValueError("archive lacks its expected tool directory")
            extracted.rename(installed)
    return {"name": name, "version": pin["version"], "archive_sha256": actual,
            "directory": str(installed), "existing_directory_retained": existing,
            "tool_executed": False, "target_or_candidate_executed": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="work/tools")
    parser.add_argument("--tools", nargs="+", choices=["ndk", "ghidra", "jdk"],
                        default=["ndk", "ghidra", "jdk"])
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    pin_path = Path(__file__).resolve().parents[1] / "toolchains/static.lock.json"
    pins = json.loads(pin_path.read_text())
    results = []
    for name in args.tools:
        print(f"Checking/installing pinned {name}", file=sys.stderr)
        results.append(install(name, pins[name], output))
    print(json.dumps({"schema_version": 1, "tools": results}, indent=2))


if __name__ == "__main__":
    main()
