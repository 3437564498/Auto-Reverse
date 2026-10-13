import importlib.util
from pathlib import Path
import stat
import zipfile

import pytest


spec = importlib.util.spec_from_file_location(
    "static_installer", Path(__file__).resolve().parents[1] / "scripts/install_static_toolchains.py"
)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def test_archive_path_traversal_cannot_write_outside_staging(tmp_path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../escaped", b"data")
    with pytest.raises(ValueError, match="escapes"):
        installer.unpack_zip(archive, tmp_path / "staging")
    assert not (tmp_path / "escaped").exists()


def test_archive_symlink_cannot_point_outside_staging(tmp_path):
    archive = tmp_path / "bad-link.zip"
    link = zipfile.ZipInfo("tool/link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(link, "../../escaped")
    with pytest.raises(ValueError, match="symlink escapes"):
        installer.unpack_zip(archive, tmp_path / "staging")


def test_pinned_archive_hash_mismatch_prevents_install(tmp_path):
    archive = tmp_path / "tool.zip"
    archive.write_bytes(b"untrusted archive")
    pin = {"archive": archive.name, "directory": "tool", "version": "1",
           "sha256": "0" * 64, "url": "https://example.invalid/unused"}
    with pytest.raises(ValueError, match="SHA256"):
        installer.install("tool", pin, tmp_path)
    assert not (tmp_path / "tool").exists()
