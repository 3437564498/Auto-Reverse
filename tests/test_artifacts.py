import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json

import pytest

from auto_reverse.artifacts import ArtifactError, ArtifactStore


def test_objects_are_content_addressed_immutable_and_refs_preserve_metadata(tmp_path):
    store = ArtifactStore(tmp_path)
    first = store.put_bytes(b"evidence", metadata={"scope": "function:foo", "source": "raw bytes"})
    second = store.put_bytes(b"evidence", kind="diagnostic", metadata={"scope": "function:bar"})
    assert first["artifact_id"] == second["artifact_id"]
    assert first["reference_id"] != second["reference_id"]
    assert first["sha256"] == hashlib.sha256(b"evidence").hexdigest()
    assert store.get_metadata(first["reference_id"])["metadata"]["source"] == "raw bytes"
    assert store.get_metadata(second["reference_id"])["kind"] == "diagnostic"
    assert store.resolve_artifact(first["artifact_id"]).read_bytes() == b"evidence"
    assert store.resolve_artifact(first["artifact_id"]).stat().st_mode & 0o222 == 0
    assert store.get_metadata(first["artifact_id"])["size"] == 8


def test_pagination_is_explicit_and_lossless_across_utf8_boundaries(tmp_path):
    store = ArtifactStore(tmp_path)
    payload = "证据 immutable\n".encode()
    artifact = store.put_bytes(payload)
    pages, offset = [], 0
    while True:
        page = store.read_artifact(artifact["artifact_id"], offset=offset, limit=2)
        pages.append(base64.b64decode(page["data_base64"]))
        assert page["total"] == len(payload)
        assert page["offset"] == offset
        assert page["returned"] == len(pages[-1])
        if page["complete"]:
            assert page["next_cursor"] is None
            break
        offset = page["next_cursor"]["offset"]
    assert b"".join(pages) == payload


def test_empty_artifact_and_eof_pages_are_complete(tmp_path):
    store = ArtifactStore(tmp_path)
    artifact = store.put_bytes(b"")
    page = store.read_artifact(artifact["artifact_id"])
    assert page["complete"] and page["total"] == 0 and page["data_base64"] == ""
    nonempty = store.put_bytes(b"123")
    assert store.read_artifact(nonempty["artifact_id"], offset=3)["complete"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"offset": -1},
        {"offset": 4},
        {"offset": True},
        {"limit": 0},
        {"limit": 1048577},
        {"limit": False},
    ],
)
def test_pagination_never_silently_clamps_invalid_input(tmp_path, kwargs):
    store = ArtifactStore(tmp_path)
    artifact = store.put_bytes(b"123")
    with pytest.raises(ArtifactError):
        store.read_artifact(artifact["artifact_id"], **kwargs)


@pytest.mark.parametrize(
    "artifact_id",
    [
        "../../outside",
        "sha256:../outside",
        "sha256:" + "A" * 64,
        "sha256:" + "a" * 64 + "/../outside",
        "file:///etc/passwd",
    ],
)
def test_untrusted_references_cannot_be_paths(tmp_path, artifact_id):
    with pytest.raises(ArtifactError):
        ArtifactStore(tmp_path).resolve_artifact(artifact_id)


def test_registration_snapshots_file_and_survives_source_removal(tmp_path):
    source = tmp_path / "original.so"
    source.write_bytes(b"ELF static data")
    store = ArtifactStore(tmp_path / "state")
    registered = store.register_input(source)
    source.unlink()
    assert store.resolve_input(registered["input_ref"]).read_bytes() == b"ELF static data"
    assert ArtifactStore(tmp_path / "state").resolve_input(registered["input_ref"]).exists()
    with pytest.raises(ArtifactError):
        store.resolve_input(registered["artifact_id"])


def test_register_same_bytes_under_different_names_preserves_both_references(tmp_path):
    store = ArtifactStore(tmp_path / "state")
    first, second = tmp_path / "a.so", tmp_path / "b.so"
    first.write_bytes(b"binary")
    second.write_bytes(b"binary")
    a, b = store.register_input(first), store.register_input(second)
    assert a["input_ref"] == b["input_ref"]
    assert a["reference_id"] != b["reference_id"]
    assert store.resolve_input(a["input_ref"]).read_bytes() == b"binary"


def test_corrupted_bytes_are_never_returned_even_with_correct_size(tmp_path):
    store = ArtifactStore(tmp_path)
    artifact = store.put_bytes(b"good")
    path = store.resolve_artifact(artifact["artifact_id"])
    path.chmod(0o644)
    path.write_bytes(b"evil")
    with pytest.raises(ArtifactError, match="hash or size mismatch"):
        store.read_artifact(artifact["artifact_id"])
    with pytest.raises(ArtifactError, match="hash or size mismatch"):
        store.put_bytes(b"good")


def test_reference_metadata_hash_is_verified(tmp_path):
    store = ArtifactStore(tmp_path)
    artifact = store.put_bytes(b"good", metadata={"scope": "foo"})
    path = store.root / "references" / (artifact["reference_id"].split(":")[-1] + ".json")
    metadata = json.loads(path.read_bytes())
    metadata["metadata"]["scope"] = "other"
    path.chmod(0o644)
    path.write_text(json.dumps(metadata))
    with pytest.raises(ArtifactError, match="reference hash mismatch"):
        store.get_metadata(artifact["reference_id"])


def test_symlink_objects_and_store_directories_are_rejected(tmp_path):
    store = ArtifactStore(tmp_path / "state")
    artifact = store.put_bytes(b"good")
    path = store.resolve_artifact(artifact["artifact_id"])
    outside = tmp_path / "outside"
    outside.write_bytes(b"good")
    path.unlink()
    path.symlink_to(outside)
    with pytest.raises(ArtifactError, match="symlink"):
        store.resolve_artifact(artifact["artifact_id"])
    second_state = tmp_path / "other"
    second_state.mkdir()
    (second_state / "artifacts").symlink_to(store.root, target_is_directory=True)
    with pytest.raises(ArtifactError, match="symlink"):
        ArtifactStore(second_state)


def test_parallel_publication_is_idempotent_and_leaves_no_partial_objects(tmp_path):
    store = ArtifactStore(tmp_path)
    payload = bytes(range(256)) * 5000
    with ThreadPoolExecutor(max_workers=8) as workers:
        artifacts = list(workers.map(lambda _: store.put_bytes(payload), range(16)))
    assert len({a["artifact_id"] for a in artifacts}) == 1
    assert len({a["reference_id"] for a in artifacts}) == 1
    assert store.resolve_artifact(artifacts[0]["artifact_id"]).read_bytes() == payload
    assert not list((store.root / "tmp").iterdir())


def test_put_json_canonicalizes_data_and_rejects_nan(tmp_path):
    store = ArtifactStore(tmp_path)
    first = store.put_json({"b": 2, "a": "证据"})
    second = store.put_json({"a": "证据", "b": 2})
    assert first["artifact_id"] == second["artifact_id"]
    assert store.get_metadata(first["reference_id"])["media_type"] == "application/json"
    with pytest.raises(ValueError):
        store.put_json({"bad": float("nan")})
