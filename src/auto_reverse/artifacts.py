"""Immutable, verified content-addressed objects and explicit evidence pages.

Object publication is separate from domain transactions.  A caller must commit
the returned reference in its domain ledger; an uncommitted object is harmless.
Nothing in this module loads or executes an input library.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, BinaryIO


_OBJECT_ID = re.compile(r"sha256:([0-9a-f]{64})\Z")
_REF_ID = re.compile(r"ref:sha256:([0-9a-f]{64})\Z")
_INPUT_ID = re.compile(r"input:sha256:([0-9a-f]{64})\Z")
_CHUNK = 1024 * 1024


class ArtifactError(ValueError):
    """An invalid reference, corrupted object, or unsafe store path."""


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


class ArtifactStore:
    """Filesystem object store with atomic no-replace publication.

    ``artifact_id`` identifies bytes, ``reference_id`` identifies an immutable
    metadata reference.  Multiple references may describe the same bytes.
    Pagination offsets and limits count bytes; data is returned as base64 so
    pages are lossless even across UTF-8 boundaries.
    """

    max_page_bytes = 1024 * 1024

    def __init__(self, state_dir: str | Path):
        self.state_dir = Path(state_dir).expanduser().resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.root = self.state_dir / "artifacts"
        self._mkdir(self.root)
        for name in ("objects", "references", "inputs", "tmp"):
            self._mkdir(self.root / name)

    def _mkdir(self, path: Path) -> None:
        if path.is_symlink():
            raise ArtifactError(f"store directory is a symlink: {path.name}")
        path.mkdir(parents=True, exist_ok=True)
        self._safe(path)

    def _safe(self, path: Path) -> Path:
        # Reject symlink components, including a final link that points inside
        # the store.  Object names are never derived from arbitrary user paths.
        try:
            relative = path.relative_to(self.state_dir)
        except ValueError as exc:
            raise ArtifactError("path escapes store") from exc
        current = self.state_dir
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                raise ArtifactError("symlink in artifact store")
        if not path.resolve().is_relative_to(self.state_dir):
            raise ArtifactError("path escapes store")
        return path

    @staticmethod
    def _digest_id(artifact_id: str) -> str:
        match = _OBJECT_ID.fullmatch(artifact_id) if isinstance(artifact_id, str) else None
        if match is None:
            raise ArtifactError("expected sha256:<64 lowercase hexadecimal digits>")
        return match[1]

    def _object_path(self, artifact_id: str) -> Path:
        digest = self._digest_id(artifact_id)
        return self._safe(self.root / "objects" / digest[:2] / digest)

    def _publish(self, temporary: Path, destination: Path) -> None:
        self._safe(destination)
        self._mkdir(destination.parent)
        # Hard-link creation is atomic and cannot replace an existing object.
        # chmod before publishing ensures readers never see a writable object.
        temporary.chmod(0o444)
        try:
            os.link(temporary, destination)
            directory_fd = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except FileExistsError:
            self._safe(destination)
        finally:
            temporary.unlink(missing_ok=True)

    def _publish_json(self, destination: Path, value: dict[str, Any]) -> None:
        encoded = _json_bytes(value)
        fd, name = tempfile.mkstemp(prefix="metadata-", dir=self._safe(self.root / "tmp"))
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            self._publish(temporary, destination)
            if destination.read_bytes() != encoded:
                raise ArtifactError("immutable metadata collision or corruption")
        finally:
            temporary.unlink(missing_ok=True)

    def _put_stream(
        self, stream: BinaryIO, *, kind: str, media_type: str, metadata: dict[str, Any] | None
    ) -> dict[str, Any]:
        if not isinstance(kind, str) or not kind:
            raise ArtifactError("kind must be a nonempty string")
        if not isinstance(media_type, str) or not media_type:
            raise ArtifactError("media_type must be a nonempty string")
        # Validate metadata before creating objects.
        extra = {} if metadata is None else metadata
        if not isinstance(extra, dict):
            raise ArtifactError("metadata must be an object")
        _json_bytes(extra)
        fd, name = tempfile.mkstemp(prefix="object-", dir=self._safe(self.root / "tmp"))
        temporary = Path(name)
        digest = hashlib.sha256()
        size = 0
        try:
            with os.fdopen(fd, "wb") as output:
                while block := stream.read(_CHUNK):
                    digest.update(block)
                    output.write(block)
                    size += len(block)
                output.flush()
                os.fsync(output.fileno())
            sha256 = digest.hexdigest()
            artifact_id = f"sha256:{sha256}"
            destination = self._object_path(artifact_id)
            self._publish(temporary, destination)
            self._verify(destination, sha256, size)
            reference = {
                "artifact_id": artifact_id,
                "sha256": sha256,
                "size": size,
                "kind": kind,
                "media_type": media_type,
                "metadata": extra,
                "immutable": True,
                "permissions": "read",
                "scope": extra.get("scope"),
            }
            reference_digest = hashlib.sha256(_json_bytes(reference)).hexdigest()
            reference["reference_id"] = f"ref:sha256:{reference_digest}"
            self._publish_json(self.root / "references" / f"{reference_digest}.json", reference)
            # A bytes-only manifest permits lookup by object id without choosing
            # one of potentially many metadata descriptions of the same object.
            manifest = {
                "artifact_id": artifact_id,
                "sha256": sha256,
                "size": size,
                "immutable": True,
                "permissions": "read",
            }
            self._publish_json(destination.with_suffix(".json"), manifest)
            return reference
        finally:
            temporary.unlink(missing_ok=True)

    def put_bytes(
        self,
        data: bytes,
        *,
        kind: str = "evidence",
        media_type: str = "application/octet-stream",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        from io import BytesIO

        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        return self._put_stream(BytesIO(data), kind=kind, media_type=media_type, metadata=metadata)

    def put_json(
        self, value: Any, *, kind: str = "evidence", metadata: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return self.put_bytes(
            _json_bytes(value), kind=kind, media_type="application/json", metadata=metadata
        )

    def put_file(
        self,
        path: str | Path,
        *,
        kind: str = "evidence",
        media_type: str = "application/octet-stream",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        source = Path(path)
        if not source.is_file():
            raise ArtifactError("source must be a regular file")
        with source.open("rb") as stream:
            return self._put_stream(stream, kind=kind, media_type=media_type, metadata=metadata)

    @staticmethod
    def _verify(path: Path, digest: str, size: int | None = None) -> int:
        actual = hashlib.sha256()
        count = 0
        try:
            with path.open("rb") as stream:
                while block := stream.read(_CHUNK):
                    actual.update(block)
                    count += len(block)
        except OSError as exc:
            raise ArtifactError("artifact is missing or unreadable") from exc
        if actual.hexdigest() != digest or (size is not None and size != count):
            raise ArtifactError("artifact hash or size mismatch")
        return count

    def get_metadata(self, artifact_id: str) -> dict[str, Any]:
        ref = _REF_ID.fullmatch(artifact_id) if isinstance(artifact_id, str) else None
        if ref:
            path = self._safe(self.root / "references" / f"{ref[1]}.json")
        else:
            path = self._object_path(artifact_id).with_suffix(".json")
        try:
            value = json.loads(self._safe(path).read_bytes())
        except (OSError, ValueError) as exc:
            raise ArtifactError("artifact metadata is missing or corrupt") from exc
        if not isinstance(value, dict):
            raise ArtifactError("artifact metadata must be an object")
        if ref:
            checked = dict(value)
            checked.pop("reference_id", None)
            if (
                value.get("reference_id") != artifact_id
                or hashlib.sha256(_json_bytes(checked)).hexdigest() != ref[1]
            ):
                raise ArtifactError("metadata reference hash mismatch")
        elif value.get("artifact_id") != artifact_id:
            raise ArtifactError("metadata artifact id mismatch")
        digest = self._digest_id(value.get("artifact_id"))
        if value.get("sha256") != digest or type(value.get("size")) is not int or value["size"] < 0:
            raise ArtifactError("invalid artifact manifest")
        self._verify(self._object_path(value["artifact_id"]), digest, value["size"])
        return value

    def resolve_artifact(self, artifact_id: str) -> Path:
        metadata = self.get_metadata(artifact_id)
        return self._object_path(metadata["artifact_id"])

    def read_artifact(
        self, artifact_id: str, *, offset: int = 0, limit: int = 65536
    ) -> dict[str, Any]:
        if type(offset) is not int or offset < 0:
            raise ArtifactError("offset must be a nonnegative integer")
        if type(limit) is not int or not 1 <= limit <= self.max_page_bytes:
            raise ArtifactError(f"limit must be between 1 and {self.max_page_bytes}")
        metadata = self.get_metadata(artifact_id)
        total = metadata["size"]
        if offset > total:
            raise ArtifactError("offset exceeds artifact size")
        with self._object_path(metadata["artifact_id"]).open("rb") as stream:
            stream.seek(offset)
            data = stream.read(min(limit, total - offset))
        next_offset = offset + len(data)
        complete = next_offset == total
        return {
            "artifact_id": metadata["artifact_id"],
            "sha256": metadata["sha256"],
            "offset": offset,
            "limit": limit,
            "returned": len(data),
            "total": total,
            "complete": complete,
            "next_cursor": None if complete else {"offset": next_offset},
            "data_base64": base64.b64encode(data).decode("ascii"),
            "encoding": "base64",
        }

    def register_input(self, path: str | Path) -> dict[str, Any]:
        source = Path(path)
        reference = self.put_file(source, kind="input", metadata={"original_name": source.name})
        input_ref = f"input:sha256:{reference['sha256']}"
        mapping = {
            "input_ref": input_ref,
            "artifact_id": reference["artifact_id"],
            "sha256": reference["sha256"],
            "size": reference["size"],
        }
        self._publish_json(self.root / "inputs" / f"{reference['sha256']}.json", mapping)
        return {**reference, "input_ref": input_ref}

    def resolve_input(self, input_ref: str) -> Path:
        match = _INPUT_ID.fullmatch(input_ref) if isinstance(input_ref, str) else None
        if match is None:
            raise ArtifactError("expected input:sha256:<64 lowercase hexadecimal digits>")
        path = self._safe(self.root / "inputs" / f"{match[1]}.json")
        try:
            mapping = json.loads(path.read_bytes())
        except (OSError, ValueError) as exc:
            raise ArtifactError("input is not registered") from exc
        if not isinstance(mapping, dict):
            raise ArtifactError("input mapping must be an object")
        expected_id = f"sha256:{match[1]}"
        if (
            mapping.get("input_ref") != input_ref
            or mapping.get("artifact_id") != expected_id
            or mapping.get("sha256") != match[1]
        ):
            raise ArtifactError("input mapping mismatch")
        metadata = self.get_metadata(expected_id)
        if mapping.get("size") != metadata["size"]:
            raise ArtifactError("input mapping size mismatch")
        return self._object_path(expected_id)
