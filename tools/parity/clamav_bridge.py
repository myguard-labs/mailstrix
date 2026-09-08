"""Bounded private protocol between the Go corpus orchestrator and ClamAV.

Go owns the container name and this process group. On a normal reply this
process has completed container cleanup; after abnormal termination Go first
kills/reaps the group, then handles terminal container cleanup itself.
"""

import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import clamav_adapter as adapter

MAX_JSON = 64 << 10
MAX_TAR = (1 << 30) + (1 << 20)
SHA = re.compile(r"[0-9a-f]{64}")
IDENTITY_FIELDS = {
    "image_id",
    "rootfs_sha256",
    "engine_assets_sha256",
    "database_sha256",
    "version",
}
REQUEST_FIELDS = {
    "version",
    "operation",
    "name",
    "qualification_dir",
    "variant",
    "identity",
    "manifest_sha256",
    "sample_sha256",
    "size",
    "input_unit",
    "scan_args",
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def decode(raw):
    if not raw or len(raw) > MAX_JSON:
        raise ValueError("JSON size")
    return json.loads(raw, object_pairs_hook=unique_object)


def open_regular(path, limit):
    """Validate an already-opened nonblocking descriptor before reading it."""
    stream = os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), "rb")
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
        stream.close()
        raise ValueError("bounded regular file required")
    return stream


def json_file(path):
    with open_regular(path, MAX_JSON) as stream:
        return decode(stream.read(MAX_JSON + 1))


def frozen_identity(directory, variant):
    """Prove DB/engine inventory against bounded tar bytes and the image layer.

    No tar member is extracted or executed. The sole Docker diffID must equal
    the streamed uncompressed tar hash; thus the image contains exactly the
    bytes whose inventory we independently recompute here.
    """
    if variant not in ("engine", "private-engine"):
        raise ValueError("unknown qualification variant")
    root = Path(directory)
    qualification = json_file(root / "qualification.json")
    key = "engine" if variant == "engine" else "private_engine"
    if (
        qualification.get("schema_version") != 1
        or qualification.get("qualified") is not True
    ):
        raise ValueError("qualification incomplete")
    claimed = qualification[key]
    snapshot = json_file(root / variant / "snapshot.json")
    if snapshot.get("schema_version") != 1:
        raise ValueError("snapshot schema")
    actual = []
    total = 0
    cert_directory = False
    with open_regular(root / variant / "rootfs.tar", MAX_TAR) as stream:
        rootfs_sha256 = adapter.stream_digest(stream)
        if rootfs_sha256 != snapshot.get("rootfs_sha256"):
            raise ValueError("snapshot content hash mismatch")
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r:") as archive:
            for count, member in enumerate(archive, 1):
                if count > 129:
                    raise ValueError("snapshot entry limit")
                if (
                    member.isdir()
                    and member.name == "etc/clamav/certs"
                    and not cert_directory
                ):
                    cert_directory = True
                    continue
                if not member.isfile() or not 0 < member.size <= 256 << 20:
                    raise ValueError("unexpected snapshot member")
                total += member.size
                if total > 1 << 30:
                    raise ValueError("snapshot byte limit")
                with archive.extractfile(member) as content:
                    actual.append(
                        {
                            "path": "/" + member.name,
                            "size": member.size,
                            "sha256": adapter.stream_digest(content),
                        }
                    )
    if not cert_directory or actual != snapshot.get("assets"):
        raise ValueError("snapshot inventory mismatch")
    if len({item["path"] for item in actual}) != len(actual):
        raise ValueError("duplicate snapshot asset")
    databases = [item for item in actual if item["path"].startswith("/db/")]
    engines = [item for item in actual if not item["path"].startswith("/db/")]
    if not databases or not any(
        item["path"] == "/usr/bin/clamscan" for item in engines
    ):
        raise ValueError("snapshot scanner or database missing")
    calculated = {
        "image_id": claimed["image"],
        "rootfs_sha256": rootfs_sha256,
        "engine_assets_sha256": adapter.digest(adapter.canonical(engines)),
        "database_sha256": adapter.digest(adapter.canonical(databases)),
    }
    for key in ("rootfs_sha256", "engine_assets_sha256", "database_sha256"):
        if calculated[key] != snapshot.get(key) or calculated[key] != claimed.get(key):
            raise ValueError("claimed inventory identity mismatch")
    image = calculated["image_id"]
    if not isinstance(image, str) or not adapter.IMAGE.fullmatch(image):
        raise ValueError("immutable image required")
    inspected = decode(
        adapter.require(
            adapter.call(
                adapter.DOCKER + ["image", "inspect", "--format={{json .}}", image],
                seconds=5,
            )
        )
    )
    if (
        inspected.get("Id") != image
        or inspected.get("Os") != "linux"
        or inspected.get("Architecture") != "amd64"
        or inspected.get("RootFS")
        != {"Type": "layers", "Layers": ["sha256:" + rootfs_sha256]}
        or inspected.get("Config", {}).get("Volumes")
    ):
        raise ValueError("image does not match frozen rootfs")
    runtime = decode(
        adapter.require(
            adapter.call(adapter.DOCKER + ["info", "--format={{json .}}"], seconds=5)
        )
    )
    if (
        runtime.get("CgroupVersion") != "2"
        or "name=seccomp,profile=builtin" not in runtime.get("SecurityOptions", [])
        or any(
            runtime.get(key) is not True
            for key in ("MemoryLimit", "SwapLimit", "CPUCfsQuota", "PidsLimit")
        )
    ):
        raise ValueError("runtime containment unavailable")
    return calculated


def identity_valid(identity):
    return (
        isinstance(identity, dict)
        and set(identity) == IDENTITY_FIELDS
        and isinstance(identity["image_id"], str)
        and adapter.IMAGE.fullmatch(identity["image_id"])
        and all(
            isinstance(identity[key], str) and SHA.fullmatch(identity[key])
            for key in ("rootfs_sha256", "engine_assets_sha256", "database_sha256")
        )
        and isinstance(identity["version"], str)
        and identity["version"].startswith("ClamAV 1.5.3/")
        and len(identity["version"]) < 180
    )


def exchange(request, data):
    if (
        not isinstance(request, dict)
        or set(request) != REQUEST_FIELDS
        or type(request["version"]) is not int
        or request["version"] != 1
        or request["operation"] not in ("identity", "scan")
        or not isinstance(request["name"], str)
        or not adapter.CONTAINER_NAME.fullmatch(request["name"])
        or type(request["size"]) is not int
        or not 0 <= request["size"] <= 16 << 20
        or request["size"] != len(data)
        or adapter.digest(data) != request["sample_sha256"]
        or not isinstance(request["manifest_sha256"], str)
        or not SHA.fullmatch(request["manifest_sha256"])
        or not isinstance(request["input_unit"], str)
    ):
        raise ValueError("invalid bridge request")
    identity = request["identity"]
    if request["operation"] == "identity":
        if (
            data
            or request["input_unit"] != ""
            or not isinstance(request["qualification_dir"], str)
        ):
            raise ValueError("invalid identity request")
        identity = frozen_identity(request["qualification_dir"], request["variant"])
        backend = adapter.Adapter(identity["image_id"])
        observed = backend.launch(b"", version_probe=True, name=request["name"])
        identity["version"] = observed.get("engine_version", "")
        if observed["status"] == "version" and identity_valid(identity):
            observed["status"] = "ok"
        else:
            observed["status"] = "identity_error"
    else:
        if (
            not identity_valid(identity)
            or request["qualification_dir"]
            or request["variant"]
            or request["input_unit"] not in ("file", "message")
            or request["scan_args"] != adapter.SCAN_ARGS
        ):
            raise ValueError("invalid scan identity")
        backend = adapter.Adapter(identity["image_id"], allow_stale_database=True)
        observed = backend.launch(data, name=request["name"])
    return {
        "version": 1,
        "name": request["name"],
        "manifest_sha256": request["manifest_sha256"],
        "sample_sha256": request["sample_sha256"],
        "size": request["size"],
        "input_unit": request["input_unit"],
        "identity": identity,
        "scan_args": adapter.SCAN_ARGS,
        "status": observed["status"],
        "detections": observed["detections"],
        "database_stale": observed.get("database_stale", False),
        "diagnostics": observed.get("diagnostics", []),
        "terminal": backend.poisoned,
    }


def main():
    adapter.CALL_NEW_SESSION = False
    try:
        header = sys.stdin.buffer.readline(MAX_JSON + 1)
        if not header.endswith(b"\n"):
            raise ValueError("truncated bridge header")
        request = decode(header)
        data = sys.stdin.buffer.read((16 << 20) + 1)
        reply = adapter.canonical(exchange(request, data))
        if len(reply) > MAX_JSON:
            raise ValueError("bridge reply limit")
        sys.stdout.buffer.write(reply)
        return 0
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        RecursionError,
        subprocess.SubprocessError,
        tarfile.TarError,
    ):
        # Do not expose operator paths, native output or sample bytes. Go owns
        # terminal cleanup after this abnormal reply and retains the exact name.
        print("ClamAV bridge failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
