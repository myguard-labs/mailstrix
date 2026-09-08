"""Freeze supplied local ClamAV assets and qualify with inert inputs only.

Example: python3 -B tools/parity/qualify_clamav.py --assets ASSETS.json --output NEW_DIR
ASSETS.json is an array of [local_source, absolute_image_destination] pairs.
Include /usr/bin/clamscan, its loader/shared libraries and explicit /db/* files.
No dependency discovery, installations, image pulls or database updates occur.
Local scratch images and snapshots are retained; no image is tagged or pushed.
"""

import argparse
import json
import sys
from pathlib import Path

import clamav_adapter as adapter

MARKER = b"MAILSTRIX_PRIVATE_INERT_QUALIFICATION_SIGNATURE_V1"


def require_host_memory(info):
    memory = info.get("MemTotal")
    if type(memory) is not int or memory < 6 << 30:
        raise ValueError(
            "Docker MemTotal must report at least 6GiB for one 4GiB worker"
        )


def qualify(assets, output):
    output = Path(output)
    output.mkdir(mode=0o700)
    info = json.loads(
        adapter.require(
            adapter.call(adapter.DOCKER + ["info", "--format", "{{json .}}"], seconds=5)
        )
    )
    if info.get("CgroupVersion") != "2" or not any(
        "seccomp" in item for item in info.get("SecurityOptions", [])
    ):
        raise ValueError("cgroup v2 and seccomp required")
    require_host_memory(info)
    receipt = {
        "schema_version": 1,
        "scope": "inert_clamav_adapter_qualification_only",
        "runtime": {
            key: info.get(key)
            for key in (
                "ServerVersion",
                "KernelVersion",
                "CgroupVersion",
                "SecurityOptions",
            )
        },
        "policy": {
            "argv": adapter.SCAN_ARGS,
            "invocation_only": True,
            "exhaustive_extraction_coverage": False,
            "freshness_or_current_accuracy_qualified": False,
            "allowed_metadata_diagnostic": "byte-exact ClamAV 1.5.3 historical DB warning",
            "database_verification": (
                "default legacy CVD signatures; empty detached-signature CA directory"
            ),
        },
        "envelope": {
            "memory_bytes": adapter.MEMORY,
            "swap_extra_bytes": 0,
            "cpus": 1,
            "pids": 64,
            "tmpfs": adapter.TMPFS,
            "input_bytes": adapter.MAX_INPUT,
            "output_bytes_per_pipe": adapter.MAX_OUTPUT,
            "scan_seconds": adapter.SECONDS,
            "lifecycle_operation_seconds": 5,
        },
        "cases": {},
    }

    def record(name, backend, data, expected, **kwargs):
        observed = backend.launch(data, **kwargs)
        receipt["cases"][name] = {
            "input_sha256": adapter.digest(data),
            "input_bytes": len(data),
            "image": backend.image,
            "memory_bytes": backend.memory,
            "scan_args": (
                ["--database=/db", "--version"]
                if kwargs.get("version_probe")
                else kwargs.get("scan_args", adapter.SCAN_ARGS)
            ),
            "seconds": kwargs.get("seconds", adapter.SECONDS),
            "observed": observed,
            "expected_status": expected,
        }
        (output / "qualification.json").write_bytes(adapter.canonical(receipt))
        if observed["status"] != expected:
            raise ValueError(
                f"{name}: expected {expected}, observed {observed['status']}"
            )
        print(name + ": " + observed["status"], flush=True)
        return observed

    frozen = adapter.snapshot(assets, output / "engine")
    image = adapter.import_snapshot(output / "engine")
    receipt["engine"] = dict(frozen, image=image)
    backend = adapter.Adapter(image)
    version = record("engine_version", backend, b"", "version", version_probe=True)
    receipt["engine"]["version"] = version["engine_version"]
    if not version["engine_version"].startswith("ClamAV 1.5.3/"):
        raise ValueError(
            "only ClamAV 1.5.3 historical DB diagnostic policy is qualified"
        )
    backend.allow_stale_database = True
    record(
        "full_database_no_detection",
        backend,
        b"This is an inert plain text qualification document.\n",
        "no_detection",
    )
    record(
        "missing_database",
        backend,
        b"inert",
        "execution_error",
        scan_args=[
            arg if not arg.startswith("--database=") else "--database=/absent"
            for arg in adapter.SCAN_ARGS
        ],
    )
    record(
        "scan_limit",
        backend,
        b"inert plain text\n" * 256,
        "scan_limit",
        scan_args=[
            arg if not arg.startswith("--max-filesize=") else "--max-filesize=1K"
            for arg in adapter.SCAN_ARGS
        ],
    )
    record("parent_timeout", backend, b"inert", "timeout", seconds=0.01)
    record(
        "underbudget_database_oom",
        adapter.Adapter(image, memory=32 << 20, allow_stale_database=True),
        b"inert",
        "resource_limit",
    )

    # Private signature is present only in this second qualification snapshot.
    # Its DB identity differs from the unmodified production-database snapshot.
    signature = output / "private.ndb"
    signature.write_text(
        "Mailstrix.Private.Inert:0:*:" + MARKER.hex() + "\n", encoding="ascii"
    )
    test_snapshot = adapter.snapshot(
        [*assets, (str(signature), "/db/mailstrix-private.ndb")],
        output / "private-engine",
    )
    if [
        item
        for item in test_snapshot["assets"]
        if item["path"] != "/db/mailstrix-private.ndb"
    ] != frozen["assets"]:
        raise ValueError("host installation changed between frozen snapshots")
    test_image = adapter.import_snapshot(output / "private-engine")
    receipt["private_engine"] = dict(test_snapshot, image=test_image)
    test_backend = adapter.Adapter(test_image, allow_stale_database=True)
    found = record("private_signature_detection", test_backend, MARKER, "detection")
    if found["detections"] != ["Mailstrix.Private.Inert.UNOFFICIAL"]:
        raise ValueError("private signature identity mismatch")
    record("private_signature_negative", test_backend, MARKER.lower(), "no_detection")
    receipt["qualified"] = True
    (output / "qualification.json").write_bytes(adapter.canonical(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        assets = json.loads(Path(args.assets).read_bytes())
        qualify(assets, args.output)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("qualification failed: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
