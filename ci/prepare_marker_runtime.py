"""Prepare the genuine fixture before local Go or monthly ASAN tests.

Requires Docker buildx and its daemon. The test image gets the same generated
artifact through COPY, so tests inside that image need no nested daemon.
Every invocation builds from the current reviewed source; generation failures
and absent/empty outputs fail closed, even when an older fixture exists.
"""

import os
import subprocess
import tempfile
from pathlib import Path


def prepare(repo):
    destination = repo / "ci/testdata/marker-runtime.zip"
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Remove an earlier result first: a failed bootstrap must not leave an
    # apparently usable old fixture for a later direct Go invocation.
    destination.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="mailstrix-marker-fixture-") as scratch:
        output = Path(scratch) / "export"
        subprocess.run(
            [
                "docker",
                "buildx",
                "build",
                "--builder",
                "default",
                "--file",
                str(repo / "docker/Dockerfile"),
                "--target",
                "marker-fixture-export",
                "--output",
                "type=local,dest=" + str(output),
                str(repo),
            ],
            check=True,
        )
        fixture = output / "marker-runtime.zip"
        if fixture.is_symlink() or not fixture.is_file() or fixture.stat().st_size == 0:
            raise RuntimeError(
                "native marker fixture generation produced no regular nonempty output"
            )
        # Install only after successful generation, atomically on this filesystem.
        with tempfile.NamedTemporaryFile(
            dir=destination.parent, delete=False
        ) as staged:
            staging = Path(staged.name)
            try:
                staged.write(fixture.read_bytes())
                staged.flush()
                os.replace(staging, destination)
            finally:
                staging.unlink(missing_ok=True)
    return destination


if __name__ == "__main__":
    print(prepare(Path(__file__).resolve().parents[1]))
