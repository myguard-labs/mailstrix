"""Run the two isolated parity qualification unittest modules in one Python."""

import importlib.util
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUITES = (
    ("packaging/deb/parity_image_cleanup_test.py", "ci_batch_parity_image_cleanup"),
    ("ci/parity_cache_test.py", "ci_batch_parity_cache"),
)


def run_suite(path, module_name, *, stream=None):
    source = ROOT / path
    spec = importlib.util.spec_from_file_location(module_name, source)
    if spec is None or spec.loader is None:
        print(f"cannot load required suite: {path}", file=stream or sys.stderr)
        return False
    module = importlib.util.module_from_spec(spec)
    if module_name in sys.modules:
        print(f"duplicate suite module: {module_name}", file=stream or sys.stderr)
        return False
    original_env = dict(os.environ)
    original_path = list(sys.path)
    original_cwd = Path.cwd()
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        suite = unittest.TestLoader().loadTestsFromModule(module)
        if suite.countTestCases() == 0:
            print(f"no tests in required suite: {path}", file=stream or sys.stderr)
            return False
        output = stream or sys.stderr
        print(f"running required suite: {path}", file=output)
        return (
            unittest.TextTestRunner(stream=output, verbosity=2)
            .run(suite)
            .wasSuccessful()
        )
    except SystemExit as error:
        print(
            f"cannot execute required suite {path}: {error!r}",
            file=stream or sys.stderr,
        )
        return False
    finally:
        sys.modules.pop(module_name, None)
        os.environ.clear()
        os.environ.update(original_env)
        sys.path[:] = original_path
        os.chdir(original_cwd)


def main():
    if len(SUITES) != 2 or len({path for path, _ in SUITES}) != 2:
        print("required parity suite selection is incomplete", file=sys.stderr)
        return 1
    for path, module_name in SUITES:
        if not run_suite(path, module_name):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
