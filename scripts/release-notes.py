#!/usr/bin/env python3
"""Extract the CHANGELOG.md section for a release tag.

Usage: release-notes.py --tag vX.Y.Z [--changelog CHANGELOG.md] --notes-file OUT
Input: a Keep a Changelog file. The heading is "## [X.Y.Z]" or "## [vX.Y.Z]",
optionally followed by " - YYYY-MM-DD". The body runs to the next "## " heading,
a link-reference footer line ("[x]: url") or EOF, and is trimmed.
Fails closed (exit 1, nothing written) for a malformed tag, or a missing,
duplicated or empty section. "[Unreleased]" is never selected.
"""

import argparse
import re
import sys
from pathlib import Path

# SemVer 2.0.0: numeric prerelease identifiers have no leading zero; no
# prerelease or build identifier is empty.
PRE_ID = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
BUILD_ID = r"[0-9A-Za-z-]+"
SEMVER = (
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-" + PRE_ID + r"(?:\." + PRE_ID + r")*)?"
    r"(?:\+" + BUILD_ID + r"(?:\." + BUILD_ID + r")*)?"
)
TAG_RE = re.compile(r"v(" + SEMVER + r")")
REF_RE = re.compile(r"^\[[^\]]+\]:\s*\S")


class NotesError(Exception):
    pass


def extract(text, tag):
    match = TAG_RE.fullmatch(tag)
    if match is None:
        raise NotesError(f"malformed tag {tag!r}: expected v<semver>")
    version = match.group(1)
    heading = re.compile(
        r"^## \[v?" + re.escape(version) + r"\](?: - [0-9]{4}-[0-9]{2}-[0-9]{2})?\s*$"
    )
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if heading.match(line)]
    if not starts:
        raise NotesError(f"CHANGELOG.md has no section for {version}")
    if len(starts) > 1:
        raise NotesError(f"CHANGELOG.md has {len(starts)} sections for {version}")
    body = []
    for line in lines[starts[0] + 1 :]:
        if line.startswith("## ") or REF_RE.match(line):
            break
        body.append(line)
    notes = "\n".join(body).strip()
    if not notes:
        raise NotesError(f"CHANGELOG.md section for {version} is empty")
    return notes + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tag", required=True)
    parser.add_argument("--changelog", default="CHANGELOG.md")
    parser.add_argument("--notes-file", required=True)
    args = parser.parse_args(argv)
    try:
        text = Path(args.changelog).read_text(encoding="utf-8")
        notes = extract(text, args.tag)
    except (NotesError, OSError, UnicodeDecodeError) as err:
        print(f"release-notes: {err}", file=sys.stderr)
        return 1
    Path(args.notes_file).write_text(notes, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
