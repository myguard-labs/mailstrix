"""Check repository Docker pins and the reviewed YARA/nfpm download recipes.

This is a static repository policy, not a general shell or Dockerfile analyzer.
The download recipes deliberately accept one fail-fast command shape; changes to
that shape require updating its positive and negative fixtures together.
"""

# PyYAML is installed by the repository's existing runner-isolation checks.
# pylint: disable=missing-function-docstring,import-error

import codecs
import os
import posixpath
import re
import shlex
import sys
import unittest
from pathlib import Path

import yaml
from yaml.nodes import (
    MappingNode,
    Node,
    ScalarNode,
    SequenceNode,
)

# Test names state their contract; method docstrings would only duplicate them.

HEX64 = r"[0-9a-f]{64}"
IMAGE_PINS = {
    "debian:bookworm-slim": (
        "88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171"
    ),
    "docker/dockerfile:1": (
        "ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32"
    ),
    "gcr.io/distroless/base-debian12:nonroot": (
        "7f0c72cd138b442ae0deeb69c08b1acf5525439ba251a49ad93c320a061567e5"
    ),
    "golang:1.26.8-bookworm": (
        "9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81"
    ),
}


def _is_default_https_port(port: str) -> bool:
    """Accept an omitted or ASCII decimal spelling of port 443."""
    return not port or (port.isascii() and port.isdigit() and int(port) == 443)


def _canonical_image_label(label: str) -> str:
    """Normalize equivalent registry authorities for reviewed-pin comparison."""
    authority, separator, remainder = label.partition("/")
    host, port_separator, port = authority.rpartition(":")
    if not port_separator:
        host, port = authority, ""
    hub_hosts = {
        "docker.io",
        "index.docker.io",
        "registry-1.docker.io",
        "registry.hub.docker.com",
    }
    if (
        separator
        and host.casefold().rstrip(".") in hub_hosts
        and _is_default_https_port(port)
    ):
        label = remainder
    elif separator and (
        "." in host or port_separator or host.casefold() == "localhost"
    ):
        canonical_host = host.casefold().rstrip(".")
        canonical_port = "" if _is_default_https_port(port) else ":" + port
        label = canonical_host + canonical_port + "/" + remainder
    return "library/" + label if "/" not in label else label


CANONICAL_IMAGE_PINS = {
    _canonical_image_label(label): digest for label, digest in IMAGE_PINS.items()
}
PINNED_IMAGE_REPOSITORIES = {image.rsplit(":", 1)[0] for image in CANONICAL_IMAGE_PINS}
YARA_PINS = {
    "4.5.2": "1f87056fcb10ee361936ee7b0548444f7974612ebb0e681734d8de7df055d1ec"
}
NFPM_PINS = {
    "2.43.0": "4a4402f8f9ea87c669d6a62b333f8e268439974754dd886a01731ecaf9fa6d66"
}
YARA_RECIPE_PATHS = (
    "docker/Dockerfile",
    "docker/Dockerfile.release",
    "docker/profile/Dockerfile.profile",
)
EXCLUDED_TREE_DIRS = frozenset(
    {".git", ".venv", "node_modules", "target", "third_party", "vendor"}
)
DOCUMENT_SUFFIXES = frozenset({".json", ".md", ".rst", ".txt", ".yaml", ".yml"})
YARA_URL = (
    '"https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz"'
)
YARA_RECIPE = (
    "RUN curl -fsSL "
    + re.escape(YARA_URL)
    + r' -o /tmp/yara\.tar\.gz && echo "'
    + HEX64
    + r'  /tmp/yara\.tar\.gz" \| sha256sum -c -'
    + r" && tar -xzf /tmp/yara\.tar\.gz -C /tmp && rm /tmp/yara\.tar\.gz"
)
NFPM_URL = (
    '"https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/'
    'nfpm_${NFPM_VERSION}_amd64.deb"'
)
NFPM_RECIPE = (
    r"curl -fsSL "
    + re.escape(NFPM_URL)
    + r" -o /tmp/nfpm\.deb\n"
    + r'echo "'
    + HEX64
    + r'  /tmp/nfpm\.deb" \| sha256sum -c -\n'
    + r"sudo dpkg -i /tmp/nfpm\.deb"
)


def _image_repository(image: str) -> str:
    """Return an image repository without its final tag."""
    slash = image.rfind("/")
    colon = image.rfind(":")
    return image[:colon] if colon > slash else image


def _pin_association_errors(image: str) -> list[str]:
    """Bind reviewed readable image labels to their verified index digests."""
    label, separator, digest = image.partition("@sha256:")
    canonical = _canonical_image_label(label)
    if not separator or _image_repository(canonical) not in PINNED_IMAGE_REPOSITORIES:
        return []
    expected = CANONICAL_IMAGE_PINS.get(canonical)
    if expected is None:
        return ["Docker image label has no reviewed digest: " + label]
    if digest != expected:
        return [
            "Docker image label/digest pair does not match the reviewed pin: " + label
        ]
    return []


def _expand_args(value: str, args: dict[str, str]) -> str:
    """Expand Docker ARG defaults used by FROM labels for static comparison."""
    return re.sub(
        r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}",
        lambda match: args.get(match.group(1), match.group(0)),
        value,
    )


def _docker_image_errors(
    image: str,
    raw_image: str,
    stages: set[str],
    local_images: frozenset[str],
) -> list[str]:
    """Validate one image token without trusting overridable ARG defaults."""
    if raw_image.lower() in stages or raw_image in local_images:
        return []
    if not re.fullmatch(r"\S+@sha256:" + HEX64, raw_image):
        return [
            "Docker external base must have a sha256 digest; use a literal token: "
            + image
        ]
    return _pin_association_errors(image)


def _frontend_errors(frontend: str) -> list[str]:
    """Validate one Dockerfile frontend reference."""
    if not re.fullmatch(r"\S+@sha256:" + HEX64, frontend):
        return ["Docker frontend must have a sha256 digest"]
    return _pin_association_errors(frontend)


def _external_sources(line: str) -> list[str]:
    """Extract image/stage sources from COPY and RUN mount instructions."""
    sources = []
    line = re.sub(r"^ONBUILD\s+", "", line, flags=re.IGNORECASE)
    line = re.sub(r",\s+", ",", line)
    line = re.sub(r"(--from=)\s+", r"\1", line, flags=re.IGNORECASE)
    if re.match(r"COPY\s", line, re.IGNORECASE):
        sources.extend(re.findall(r"--from=([^\s]+)", line, re.IGNORECASE))
    if re.match(r"RUN\s", line, re.IGNORECASE):
        sources.extend(
            re.findall(r"--mount=[^\s]*?\bfrom=([^,\s]+)", line, re.IGNORECASE)
        )
    return [source.strip("\"'") for source in sources]


def _external_source_errors(
    line: str,
    args: dict[str, str],
    stages: set[str],
    local_images: frozenset[str],
) -> list[str]:
    """Validate every external COPY or RUN mount image source."""
    errors: list[str] = []
    for raw_source in _external_sources(line):
        source = _expand_args(raw_source, args)
        errors.extend(_docker_image_errors(source, raw_source, stages, local_images))
    return errors


def _mapping_values(mapping: MappingNode, wanted_key: str) -> list[Node]:
    """Return direct values for a decoded mapping key, including duplicates."""
    return [
        value_node
        for key_node, value_node in mapping.value
        if isinstance(key_node, ScalarNode) and key_node.value == wanted_key
    ]


def _mapping_scalar(mapping: MappingNode, name: str) -> str | None:
    """Return the first direct scalar value for a decoded mapping key."""
    for key_node, value_node in mapping.value:
        if (
            isinstance(key_node, ScalarNode)
            and key_node.value == name
            and isinstance(value_node, ScalarNode)
        ):
            return str(value_node.value)
    return None


def _execution_mappings(
    text: str,
) -> tuple[list[MappingNode], list[MappingNode], list[str]]:
    """Return workflow job and executable-step mappings without generic descent."""
    try:
        document = yaml.compose(text)
    except yaml.YAMLError as error:
        return [], [], [f"invalid YAML: {error}"]
    if not isinstance(document, MappingNode):
        return [], [], ["workflow document must be a mapping"]

    jobs: list[MappingNode] = []
    steps: list[MappingNode] = []
    seen_steps: set[int] = set()

    def add_steps(container: MappingNode) -> None:
        for sequence in _mapping_values(container, "steps"):
            if not isinstance(sequence, SequenceNode):
                continue
            for child in sequence.value:
                if isinstance(child, MappingNode) and id(child) not in seen_steps:
                    seen_steps.add(id(child))
                    steps.append(child)

    # Top-level steps are accepted for the isolated policy fixtures. Real
    # workflows use jobs.*.steps and composite actions use runs.steps.
    add_steps(document)
    for runs_node in _mapping_values(document, "runs"):
        if isinstance(runs_node, MappingNode):
            add_steps(runs_node)
    for jobs_node in _mapping_values(document, "jobs"):
        if not isinstance(jobs_node, MappingNode):
            continue
        for _, job_node in jobs_node.value:
            if isinstance(job_node, MappingNode):
                jobs.append(job_node)
                add_steps(job_node)
    return jobs, steps, []


def _yaml_scalar_values(
    text: str, wanted_key: str
) -> tuple[list[tuple[int, str]], list[str]]:
    """Return decoded run/uses values only from executable schema positions."""
    jobs, steps, errors = _execution_mappings(text)
    values: list[tuple[int, str]] = []
    mappings = steps if wanted_key == "run" else [*jobs, *steps]
    for mapping in mappings:
        for key_node, value_node in mapping.value:
            if not isinstance(key_node, ScalarNode) or key_node.value != wanted_key:
                continue
            if isinstance(value_node, ScalarNode):
                values.append((key_node.start_mark.line + 1, str(value_node.value)))
            else:
                errors.append(
                    f"line {key_node.start_mark.line + 1}: "
                    f"{wanted_key} value must be a scalar"
                )
    return values, errors


def _yaml_uses(text: str) -> tuple[list[tuple[int, str]], list[str]]:
    """Extract decoded uses values from every workflow mapping."""
    return _yaml_scalar_values(text, "uses")


def _local_uses_file(root: Path, value: str) -> Path | None:
    """Resolve a local action or reusable workflow without permitting escape."""
    relative = Path(value[2:])
    if relative.is_absolute() or ".." in relative.parts:
        return None
    target = root / relative
    if target.is_file() and target.suffix in {".yml", ".yaml"}:
        return target
    for name in ("action.yml", "action.yaml"):
        candidate = target / name
        if candidate.is_file():
            return candidate
    return None


def _logical_shell_lines(script: str) -> list[str]:
    """Join shell continuations without letting comments consume the next line."""
    logical = []
    pending = ""
    for physical in script.splitlines():
        line = pending + physical.lstrip() if pending else physical
        if not line.lstrip().startswith("#") and re.search(r"\\\s*$", line):
            pending = re.sub(r"\\\s*$", " ", line)
            continue
        logical.append(line)
        pending = ""
    if pending:
        logical.append(pending)
    return logical


def _redirect_token_width(tokens: list[str], index: int) -> int:
    """Return tokens to skip for a shell redirection at index, or zero."""
    token = tokens[index]
    if (
        token.isdigit()
        and index + 1 < len(tokens)
        and re.fullmatch(r"[<>&]+", tokens[index + 1])
    ):
        return 1
    if re.fullmatch(r"[<>&]+", token):
        return 2
    return 0


def _shell_commands(tokens: list[str]) -> list[list[str]]:
    """Split shell tokens at control operators without interpreting arguments."""
    controls = {";", "&", "&&", "|", "||", "(", ")"}
    commands: list[list[str]] = []
    start = 0
    for index, token in enumerate(tokens):
        if token not in controls:
            continue
        if start < index:
            commands.append(tokens[start:index])
        start = index + 1
    if start < len(tokens):
        commands.append(tokens[start:])
    return commands


def _command_word_index(command: list[str]) -> int | None:
    """Return the executable word after assignments and simple shell wrappers."""
    index = 0
    keywords = {"!", "do", "elif", "else", "if", "then", "until", "while"}
    wrappers = {"command", "exec", "nohup"}
    while index < len(command):
        token = command[index]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token):
            index += 1
            continue
        if token in keywords:
            index += 1
            continue
        if token in wrappers:
            index += 1
            while index < len(command) and command[index].startswith("-"):
                index += 1
            continue
        if token == "env":
            index += 1
            while index < len(command) and (
                command[index].startswith("-")
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", command[index])
            ):
                index += 1
            continue
        return index
    return None


def _literal_go_index(command: list[str]) -> int | None:
    """Locate a literal Go executable unless the command only prints arguments."""
    command_index = _command_word_index(command)
    if command_index is None:
        return None
    if command[command_index].rsplit("/", 1)[-1] in {"echo", "printf", "set"}:
        return None
    return next(
        (
            position
            for position in range(command_index, len(command))
            if command[position].rsplit("/", 1)[-1] == "go"
        ),
        None,
    )


def _go_package_refs(command: list[str], start: int) -> list[str]:
    """Return non-option package words, excluding shell redirections."""
    refs: list[str] = []
    for position in range(start, len(command)):
        if _redirect_token_width(command, position):
            continue
        if position and _redirect_token_width(command, position - 1) > 1:
            continue
        if not command[position].startswith("-"):
            refs.append(command[position])
    return refs


def _go_install_from_command(command: list[str]) -> tuple[bool, list[str]]:
    """Return direct Go install references from one executable command."""
    index = _literal_go_index(command)
    if index is None:
        return False, []
    cursor = index + 1
    if cursor < len(command) and command[cursor] == "-C":
        cursor += 2
    elif cursor < len(command) and command[cursor].startswith("-C="):
        cursor += 1
    if cursor >= len(command) or command[cursor] != "install":
        return False, []
    return True, _go_package_refs(command, cursor + 1)


def _go_install_refs(line: str) -> tuple[bool, list[str]]:
    """Use shell tokenization to find direct Go install package arguments."""
    lexer = shlex.shlex(line, posix=True, punctuation_chars="();<>|&")
    lexer.whitespace_split = True
    found = False
    refs: list[str] = []
    for command in _shell_commands(list(lexer)):
        command_found, command_refs = _go_install_from_command(command)
        found = found or command_found
        refs.extend(command_refs)
    return found, refs


def _without_empty_shell_expansions(line: str) -> str:
    """Expose command words split by empty or ANSI-C Bash expansions."""

    def decode_ansi(match: re.Match[str]) -> str:
        try:
            return codecs.decode(match.group(1), "unicode_escape")
        except (UnicodeDecodeError, ValueError):
            return match.group(1)

    line = re.sub(r"\$\{[^{}]*\}", "", line)
    line = re.sub(r"\$'([^'\\]*(?:\\.[^'\\]*)*)'", decode_ansi, line)
    return re.sub(r'\$"([^"\\]*(?:\\.[^"\\]*)*)"', r"\1", line)


def _is_dynamic_shell_word(word: str) -> bool:
    """Return whether a shell word contains parameter or command expansion."""
    return "$" in word or "`" in word


def _has_substituted_install_command(line: str) -> bool:
    """Reject dynamic command or Go subcommand words that can become install."""
    dynamic_word = (
        r"(?:\S*\$\([^)]*\)\S*|\S*`[^`]*`\S*|"
        r"\S*\$(?:\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*)\S*)"
    )
    prefix = r"(?:^|[;&|()]\s*)(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*"
    literal_go = r"(?:\S*/)?go"
    directory_flag = r"(?:\s+-C(?:=\S+|\s+\S+))?"
    if bool(
        re.search(prefix + literal_go + directory_flag + r"\s+" + dynamic_word, line)
        or re.search(
            prefix + dynamic_word + r"\s+(?:install|" + dynamic_word + r")",
            line,
        )
    ):
        return True
    lexer = shlex.shlex(line, posix=True, punctuation_chars="();<>|&")
    lexer.whitespace_split = True
    for command in _shell_commands(list(lexer)):
        index = _command_word_index(command)
        if index is None or command[index].rsplit("/", 1)[-1] in {
            "echo",
            "printf",
            "set",
        }:
            continue
        for position in range(index, len(command) - 1):
            word = command[position]
            following = command[position + 1]
            if word.rsplit("/", 1)[-1] == "go" and _is_dynamic_shell_word(
                following
            ):
                return True
            if (
                position == index
                and _is_dynamic_shell_word(word)
                and (following == "install" or _is_dynamic_shell_word(following))
            ):
                return True
    return False


def _shell_c_payloads(line: str) -> list[str]:
    """Return literal command strings passed to supported POSIX-like shells."""
    lexer = shlex.shlex(line, posix=True, punctuation_chars="();<>|&")
    lexer.whitespace_split = True
    payloads: list[str] = []
    for command in _shell_commands(list(lexer)):
        index = _command_word_index(command)
        if index is None or command[index].rsplit("/", 1)[-1] not in {
            "bash",
            "dash",
            "sh",
        }:
            continue
        option = next(
            (
                position
                for position in range(index + 1, len(command))
                if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", command[position])
            ),
            None,
        )
        if option is None:
            continue
        cursor = option + 1
        while cursor < len(command) and command[cursor].startswith("-"):
            cursor += 1
        if cursor < len(command):
            payloads.append(command[cursor])
    return payloads


def _nested_shell_errors(location: str, line: str, nesting: int) -> list[str]:
    """Inspect literal shell -c payloads, failing closed at the depth bound."""
    payloads = _shell_c_payloads(line)
    if payloads and nesting >= 4:
        return [f"{location}: nested shell commands exceed the inspected depth"]
    errors: list[str] = []
    for payload in payloads:
        for nested_line in _logical_shell_lines(payload):
            if not nested_line.lstrip().startswith("#"):
                errors.extend(
                    _go_install_line_errors(location, nested_line, nesting + 1)
                )
    return errors


def _go_install_line_errors(
    location: str, line: str, nesting: int = 0
) -> list[str]:
    """Validate literal Go install arguments on one logical shell line."""
    errors: list[str] = []
    try:
        found, refs = _go_install_refs(line)
    except ValueError as error:
        if "go" in line and "install" in line:
            errors.append(f"{location}: invalid shell quoting: {error}")
        return errors
    nested_errors = _nested_shell_errors(location, line, nesting)
    if not found:
        normalized = _without_empty_shell_expansions(line)
        try:
            expanded_command, _ = _go_install_refs(normalized)
        except ValueError:
            expanded_command = False
        if expanded_command or _has_substituted_install_command(line):
            errors.append(
                f"{location}: possible go install uses unsupported command syntax; "
                "use literal command words"
            )
        return errors + nested_errors
    if not refs:
        errors.append(f"{location}: go install has no package reference")
    for ref in refs:
        exact = re.fullmatch(
            r"[^@\s]+@v[0-9]+\.[0-9]+\.[0-9]+"
            r"(?:-[0-9A-Za-z.-]+)?(?:\+incompatible)?",
            ref,
        )
        if not exact:
            errors.append(
                f"{location}: go install without an exact pinned version: {ref}"
            )
    return errors + nested_errors


def _go_install_errors(root: Path, path: Path, text: str) -> list[str]:
    """Reject mutable Go tool versions in decoded workflow shell blocks."""
    errors: list[str] = []
    relative = path.relative_to(root)
    runs, parse_errors = _yaml_scalar_values(text, "run")
    errors.extend(f"{relative}: {error}" for error in parse_errors)
    for lineno, script in runs:
        for line in _logical_shell_lines(script):
            if not line.lstrip().startswith("#"):
                errors.extend(_go_install_line_errors(f"{relative}:{lineno}", line))
    return errors


def _action_repository(action: str) -> str:
    """Return the case-insensitive repository that a commit SHA pins."""
    return "/".join(part.casefold() for part in action.split("/")[:2])


def _uses_errors(
    root: Path, path: Path, text: str
) -> tuple[list[str], list[Path], list[tuple[str, str]]]:
    """Validate uses entries and return local manifests plus immutable pins."""
    errors: list[str] = []
    local_files: list[Path] = []
    pins: list[tuple[str, str]] = []
    uses, parse_errors = _yaml_uses(text)
    relative = path.relative_to(root)
    errors.extend(f"{relative}: {error}" for error in parse_errors)
    for lineno, value in uses:
        if value.startswith("./"):
            manifest = _local_uses_file(root, value)
            if manifest is None:
                errors.append(
                    f"{relative}:{lineno}: local action manifest not found: {value}"
                )
            else:
                local_files.append(manifest)
            continue
        match = re.fullmatch(r"([A-Za-z0-9._/-]+)@([0-9a-f]{40})", value)
        if match is None:
            errors.append(
                f"{relative}:{lineno}: third-party action(s) not pinned "
                f"to a full commit SHA: {value}"
            )
        else:
            pins.append((_action_repository(match.group(1)), match.group(2)))
    return errors, local_files, pins


def _workflow_entry_paths(root: Path) -> list[Path]:
    """Return workflow and recursively reachable local-action manifests."""
    workflows = sorted((root / ".github/workflows").glob("*.yml"))
    workflows += sorted((root / ".github/workflows").glob("*.yaml"))
    actions_root = root / ".github/actions"
    queued = list(workflows)
    if actions_root.is_dir():
        queued.extend(sorted(actions_root.rglob("*.yml")))
        queued.extend(sorted(actions_root.rglob("*.yaml")))
    seen: set[Path] = set()
    while queued:
        path = queued.pop(0)
        if path in seen:
            continue
        seen.add(path)
        uses, _ = _yaml_uses(path.read_text(encoding="utf-8", errors="replace"))
        for _, value in uses:
            if value.startswith("./"):
                manifest = _local_uses_file(root, value)
                if manifest is not None:
                    queued.append(manifest)
    return sorted(seen)


def workflow_errors(root: Path) -> list[str]:
    """Recursively enforce action and Go-tool pins from every workflow entry."""
    workflows = list((root / ".github/workflows").glob("*.yml"))
    workflows += list((root / ".github/workflows").glob("*.yaml"))
    if not workflows:
        return [f"no workflows found under {root / '.github/workflows'}"]
    paths = _workflow_entry_paths(root)
    errors: list[str] = []
    action_pins: dict[str, set[str]] = {}
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        uses_errors, _, pins = _uses_errors(root, path, text)
        errors.extend(uses_errors)
        for action, sha in pins:
            action_pins.setdefault(action, set()).add(sha)
        errors.extend(_go_install_errors(root, path, text))

    for action, shas in sorted(action_pins.items()):
        if len(shas) > 1:
            errors.append(
                "inconsistent pinned action SHAs: "
                f"{action} pinned to multiple SHAs: {' '.join(sorted(shas))}"
            )
    return errors


def _cache_path_covers_go_bin(cache_path: str | None) -> bool:
    """Return whether an actions/cache path includes the Go binary directory."""
    # Canonicalize home aliases before GOPATH and dot segments so every form
    # reaches the same ~/go path without allowing normpath to erase the alias.
    entries = [
        re.sub(
            r"/{2,}",
            "/",
            re.sub(
                r"^(?:\$\{\{\s*env\.HOME\s*\}\}|\$\{HOME\}|\$HOME"
                r"|/home/[^/]+|/root)/",
                "~/",
                entry.strip(),
                flags=re.IGNORECASE,
            ),
        ).rstrip("/")
        for entry in (cache_path or "").splitlines()
        if entry.strip()
    ]
    entries = [
        posixpath.normpath(
            re.sub(
                r"^(?:\$\{\{\s*env\.GOPATH\s*\}\}|\$\{GOPATH\}|\$GOPATH)"
                r"(?=/|$)",
                "~/go",
                entry,
                flags=re.IGNORECASE,
            )
        )
        for entry in entries
    ]
    return any(
        entry in {"~/go", "~/go/bin"}
        or entry.startswith(("~/go/bin/", "~/go/*", "~/go/**"))
        for entry in entries
    )


def _cache_step_has_unbound_key(step: MappingNode, expected: re.Pattern[str]) -> bool:
    """Return whether one Go-tool cache step lacks the required hash expression."""
    uses = _mapping_scalar(step, "uses") or ""
    is_cache = bool(
        re.fullmatch(r"(?i)actions/cache(?:/(?:restore|save))?@[0-9a-f]{40}", uses)
    )
    is_gotools = _mapping_scalar(step, "id") == "gotools"
    if not is_cache:
        return is_gotools
    for with_node in _mapping_values(step, "with"):
        if not isinstance(with_node, MappingNode):
            continue
        covers_go_bin = _cache_path_covers_go_bin(_mapping_scalar(with_node, "path"))
        if is_gotools and not covers_go_bin:
            return True
        if covers_go_bin:
            return not expected.search(_mapping_scalar(with_node, "key") or "")
    return is_gotools


def _tool_cache_errors(root: Path) -> list[str]:
    """Bind the analysis-tool binary cache to workflow and compiler inputs."""
    workflow_path = root / ".github/workflows/ci.yml"
    if not workflow_path.is_file():
        return []
    _, steps, parse_errors = _execution_mappings(
        workflow_path.read_text(encoding="utf-8", errors="replace")
    )
    if parse_errors:
        return parse_errors
    expected = re.compile(
        r"\$\{\{\s*hashFiles\(\s*'\.github/workflows/ci\.yml'\s*,\s*"
        r"'\.github/actions/go-setup/action\.yml'\s*\)\s*\}\}"
    )
    return [
        "analysis-tool cache key does not hash workflow and Go setup inputs"
        for step in steps
        if _cache_step_has_unbound_key(step, expected)
    ]


def _docker_logical_text(text: str) -> str:
    """Join Dockerfile continuations using its declared parser escape."""
    escape = "\\"
    for physical in text.splitlines():
        directive = re.fullmatch(
            r"[ \t]*#[ \t]*([A-Za-z]+)[ \t]*=[ \t]*(\S+)[ \t]*", physical
        )
        if directive is None:
            break
        if directive.group(1).casefold() == "escape" and directive.group(2) in {
            "\\",
            "`",
        }:
            escape = directive.group(2)

    continuation = re.compile(
        r"[ \t]*" + re.escape(escape) + r"[ \t]*\r?$"
    )
    logical: list[str] = []
    pending = ""
    for physical in text.splitlines():
        if pending and physical.lstrip().startswith("#"):
            continue
        line = pending + physical.lstrip() if pending else physical
        if not line.lstrip().startswith("#") and continuation.search(line):
            pending = continuation.sub(" ", line)
            continue
        logical.append(line)
        pending = ""
    if pending:
        logical.append(pending)
    return "\n".join(logical)


def docker_errors(text: str, local_images: frozenset[str] = frozenset()) -> list[str]:
    """Require immutable external images and checked YARA extraction."""
    errors = []
    stages = {"scratch"}
    stage_number = 0
    args = {}
    yara_recipes = 0
    # Join only Docker continuation lines; command chaining remains significant.
    logical = _docker_logical_text(text)
    for line in logical.splitlines():
        line = line.strip()
        yara_recipes += bool(re.fullmatch(YARA_RECIPE, line))
        arg = re.fullmatch(r"ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)", line)
        if arg:
            args[arg.group(1)] = arg.group(2)
        directive = re.fullmatch(r"#\s*syntax\s*=\s*(\S+)", line, re.IGNORECASE)
        if directive:
            errors.extend(_frontend_errors(directive.group(1)))
        if re.match(r"FROM\s", line, re.IGNORECASE):
            fields = line.split()
            if fields[1].startswith("--platform="):
                fields.pop(1)
            raw_image = fields[1]
            image = _expand_args(raw_image, args)
            errors.extend(_docker_image_errors(image, raw_image, stages, local_images))
            stages.add(str(stage_number))
            stage_number += 1
            if len(fields) == 4 and fields[2].lower() == "as":
                stages.add(fields[3].lower())
        errors.extend(_external_source_errors(line, args, stages, local_images))
        if (
            "virustotal/yara/" in line.casefold()
            and not line.startswith("#")
            and not re.fullmatch(YARA_RECIPE, line)
        ):
            errors.append(
                "YARA download must verify a pinned checksum before extraction"
            )
    if re.search(r"(?m)^ARG YARA_VERSION(?:=|$)", text) and yara_recipes != 1:
        errors.append("YARA build must contain exactly one checked source download")
    return errors


def yara_pin(text: str) -> tuple[str, str] | None:
    """Return the single checked YARA version/checksum tuple from a recipe."""
    version = re.search(r"(?m)^ARG YARA_VERSION=([^\s]+)$", text)
    logical = _docker_logical_text(text)
    checksums = []
    for line in logical.splitlines():
        line = line.strip()
        if re.fullmatch(YARA_RECIPE, line):
            match = re.search(r'echo "(' + HEX64 + r')  /tmp/yara\.tar\.gz"', line)
            if match:
                checksums.append(match.group(1))
    if version is None or len(checksums) != 1:
        return None
    return version.group(1), checksums[0]


def _nfpm_pin_error(lines: list[str], recipe: str) -> str | None:
    """Validate the reviewed nfpm version/checksum pair in one recipe."""
    version = re.search(r"(?m)^NFPM_VERSION=([^\s]+)$", "\n".join(lines))
    checksum = re.search(r'echo "(' + HEX64 + r')  /tmp/nfpm\.deb"', recipe)
    if (
        version is None
        or checksum is None
        or NFPM_PINS.get(version.group(1)) != checksum.group(1)
    ):
        return "nfpm version/checksum pair does not match the reviewed pin"
    return None


def _nfpm_block_result(block: str) -> tuple[int, int, list[str]]:
    """Count nfpm references and valid recipes in one literal shell block."""
    downloads = 0
    checked = 0
    pin_errors: list[str] = []
    lines = [
        line.strip()
        for line in block.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    downloads += sum("goreleaser/nfpm/" in line.casefold() for line in lines)
    for index, line in enumerate(lines):
        if "goreleaser/nfpm/" not in line.casefold():
            continue
        recipe = "\n".join(lines[index : index + 3])
        if lines[0] == "set -euo pipefail" and re.fullmatch(NFPM_RECIPE, recipe):
            checked += 1
            pin_error = _nfpm_pin_error(lines, recipe)
            if pin_error:
                pin_errors.append(pin_error)
    return downloads, checked, pin_errors


def release_errors(text: str, *, required: bool = False) -> list[str]:
    """Require the nfpm download/check/install sequence in a strict shell step."""
    errors = []
    runs, parse_errors = _yaml_scalar_values(text, "run")
    errors.extend(parse_errors)
    downloads = 0
    checked = 0
    pin_errors: list[str] = []
    for _, block in runs:
        block_downloads, block_checked, block_pin_errors = _nfpm_block_result(block)
        downloads += block_downloads
        checked += block_checked
        pin_errors.extend(block_pin_errors)
    # Count across the whole document as well, so an unsupported run style fails
    # closed instead of disappearing from the parsed block set.
    total = sum(
        "goreleaser/nfpm/" in line.casefold()
        for line in text.splitlines()
        if not line.lstrip().startswith("#")
    )
    installs = len(
        re.findall(r"(?m)^\s*sudo dpkg (?:-i|--install) /tmp/nfpm\.deb\s*$", text)
    )
    if (
        total != checked
        or downloads != checked
        or installs != checked
        or (required and checked != 1)
    ):
        errors.append("nfpm download must verify a pinned checksum before sudo install")
    errors.extend(pin_errors)
    return errors


class PinFixtures(unittest.TestCase):
    """Benign static fixtures exercise each new policy arm and its boundary."""

    digest = "1" * 64
    yara_version, yara_digest = next(iter(YARA_PINS.items()))
    nfpm_version, nfpm_digest = next(iter(NFPM_PINS.items()))
    yara = (
        f"RUN curl -fsSL {YARA_URL} -o /tmp/yara.tar.gz "
        f'&& echo "{yara_digest}  /tmp/yara.tar.gz" | sha256sum -c - '
        "&& tar -xzf /tmp/yara.tar.gz -C /tmp && rm /tmp/yara.tar.gz"
    )
    nfpm = (
        "steps:\n  - run: |\n      set -euo pipefail\n"
        f"      NFPM_VERSION={nfpm_version}\n"
        f"      curl -fsSL {NFPM_URL} -o /tmp/nfpm.deb\n"
        f'      echo "{nfpm_digest}  /tmp/nfpm.deb" | sha256sum -c -\n'
        "      sudo dpkg -i /tmp/nfpm.deb\n"
    )

    def test_external_and_local_stages(self) -> None:
        self.assertEqual(
            [],
            docker_errors(
                f"FROM example.test/base:1@sha256:{self.digest} AS builder\n"
                "FROM builder AS test\nFROM scratch AS output\n"
            ),
        )
        self.assertIn(
            "Docker external base", docker_errors("FROM example.test/base:1")[0]
        )
        self.assertIn("Docker external base", docker_errors("FROM unknown_stage")[0])

    def test_external_copy_and_mount_sources(self) -> None:
        for instruction in (
            "COPY --from=example.test/tool:1 /bin/tool /bin/tool",
            "RUN --mount=type=bind,from=example.test/tool:1,target=/tool true",
            "ONBUILD COPY --from=example.test/tool:1 /bin/tool /bin/tool",
            "ONBUILD RUN --mount=type=bind,from=example.test/tool:1,target=/tool true",
        ):
            self.assertIn(
                "Docker external base", docker_errors("FROM scratch\n" + instruction)[0]
            )
            pinned = instruction.replace(":1", f":1@sha256:{self.digest}")
            self.assertEqual([], docker_errors("FROM scratch\n" + pinned))

    def test_nested_shell_payload_uses_logical_line_rules(self) -> None:
        command = (
            "sh -ec '# setup\n"
            "go \\\n"
            "  install example.test/tool@latest'"
        )
        self.assertIn(
            "exact pinned version",
            _go_install_line_errors("fixture", command)[0],
        )

    def test_nested_shell_depth_limit_fails_closed(self) -> None:
        self.assertIn(
            "exceed the inspected depth",
            _go_install_line_errors("fixture", "sh -c 'echo safe'", nesting=4)[0],
        )

    def test_frontend(self) -> None:
        self.assertEqual(
            [], docker_errors(f"# syntax=example.test/frontend:1@sha256:{self.digest}")
        )
        self.assertEqual(
            [], docker_errors(f"#syntax=example.test/frontend:1@sha256:{self.digest}")
        )
        self.assertIn(
            "Docker frontend", docker_errors("# syntax=example.test/frontend:1")[0]
        )
        self.assertIn(
            "Docker frontend", docker_errors("#syntax=example.test/frontend:1")[0]
        )

    def test_known_image_label_matches_reviewed_digest(self) -> None:
        digest = IMAGE_PINS["golang:1.26.8-bookworm"]
        recipe = (
            "ARG GO_VERSION=1.26.8\n"
            f"FROM golang:${{GO_VERSION}}-bookworm@sha256:{digest}\n"
        )
        self.assertEqual([], docker_errors(recipe))
        aliases = (
            "docker.io/library/golang:",
            "index.docker.io:443/library/golang:",
            "registry-1.docker.io:443/library/golang:",
            "registry.hub.docker.com:443/library/golang:",
            "REGISTRY-1.DOCKER.IO/library/golang:",
            "docker.io:0443/library/golang:",
            "docker.io./library/golang:",
        )
        qualified = [
            recipe.replace("FROM golang:", f"FROM {alias}") for alias in aliases
        ]
        for candidate in qualified:
            self.assertEqual([], docker_errors(candidate))
        self.assertIn(
            "label has no reviewed digest",
            docker_errors(recipe.replace("1.26.8", "9.99.99"))[0],
        )
        self.assertIn(
            "label has no reviewed digest",
            docker_errors(qualified[0].replace("1.26.8", "9.99.99"))[0],
        )
        for candidate in qualified[1:]:
            self.assertIn(
                "label has no reviewed digest",
                docker_errors(candidate.replace("1.26.8", "9.99.99"))[0],
            )
        self.assertIn(
            "label/digest pair",
            docker_errors(recipe.replace(digest, "2" * 64))[0],
        )

    def test_yara_checksum_before_extract(self) -> None:
        self.assertEqual([], docker_errors(self.yara))
        self.assertIn(
            "YARA download", docker_errors(f"RUN curl -fsSL {YARA_URL} | tar -xz")[0]
        )
        self.assertIn(
            "YARA download",
            docker_errors(self.yara.replace("sha256sum -c -", "true"))[0],
        )
        self.assertIn(
            "YARA download", docker_errors(self.yara.replace("&& tar", "; tar"))[0]
        )
        self.assertIn(
            "YARA download",
            docker_errors(self.yara.replace(self.yara_digest, "bad"))[0],
        )

    def test_nfpm_checksum_before_install(self) -> None:
        self.assertEqual([], release_errors(self.nfpm))
        self.assertIn(
            "nfpm download",
            release_errors(self.nfpm.replace("sha256sum -c -", "true"))[0],
        )
        self.assertIn(
            "nfpm download",
            release_errors(self.nfpm.replace("set -euo pipefail", "set -u"))[0],
        )
        self.assertIn(
            "nfpm download",
            release_errors(self.nfpm.replace(self.nfpm_digest, "bad"))[0],
        )
        self.assertIn(
            "reviewed pin",
            release_errors(self.nfpm.replace(self.nfpm_version, "9.99.99"))[0],
        )
        self.assertIn(
            "reviewed pin",
            release_errors(self.nfpm.replace(self.nfpm_digest, "2" * 64))[0],
        )
        self.assertIn(
            "nfpm download",
            release_errors(self.nfpm.replace("github.com", "example.test"))[0],
        )
        lines = self.nfpm.splitlines()
        lines[-1], lines[-2] = lines[-2], lines[-1]
        self.assertIn("nfpm download", release_errors("\n".join(lines))[0])


def _local_images_for(root: Path, path: Path, text: str) -> frozenset[str]:
    """Return the one repository-produced image allowed by the integration test."""
    if path.relative_to(root).as_posix() != "contrib/postfix/Dockerfile.integration":
        return frozenset()
    ci_workflow = root / ".github/workflows/ci.yml"
    if not ci_workflow.is_file():
        return frozenset()
    workflow = ci_workflow.read_text(encoding="utf-8", errors="replace")
    workflow = re.sub(r"[ \t]*\\\n\s*", " ", workflow)
    producer = re.search(
        r"(?m)^\s*docker buildx build --target test -f docker/Dockerfile "
        r"-t strixd-test --load(?: [^\n]*?)? \.$",
        workflow,
    )
    if producer and re.search(r"(?mi)^FROM\s+strixd-test(?:\s+AS\s+\S+)?$", text):
        return frozenset({"strixd-test"})
    return frozenset()


def _yara_recipe_paths(root: Path, dockerfiles: dict[Path, str]) -> set[Path]:
    """Return required and discovered Dockerfiles that should build YARA."""
    required = [root / relative for relative in YARA_RECIPE_PATHS]
    paths = {path for path in required if path in dockerfiles}
    for path, text in dockerfiles.items():
        if re.search(r"(?m)^ARG YARA_VERSION(?:=|$)", text) or any(
            "virustotal/yara/" in line.casefold() and not line.lstrip().startswith("#")
            for line in text.splitlines()
        ):
            paths.add(path)
    return paths


def _yara_tree_errors(root: Path, dockerfiles: dict[Path, str]) -> list[str]:
    """Require every YARA recipe to share one reviewed version/checksum."""
    required = [root / relative for relative in YARA_RECIPE_PATHS]
    missing = [path for path in required if path not in dockerfiles]
    errors = [
        f"missing required YARA build recipe: {path.relative_to(root)}"
        for path in missing
    ]
    pins = {}
    for path in sorted(_yara_recipe_paths(root, dockerfiles)):
        pin = yara_pin(dockerfiles[path])
        if pin is None:
            errors.append(f"unreadable YARA build pin: {path.relative_to(root)}")
        else:
            pins[path] = pin
    if errors:
        return errors
    if not pins or len(set(pins.values())) != 1:
        return ["YARA build recipes must use the same version and checksum"]
    version, checksum = next(iter(pins.values()))
    if YARA_PINS.get(version) != checksum:
        return ["YARA version/checksum pair does not match the reviewed pin"]
    return []


def _is_dockerfile_path(root: Path, path: Path) -> bool:
    """Recognize executable Dockerfile/Containerfile naming conventions."""
    name = path.name.casefold()
    return (
        path.is_file()
        and not EXCLUDED_TREE_DIRS.intersection(path.relative_to(root).parts)
        and path.suffix.casefold() not in DOCUMENT_SUFFIXES
        and (
            name.startswith(("dockerfile", "containerfile"))
            or name.endswith((".dockerfile", ".containerfile"))
        )
    )


def _candidate_files(root: Path) -> list[Path]:
    """Walk project-owned paths without descending into dependency/build trees."""
    files: list[Path] = []
    for parent, directories, names in os.walk(root):
        directories[:] = [
            directory
            for directory in directories
            if directory not in EXCLUDED_TREE_DIRS
        ]
        files.extend(Path(parent) / name for name in names)
    return sorted(files)


def _docker_build_arguments(command: list[str]) -> list[str] | None:
    """Return arguments after an executable docker build/buildx build command."""
    index = _command_word_index(command)
    if index is None or command[index].rsplit("/", 1)[-1] in {
        "echo",
        "printf",
        "set",
    }:
        return None
    index = next(
        (
            position
            for position in range(index, len(command))
            if command[position].rsplit("/", 1)[-1] == "docker"
        ),
        None,
    )
    if index is None:
        return None
    arguments = command[index + 1 :]
    value_options = {
        "--config",
        "--context",
        "--host",
        "--log-level",
        "-H",
        "-c",
        "-l",
    }
    while arguments and arguments[0].startswith("-"):
        consumes_value = arguments[0] in value_options
        arguments = arguments[2 if consumes_value else 1 :]
    if arguments[:2] == ["buildx", "build"]:
        return arguments[2:]
    if arguments[:1] == ["build"]:
        return arguments[1:]
    return None


def _dockerfile_option(arguments: list[str]) -> str | None:
    """Return the first explicit Dockerfile option value."""
    for position, argument in enumerate(arguments):
        if argument in {"-f", "--file"}:
            return arguments[position + 1] if position + 1 < len(arguments) else ""
        if argument.startswith("--file="):
            return argument.partition("=")[2]
        if argument.startswith("-f") and len(argument) > 2:
            return argument[2:]
    return None


def _dockerfile_values(line: str) -> list[str]:
    """Extract explicit Dockerfile paths, including literal shell -c payloads."""
    lexer = shlex.shlex(line, posix=True, punctuation_chars="();<>|&")
    lexer.whitespace_split = True
    values: list[str] = []
    for command in _shell_commands(list(lexer)):
        arguments = _docker_build_arguments(command)
        if arguments is None:
            continue
        value = _dockerfile_option(arguments)
        if value is not None:
            values.append(value)
    for payload in _shell_c_payloads(line):
        for nested_line in _logical_shell_lines(payload):
            if not nested_line.lstrip().startswith("#"):
                values.extend(_dockerfile_values(nested_line))
    return values


def _resolve_dockerfile(
    root: Path, location: str, value: str
) -> tuple[Path | None, str | None]:
    """Resolve one literal repository-local Dockerfile selection."""
    if not value or "$" in value or "`" in value:
        return None, f"{location}: Docker build file path must be literal"
    candidate = (root / value).resolve()
    if not candidate.is_relative_to(root.resolve()):
        return None, f"{location}: Docker build file escapes repository: {value}"
    if not candidate.is_file():
        return None, f"{location}: Docker build file does not exist: {value}"
    return candidate, None


def _workflow_dockerfile_references(root: Path) -> tuple[set[Path], list[str]]:
    """Resolve literal Dockerfiles selected by executable workflow build commands."""
    referenced: set[Path] = set()
    errors: list[str] = []
    for workflow in _workflow_entry_paths(root):
        runs, _ = _yaml_scalar_values(
            workflow.read_text(encoding="utf-8", errors="replace"), "run"
        )
        for lineno, script in runs:
            for line in _logical_shell_lines(script):
                try:
                    values = _dockerfile_values(line)
                except ValueError:
                    continue
                for value in values:
                    location = f"{workflow.relative_to(root)}:{lineno}"
                    candidate, error = _resolve_dockerfile(root, location, value)
                    if error:
                        errors.append(error)
                    elif candidate:
                        referenced.add(candidate)
    return referenced, errors


def check_tree(root: Path) -> list[str]:
    """Scan repository-wide Dockerfiles and recursive GitHub YAML files."""
    root = root.resolve()
    errors = workflow_errors(root)
    errors.extend(_tool_cache_errors(root))
    referenced_dockerfiles, reference_errors = _workflow_dockerfile_references(root)
    errors.extend(reference_errors)
    discovered_dockerfiles = {
        path for path in _candidate_files(root) if _is_dockerfile_path(root, path)
    }
    discovered_dockerfiles.update(referenced_dockerfiles)
    dockerfiles = {
        path: path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(discovered_dockerfiles)
    }
    if not dockerfiles:
        errors.append("no Dockerfiles found")
    for path, text in dockerfiles.items():
        # The Postfix integration image consumes binaries built from this
        # checkout by CI. Only that exact producer/consumer pair is exempt;
        # other ARG-based FROM references must carry literal digest pins.
        local_images = _local_images_for(root, path, text)
        errors.extend(
            f"{path.relative_to(root)}: {error}"
            for error in docker_errors(
                text,
                local_images,
            )
        )
    errors.extend(_yara_tree_errors(root, dockerfiles))
    release_path = root / ".github/workflows/release.yml"
    if not release_path.is_file():
        errors.append(
            "missing required nfpm release workflow: .github/workflows/release.yml"
        )
    for path in sorted((root / ".github").rglob("*")):
        if path.suffix in {".yml", ".yaml"} and path.is_file():
            errors.extend(
                f"{path.relative_to(root)}: {error}"
                for error in release_errors(
                    path.read_text(encoding="utf-8", errors="replace"),
                    required=path == release_path,
                )
            )
    return errors


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PinFixtures)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful():
        sys.exit(1)
    problems = check_tree(Path(sys.argv[1]))
    for problem in problems:
        print("FAIL - " + problem)
    if problems:
        sys.exit(1)
    print("ok   - every third-party action is pinned to a full commit SHA")
    print("ok   - every go install pins an exact version")
    print("ok   - every SHA-pinned action is consistent across all workflows")
    print("ok   - Docker images and YARA/nfpm downloads have immutable pins")
