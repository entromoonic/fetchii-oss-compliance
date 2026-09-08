#!/usr/bin/env python3
"""Offline policy checks for compliance records, locks, docs, and local links."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit, urlunsplit

try:
    from packaging.version import InvalidVersion, Version
except ImportError:  # pragma: no cover - pip vendors packaging on CI runners.
    from pip._vendor.packaging.version import InvalidVersion, Version


ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
CALVER = re.compile(r"^[0-9]{4}\.[0-9]{2}\.[0-9]{2}$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
DISPLAY_VERSION = re.compile(r"^[0-9a-f]{8}$")
PYTHON_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
PACKAGE_VERSION = re.compile(
    r"^(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*"
    r"(?:(?:a|b|rc)[0-9]+)?"
    r"(?:\.post[0-9]+)?(?:\.dev[0-9]+)?"
    r"(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?$"
)
LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
CORE_RECORD_SCHEMA = "fetchii-core-record/v3"
ARIA2_RECORD_SCHEMA = "aria2-record/v4"
ARIA2_BUILDER_REPOSITORY = "dynamicfire/fetchii-aria2-builder"
CORE_MANIFEST_SCHEMA_VERSION = 1
CORE_SOURCE_REPOSITORY = "https://github.com/yt-dlp/yt-dlp.git"
CORE_SOURCE_HOST = "downloads.beamdrop.entromoonic.com"
CORE_SOURCE_PREFIX = "/fetchii-core/sources"
CORE_ARTIFACT_PREFIX = "/fetchii-core"
POLICY_WORKFLOW = Path(".github/workflows/compliance-policy.yml")
DEPENDENCY_HOST = "files.pythonhosted.org"
MAX_SOURCE_ARCHIVE_BYTES = 1_000_000_000
MAX_RECORD_BYTES = 1_000_000
# These recipe-only records predate the locked-record policy. Pinning their exact
# bytes preserves history without treating them as digest evidence or allowing a
# newly added legacy record to bypass the v3 requirement.
HISTORICAL_ARIA2_RECIPE_SHA256 = {
    "1.37.0": "fbd8da733239fc314cb793c729addafc1c884f8e52938b686cbe2c9fafeded53",
}
HISTORICAL_CORE_RECIPE_SHA256 = {
    "2026.06.09": "3abaeaf9522a4e53b975dfaab9109d1a8be52dd4749ece00efd03359ee0886ff",
    "2026.07.04": "003839ecc4a1173aecda186f38e2d90a1ad892eef6afe41f35b89cc55029c71f",
}
HISTORICAL_FFMPEG_RECIPE_SHA256 = {
    "8.0": "92084704a8022e84d759fbf193f6c2bc2f430a028b5531f15a907fd7f4844e4b",
}
REQUIRED_SCOPES = (
    "runtime",
    "build",
    "pyinstaller",
    "repair",
    "curl-arm64",
    "curl-x86-64",
)
SCOPE_INDEX = {scope: index for index, scope in enumerate(REQUIRED_SCOPES)}
CORE_LOCK_LINK = re.compile(
    r"^- \*\*Input lock:\*\* \[`([0-9a-f]{64})`\]"
    r"\((locks/([0-9]{4}\.[0-9]{2}\.[0-9]{2})\.json)\)$",
    re.MULTILINE,
)


class ComplianceError(ValueError):
    """Raised when immutable compliance evidence is malformed or inconsistent."""


def display_path(path: Path, *, root: Path = ROOT) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ComplianceError(f"JSON contains a duplicate key: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> object:
    raise ComplianceError(f"JSON contains a non-finite number: {value}")


def canonical_json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as error:
        raise ComplianceError("lock cannot be represented as canonical JSON") from error
    return (rendered + "\n").encode("utf-8")


def _stable_regular_bytes(path: Path, *, label: str, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ComplianceError(f"cannot safely open {label}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ComplianceError(f"{label} must be an independent regular file")
        if before.st_size > max_bytes:
            raise ComplianceError(f"{label} is unexpectedly large")
        chunks: list[bytes] = []
        bytes_read = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - bytes_read))
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
            if bytes_read > max_bytes:
                raise ComplianceError(f"{label} is unexpectedly large")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            stat.S_IFMT(before.st_mode),
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            stat.S_IFMT(after.st_mode),
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or bytes_read != before.st_size:
            raise ComplianceError(f"{label} changed while being read")
        return b"".join(chunks)
    except OSError as error:
        raise ComplianceError(f"cannot read {label}") from error
    finally:
        os.close(descriptor)


def _load_canonical_json(path: Path, *, label: str = "lock") -> tuple[object, bytes]:
    try:
        raw = _stable_regular_bytes(path, label=label, max_bytes=100_000_000)
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except ComplianceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ComplianceError(f"invalid {label} JSON") from error
    if raw != canonical_json_bytes(value):
        raise ComplianceError(f"{label} bytes are not canonical")
    return value, raw


def _require_calver(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not CALVER.fullmatch(value):
        raise ComplianceError(f"{label} must be an exact YYYY.MM.DD CalVer")
    try:
        datetime.strptime(value, "%Y.%m.%d")
    except ValueError as error:
        raise ComplianceError(f"{label} is not a real calendar date") from error
    return value


def _require_https_url(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComplianceError(f"{label} URL is missing")
    try:
        value.encode("ascii")
        parsed = urlsplit(value)
        port = parsed.port
    except (UnicodeEncodeError, ValueError) as error:
        raise ComplianceError(f"{label} URL is malformed") from error
    host = parsed.hostname
    if (
        parsed.scheme != "https"
        or not host
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host)
        or parsed.netloc != host
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.path.startswith("/")
        or parsed.path == "/"
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or any(character.isspace() or ord(character) < 0x20 for character in value)
    ):
        raise ComplianceError(
            f"{label} must be a canonical uncredentialed HTTPS URL without "
            "a port, query, or fragment"
        )
    if urlunsplit(("https", host, parsed.path, "", "")) != value:
        raise ComplianceError(f"{label} URL is not canonical")
    for match in re.finditer("%", parsed.path):
        if not re.match(r"%[0-9A-F]{2}", parsed.path[match.start() :]):
            raise ComplianceError(f"{label} URL has non-canonical percent escaping")
    return value


def _normalize_package_name(name: object) -> str:
    if not isinstance(name, str) or not PACKAGE_NAME.fullmatch(name):
        raise ComplianceError("dependency name is invalid")
    return re.sub(r"[-_.]+", "-", name).lower()


def _require_exact_version(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not PACKAGE_VERSION.fullmatch(value):
        raise ComplianceError(f"dependency {name} has no canonical exact version")
    try:
        canonical = str(Version(value))
    except InvalidVersion as error:
        raise ComplianceError(
            f"dependency {name} has no canonical exact version"
        ) from error
    if canonical != value:
        raise ComplianceError(f"dependency {name} version is not canonical PEP 440")
    return value


def _artifact_sort_key(item: dict[str, object]) -> tuple[int, str, str]:
    scope = item["scope"]
    assert isinstance(scope, str)
    url = item["url"]
    digest = item["sha256"]
    assert isinstance(url, str) and isinstance(digest, str)
    return SCOPE_INDEX[scope], url, digest


def _require_immutable_core_artifact_url(value: object, *, version: str) -> str:
    url = _require_https_url(value, label="artifact")
    parsed = urlsplit(url)
    expected_path = f"{CORE_ARTIFACT_PREFIX}/fetchii-core_macos_{version}.tar.gz"
    if parsed.hostname != CORE_SOURCE_HOST or parsed.path != expected_path:
        raise ComplianceError(
            "core artifact URL must be the fixed immutable Fetchii version key"
        )
    return url


def load_validated_release_manifest(
    path: Path,
    *,
    expected_version: str,
    raw_lock: bytes,
) -> tuple[dict[str, object], bytes]:
    """Load the independent immutable claims used to validate a core record."""

    value, raw = _load_canonical_json(path, label="release manifest")
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "component",
        "version",
        "displayVersion",
        "artifactUrl",
        "artifactSha256",
        "inputLockSha256",
    }:
        raise ComplianceError("unexpected core release manifest fields")
    schema_version = value.get("schemaVersion")
    if (
        type(schema_version) is not int
        or schema_version != CORE_MANIFEST_SCHEMA_VERSION
        or value.get("component") != "fetchii-core"
    ):
        raise ComplianceError("unsupported core release manifest schema")
    version = _require_calver(
        value.get("version"), label="core release manifest version"
    )
    if version != expected_version:
        raise ComplianceError("core release manifest version does not match its path")
    display_version = value.get("displayVersion")
    if not isinstance(display_version, str) or not DISPLAY_VERSION.fullmatch(
        display_version
    ):
        raise ComplianceError(
            "core release manifest display version must be eight lowercase "
            "hex characters"
        )
    artifact_sha256 = value.get("artifactSha256")
    if not isinstance(artifact_sha256, str) or not SHA256.fullmatch(artifact_sha256):
        raise ComplianceError("core release manifest artifact SHA-256 is invalid")
    _require_immutable_core_artifact_url(
        value.get("artifactUrl"), version=expected_version
    )
    expected_lock_digest = hashlib.sha256(raw_lock).hexdigest()
    if value.get("inputLockSha256") != expected_lock_digest:
        raise ComplianceError("core release manifest input lock digest mismatch")
    return value, raw


def load_validated_lock(path: Path) -> tuple[dict[str, object], bytes]:
    value, raw = _load_canonical_json(path)
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "component",
        "version",
        "source",
        "toolchain",
        "dependencies",
    }:
        raise ComplianceError("unexpected core lock fields")
    schema_version = value.get("schemaVersion")
    if (
        type(schema_version) is not int
        or schema_version != 2
        or value.get("component") != "fetchii-core"
    ):
        raise ComplianceError("unsupported core lock schema")
    version = _require_calver(value.get("version"), label="core lock version")
    source = value.get("source")
    if not isinstance(source, dict) or set(source) != {
        "repository",
        "tag",
        "commit",
        "archiveUrl",
        "archiveSha256",
        "archiveSize",
    }:
        raise ComplianceError("core lock source schema is incomplete")
    if source.get("repository") != CORE_SOURCE_REPOSITORY:
        raise ComplianceError("core lock source repository is not canonical yt-dlp")
    if source.get("tag") != version:
        raise ComplianceError("core lock source tag does not match its version")
    commit = source.get("commit")
    digest = source.get("archiveSha256")
    if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        raise ComplianceError("core lock requires a full lowercase source commit")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise ComplianceError("core lock source archive SHA-256 is invalid")
    size = source.get("archiveSize")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or size > MAX_SOURCE_ARCHIVE_BYTES
    ):
        raise ComplianceError("core lock source archive size is invalid")
    source_url = _require_https_url(source.get("archiveUrl"), label="source archive")
    expected_source_path = f"{CORE_SOURCE_PREFIX}/{version}/{commit}/{digest}.tar.gz"
    parsed_source = urlsplit(source_url)
    if (
        parsed_source.hostname != CORE_SOURCE_HOST
        or parsed_source.path != expected_source_path
    ):
        raise ComplianceError(
            "core lock source URL is not bound to version, commit, and digest"
        )

    toolchain = value.get("toolchain")
    if not isinstance(toolchain, dict) or set(toolchain) != {
        "pythonImplementation",
        "pythonVersion",
        "pipVersion",
        "targetPlatform",
        "targetArchitecture",
    }:
        raise ComplianceError("core lock toolchain schema is incomplete")
    if toolchain.get("pythonImplementation") != "CPython":
        raise ComplianceError("core lock toolchain must identify CPython")
    python_version = toolchain.get("pythonVersion")
    if not isinstance(python_version, str) or not PYTHON_VERSION.fullmatch(
        python_version
    ):
        raise ComplianceError("core lock Python version is not exact")
    if toolchain.get("targetPlatform") != "macos":
        raise ComplianceError("core lock target platform must be macos")
    if toolchain.get("targetArchitecture") != "universal2":
        raise ComplianceError("core lock target architecture must be universal2")
    _require_exact_version(toolchain.get("pipVersion"), name="pip")

    dependencies = value.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise ComplianceError("core lock dependencies are empty")
    previous_name = ""
    observed_scopes: set[str] = set()
    mutagen_runtime = False
    filenames: dict[str, dict[str, str]] = {scope: {} for scope in REQUIRED_SCOPES}
    for dependency in dependencies:
        if not isinstance(dependency, dict) or set(dependency) != {
            "name",
            "version",
            "artifacts",
        }:
            raise ComplianceError("core lock dependency schema is incomplete")
        name = dependency.get("name")
        canonical_name = _normalize_package_name(name)
        if name != canonical_name or canonical_name <= previous_name:
            raise ComplianceError(
                "core lock dependency names are not canonical and sorted"
            )
        previous_name = canonical_name
        _require_exact_version(dependency.get("version"), name=canonical_name)
        artifacts = dependency.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise ComplianceError(
                f"core lock dependency {canonical_name} has no artifact"
            )
        dependency_scopes: set[str] = set()
        for artifact in artifacts:
            if not isinstance(artifact, dict) or set(artifact) != {
                "scope",
                "url",
                "sha256",
            }:
                raise ComplianceError(
                    f"core lock dependency {canonical_name} artifact is incomplete"
                )
            scope = artifact.get("scope")
            if not isinstance(scope, str) or scope not in SCOPE_INDEX:
                raise ComplianceError(
                    f"core lock dependency {canonical_name} has an unexpected scope"
                )
            if scope in dependency_scopes:
                raise ComplianceError(
                    f"core lock dependency {canonical_name} repeats scope {scope}"
                )
            dependency_scopes.add(scope)
            url = _require_https_url(
                artifact.get("url"), label=f"dependency {canonical_name}"
            )
            parsed = urlsplit(url)
            if parsed.hostname != DEPENDENCY_HOST or not parsed.path.startswith(
                "/packages/"
            ):
                raise ComplianceError(
                    f"dependency {canonical_name} is not a canonical PyPI artifact"
                )
            filename = unquote(parsed.path.rsplit("/", 1)[-1])
            if (
                not filename
                or filename in {".", ".."}
                or not SAFE_FILENAME.fullmatch(filename)
                or "/" in filename
                or "\\" in filename
            ):
                raise ComplianceError(
                    f"dependency {canonical_name} URL has no deterministic filename"
                )
            artifact_digest = artifact.get("sha256")
            if not isinstance(artifact_digest, str) or not SHA256.fullmatch(
                artifact_digest
            ):
                raise ComplianceError(
                    f"core lock dependency {canonical_name} SHA-256 is invalid"
                )
            owner = filenames[scope].get(filename)
            if owner is not None:
                raise ComplianceError(
                    f"core lock has a {scope} filename collision: {owner}, {canonical_name}"
                )
            filenames[scope][filename] = canonical_name
            observed_scopes.add(scope)
            if canonical_name == "mutagen" and scope == "runtime":
                mutagen_runtime = True
        if artifacts != sorted(artifacts, key=_artifact_sort_key):
            raise ComplianceError(
                f"core lock dependency {canonical_name} artifacts are not canonical"
            )
    if observed_scopes != set(REQUIRED_SCOPES):
        raise ComplianceError("core lock does not cover all six required scopes")
    if not mutagen_runtime:
        raise ComplianceError("core lock runtime scope does not contain mutagen")
    return value, raw


def validate_lock(path: Path, *, root: Path = ROOT) -> list[str]:
    try:
        load_validated_lock(path)
    except ComplianceError as error:
        return [f"{display_path(path, root=root)}: {error}"]
    return []


def dependency_rows(lock: dict[str, object]) -> list[str]:
    dependencies = lock["dependencies"]
    assert isinstance(dependencies, list)
    rows: list[str] = []
    for dependency in dependencies:
        assert isinstance(dependency, dict)
        artifacts = dependency["artifacts"]
        assert isinstance(artifacts, list)
        rendered_artifacts = "<br>".join(
            f"`{item['scope']}` [sha256:{item['sha256']}]({item['url']})"
            for item in artifacts
            if isinstance(item, dict)
        )
        rows.append(
            f"| `{dependency['name']}` | `{dependency['version']}` | "
            f"{rendered_artifacts} |"
        )
    return rows


def render_core_record(
    lock: dict[str, object],
    raw_lock: bytes,
    *,
    artifact_url: str,
    artifact_sha256: str,
    display_version: str,
) -> bytes:
    """Render the one canonical record byte sequence accepted by repository policy."""

    version = lock["version"]
    if not isinstance(version, str):  # Defensive: validated locks always satisfy this.
        raise ComplianceError("core lock version is missing")
    if not DISPLAY_VERSION.fullmatch(display_version):
        raise ComplianceError(
            "core display version must be eight lowercase hex characters"
        )
    if not SHA256.fullmatch(artifact_sha256):
        raise ComplianceError("core artifact SHA-256 is invalid")
    artifact_url = _require_immutable_core_artifact_url(artifact_url, version=version)
    lock_digest = hashlib.sha256(raw_lock).hexdigest()
    source = lock["source"]
    toolchain = lock["toolchain"]
    assert isinstance(source, dict) and isinstance(toolchain, dict)
    lines = [
        "<!-- generated by release_records.py; deterministic; do not edit -->",
        f"# fetchii-core {version} — corresponding-source record",
        "",
        f"- **Schema:** `{CORE_RECORD_SCHEMA}`",
        f"- **Display version:** `{display_version}`",
        (
            f"- **Artifact:** [immutable tarball]({artifact_url}) "
            f"(`sha256: {artifact_sha256}`)"
        ),
        f"- **Input lock:** [`{lock_digest}`](locks/{version}.json)",
        f"- **Source repository:** [{source['repository']}]({source['repository']})",
        f"- **yt-dlp tag:** `{source['tag']}`",
        (
            f"- **yt-dlp commit:** [`{source['commit']}`]"
            f"(https://github.com/yt-dlp/yt-dlp/commit/{source['commit']})"
        ),
        (
            f"- **Locked source object:** [archive]({source['archiveUrl']}) "
            f"(`sha256: {source['archiveSha256']}`, "
            f"`{source['archiveSize']}` bytes)"
        ),
        (
            "- **Toolchain:** "
            f"{toolchain['pythonImplementation']} {toolchain['pythonVersion']}, "
            f"pip {toolchain['pipVersion']}, "
            f"{toolchain['targetPlatform']} {toolchain['targetArchitecture']}."
        ),
        (
            "- **License:** the bundle includes `mutagen` under "
            "GPLv2-or-later; see `../GPLv2.txt`."
        ),
        (
            "- **Build recipe:** `python3 -m bundle.pyinstaller --onedir "
            "--target-architecture universal2`."
        ),
        "",
        (
            "Reproduction must use the locked source object and every "
            "dependency artifact below."
        ),
        (
            "Do not resolve a tag, `latest` URL, package range, or "
            "installed environment again."
        ),
        "",
        "## Locked dependencies",
        "",
        "| Name | Exact version | Source artifact(s) |",
        "|---|---:|---|",
        *dependency_rows(lock),
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _validate_core_record_bytes(
    path: Path,
    raw: bytes,
    *,
    artifact_url: str | None = None,
    artifact_sha256: str | None = None,
    display_version: str | None = None,
    manifest_path: Path | None = None,
    root: Path,
) -> list[str]:
    label = display_path(path, root=root)
    try:
        resolved_root = root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        resolved_path.relative_to(resolved_root)
    except (OSError, ValueError):
        return [f"{label}: record escapes repository"]
    try:
        versions_directory = (root / "fetchii-core" / "versions").resolve(strict=True)
    except OSError:
        return [f"{label}: core versions directory is missing"]
    if resolved_path.parent != versions_directory:
        return [f"{label}: record must use the top-level fixed version path"]
    if path.suffix != ".md":
        return [f"{label}: record filename is invalid"]
    version = path.stem
    try:
        _require_calver(version, label="record version")
    except ComplianceError as error:
        return [f"{label}: {error}"]
    expected_lock = path.parent / "locks" / f"{version}.json"
    try:
        lock, raw_lock = load_validated_lock(expected_lock)
    except ComplianceError as error:
        return [f"{label}: input lock is invalid: {error}"]
    if lock["version"] != version:
        return [f"{label}: record and input lock versions differ"]
    if manifest_path is not None:
        expected_manifest = path.parent / "manifests" / f"{version}.json"
        try:
            if manifest_path.resolve(strict=True) != expected_manifest.resolve(
                strict=True
            ):
                return [
                    f"{label}: release manifest does not use its fixed version path"
                ]
            manifest, _ = load_validated_release_manifest(
                manifest_path,
                expected_version=version,
                raw_lock=raw_lock,
            )
        except (OSError, ComplianceError) as error:
            return [f"{label}: release manifest is invalid: {error}"]
        artifact_url = manifest["artifactUrl"]
        artifact_sha256 = manifest["artifactSha256"]
        display_version = manifest["displayVersion"]
    if not all(
        isinstance(value, str)
        for value in (artifact_url, artifact_sha256, display_version)
    ):
        return [f"{label}: independent release claims are missing"]
    assert isinstance(artifact_url, str)
    assert isinstance(artifact_sha256, str)
    assert isinstance(display_version, str)
    try:
        expected = render_core_record(
            lock,
            raw_lock,
            artifact_url=artifact_url,
            artifact_sha256=artifact_sha256,
            display_version=display_version,
        )
    except ComplianceError as error:
        return [f"{label}: {error}"]
    if raw != expected:
        return [f"{label}: record bytes do not match the canonical lock-bound oracle"]
    return []


def validate_core_record(
    path: Path,
    *,
    artifact_url: str,
    artifact_sha256: str,
    display_version: str,
    root: Path = ROOT,
) -> list[str]:
    """Validate a record against independently supplied release-specific inputs."""

    label = display_path(path, root=root)
    try:
        raw = _stable_regular_bytes(path, label="record", max_bytes=10_000_000)
    except ComplianceError as error:
        return [f"{label}: {error}"]
    return _validate_core_record_bytes(
        path,
        raw,
        artifact_url=artifact_url,
        artifact_sha256=artifact_sha256,
        display_version=display_version,
        root=root,
    )


def validate_manifest_bound_core_record(path: Path, *, root: Path = ROOT) -> list[str]:
    """Validate a checked-in record only against its independent fixed manifest."""

    label = display_path(path, root=root)
    try:
        raw = _stable_regular_bytes(path, label="record", max_bytes=10_000_000)
    except ComplianceError as error:
        return [f"{label}: {error}"]
    return _validate_core_record_bytes(
        path,
        raw,
        manifest_path=path.parent / "manifests" / f"{path.stem}.json",
        root=root,
    )


def validate_release_manifest(path: Path, *, root: Path = ROOT) -> list[str]:
    label = display_path(path, root=root)
    try:
        manifests_directory = (
            root / "fetchii-core" / "versions" / "manifests"
        ).resolve(strict=True)
        resolved_path = path.resolve(strict=True)
    except OSError as error:
        return [f"{label}: cannot resolve release manifest: {error}"]
    if resolved_path.parent != manifests_directory or path.suffix != ".json":
        return [f"{label}: release manifest must use the fixed version path"]
    version = path.stem
    try:
        _require_calver(version, label="core release manifest version")
        _, raw_lock = load_validated_lock(
            root / "fetchii-core" / "versions" / "locks" / f"{version}.json"
        )
        load_validated_release_manifest(
            path,
            expected_version=version,
            raw_lock=raw_lock,
        )
    except ComplianceError as error:
        return [f"{label}: {error}"]
    return []


def local_link_errors() -> list[str]:
    errors = []
    for document in sorted(ROOT.rglob("*.md")):
        contents = document.read_text(encoding="utf-8")
        for raw in LINK.findall(contents):
            target = raw.strip().split(maxsplit=1)[0].strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or target.startswith("#"):
                continue
            path_text = unquote(parsed.path)
            if not path_text:
                continue
            destination = (document.parent / path_text).resolve()
            try:
                destination.relative_to(ROOT)
            except ValueError:
                errors.append(
                    f"{document.relative_to(ROOT)}: link escapes repository: {target}"
                )
                continue
            if not destination.exists():
                errors.append(
                    f"{document.relative_to(ROOT)}: dead local link: {target}"
                )
    return errors


ARIA2_EVIDENCE_KEYS = {
    "schemaVersion",
    "component",
    "releaseVersion",
    "upstreamVersion",
    "sourceRevision",
    "sourceOriginUrl",
    "sourceArchiveUrl",
    "sourceArchiveSha256",
    "artifactSha256",
    "artifactUrl",
    "recordSha256",
}


def aria2_release_urls(
    release_version: str, upstream_version: str
) -> tuple[str, str, str]:
    if not SEMVER.fullmatch(release_version):
        raise ComplianceError("aria2 release version must be an exact semantic version")
    if not SEMVER.fullmatch(upstream_version):
        raise ComplianceError(
            "aria2 upstream version must be an exact semantic version"
        )
    release_root = (
        f"https://github.com/{ARIA2_BUILDER_REPOSITORY}/"
        f"releases/download/aria2-v{release_version}"
    )
    return (
        "https://github.com/aria2/aria2/releases/download/"
        f"release-{upstream_version}/aria2-{upstream_version}.tar.xz",
        f"{release_root}/aria2.tar.xz",
        f"{release_root}/aria2c-signed.zip",
    )


def render_aria2_record(
    release_version: str,
    upstream_version: str,
    source_sha256: str,
    artifact_sha256: str,
) -> bytes:
    if not SHA256.fullmatch(source_sha256):
        raise ComplianceError("aria2 source SHA-256 is invalid")
    if not SHA256.fullmatch(artifact_sha256):
        raise ComplianceError("aria2 artifact SHA-256 is invalid")
    source_origin_url, source_archive_url, artifact_url = aria2_release_urls(
        release_version, upstream_version
    )
    lines = [
        "<!-- generated by release_records.py; deterministic; do not edit -->",
        f"# aria2 Builder release {release_version} — corresponding-source record",
        "",
        f"- **Schema:** `{ARIA2_RECORD_SCHEMA}`",
        f"- **Release version:** `{release_version}`",
        f"- **Upstream version:** `{upstream_version}`",
        (
            "- **Artifact:** [signed universal binary]"
            f"({artifact_url}) (`sha256: {artifact_sha256}`)"
        ),
        (
            "- **Locked source object:** [carried release source archive]"
            f"({source_archive_url}) (`sha256: {source_sha256}`)"
        ),
        (
            "- **Source origin:** [canonical upstream release archive]"
            f"({source_origin_url})"
        ),
        f"- **Source revision:** `release-{upstream_version}`",
        "- **License:** GPLv2; see `../GPLv2.txt`.",
        (
            "- **Configure:** `--without-libxml2 --without-libexpat "
            "--without-sqlite3 --without-libssh2 --without-libcares "
            "--without-libnettle --without-libgmp --without-libgcrypt "
            "--with-appletls`, once per architecture, then `lipo`."
        ),
        "",
        (
            "Reproduction must use the carried release source archive above "
            "and verify its SHA-256."
        ),
        (
            "The source-origin URL is provenance only; do not download it "
            "again for reproduction."
        ),
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _parse_aria2_v4_record(
    raw: bytes,
    *,
    expected_version: str | None = None,
) -> tuple[str, str, str, str]:
    try:
        contents = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ComplianceError("aria2 record is not UTF-8") from error
    lines = contents.splitlines()
    if len(lines) != 15 or not contents.endswith("\n") or "\r" in contents:
        raise ComplianceError("aria2 record is not the deterministic v4 rendering")
    title = re.fullmatch(
        r"# aria2 Builder release ((?:0|[1-9][0-9]*)\."
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)) — corresponding-source record",
        lines[1],
    )
    if title is None:
        raise ComplianceError("aria2 record title has no exact semantic version")
    release_version = title.group(1)
    if expected_version is not None and release_version != expected_version:
        raise ComplianceError("aria2 record and fixed-path versions differ")
    if lines[4] != f"- **Release version:** `{release_version}`":
        raise ComplianceError("aria2 release version field is inconsistent")
    upstream = re.fullmatch(
        r"- \*\*Upstream version:\*\* `((?:0|[1-9][0-9]*)\."
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))`",
        lines[5],
    )
    if upstream is None:
        raise ComplianceError("aria2 upstream version is not canonical")
    upstream_version = upstream.group(1)
    source_origin_url, source_archive_url, artifact_url = aria2_release_urls(
        release_version, upstream_version
    )
    artifact = re.fullmatch(
        re.escape(
            "- **Artifact:** [signed universal binary]" f"({artifact_url}) (`sha256: "
        )
        + r"([0-9a-f]{64})"
        + re.escape("`)"),
        lines[6],
    )
    source = re.fullmatch(
        re.escape(
            "- **Locked source object:** [carried release source archive]"
            f"({source_archive_url}) (`sha256: "
        )
        + r"([0-9a-f]{64})"
        + re.escape("`)"),
        lines[7],
    )
    if artifact is None or source is None:
        raise ComplianceError("aria2 record digest or release URL is invalid")
    artifact_sha256 = artifact.group(1)
    source_sha256 = source.group(1)
    if raw != render_aria2_record(
        release_version, upstream_version, source_sha256, artifact_sha256
    ):
        raise ComplianceError("aria2 record is not the deterministic v4 rendering")
    if contents.count(source_origin_url) != 1:
        raise ComplianceError("aria2 source-origin URL role is not unique")
    if contents.count(source_archive_url) != 1:
        raise ComplianceError("aria2 carried-source URL role is not unique")
    if contents.count(artifact_url) != 1:
        raise ComplianceError("aria2 artifact URL role is not unique")
    return release_version, upstream_version, source_sha256, artifact_sha256


def validate_aria2_v4_record(
    record: Path,
    evidence_path: Path,
    *,
    root: Path = ROOT,
) -> list[str]:
    label = display_path(record, root=root)
    try:
        raw_record = _stable_regular_bytes(
            record,
            label="aria2 record",
            max_bytes=MAX_RECORD_BYTES,
        )
        release_version, upstream_version, source_sha256, artifact_sha256 = (
            _parse_aria2_v4_record(
                raw_record,
                expected_version=record.stem,
            )
        )
        value, _raw_evidence = _load_canonical_json(
            evidence_path,
            label="aria2 release evidence",
        )
        if not isinstance(value, dict) or set(value) != ARIA2_EVIDENCE_KEYS:
            raise ComplianceError("aria2 release evidence schema is incomplete")
        if type(value.get("schemaVersion")) is not int or value["schemaVersion"] != 4:
            raise ComplianceError("unsupported aria2 release evidence schema")
        if (
            value.get("component") != "aria2"
            or value.get("releaseVersion") != release_version
            or value.get("upstreamVersion") != upstream_version
        ):
            raise ComplianceError("aria2 release evidence identity is inconsistent")
        source_origin_url, source_archive_url, artifact_url = aria2_release_urls(
            release_version, upstream_version
        )
        expected = {
            "schemaVersion": 4,
            "component": "aria2",
            "releaseVersion": release_version,
            "upstreamVersion": upstream_version,
            "sourceRevision": f"release-{upstream_version}",
            "sourceOriginUrl": source_origin_url,
            "sourceArchiveUrl": source_archive_url,
            "sourceArchiveSha256": source_sha256,
            "artifactSha256": artifact_sha256,
            "artifactUrl": artifact_url,
            "recordSha256": hashlib.sha256(raw_record).hexdigest(),
        }
        if value != expected:
            raise ComplianceError(
                "aria2 release evidence does not bind the exact record"
            )
    except ComplianceError as error:
        return [f"{label}: {error}"]
    return []


def validate_historical_recipe(
    record: Path,
    *,
    component: str,
    expected_digests: dict[str, str],
    root: Path = ROOT,
) -> list[str]:
    label = display_path(record, root=root)
    expected = expected_digests.get(record.stem)
    if expected is None:
        schema = {"aria2": "v4", "fetchii-core": "v3", "ffmpeg": "v1"}[component]
        return [f"{label}: new {component} records must use the locked {schema} schema"]
    try:
        raw = _stable_regular_bytes(
            record,
            label=f"historical {component} recipe",
            max_bytes=MAX_RECORD_BYTES,
        )
    except ComplianceError as error:
        return [f"{label}: {error}"]
    if hashlib.sha256(raw).hexdigest() != expected:
        return [f"{label}: historical {component} recipe bytes changed"]
    return []


def historical_repository_errors(*, root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    for component, digests in (
        ("aria2", HISTORICAL_ARIA2_RECIPE_SHA256),
        ("fetchii-core", HISTORICAL_CORE_RECIPE_SHA256),
        ("ffmpeg", HISTORICAL_FFMPEG_RECIPE_SHA256),
    ):
        for version in sorted(digests):
            record = root / component / "versions" / f"{version}.md"
            errors.extend(
                validate_historical_recipe(
                    record,
                    component=component,
                    expected_digests=digests,
                    root=root,
                )
            )
    return errors


def record_status(component: str, contents: str) -> str:
    if "<SHA256" in contents or "auto-filled" in contents:
        return "legacy recipe; digest not recorded"
    if component == "fetchii-core" and (
        f"`{CORE_RECORD_SCHEMA}`" in contents
        and CORE_LOCK_LINK.search(contents)
        and re.search(r"yt-dlp tag:\*\* `[0-9]{4}\.[0-9]{2}\.[0-9]{2}`", contents)
        and re.search(r"yt-dlp commit:\*\* \[`[0-9a-f]{40}`\]", contents)
        and "## Locked dependencies" in contents
    ):
        return "locked v3 record"
    if component == "aria2":
        try:
            _parse_aria2_v4_record(contents.encode("utf-8"))
        except ComplianceError:
            pass
        else:
            return "locked v4 record"
    if component == "aria2" and (
        "`aria2-record/v2`" in contents
        and len(re.findall(r"sha256: ([0-9a-f]{64})", contents)) >= 2
        and re.search(
            r"Source revision:\*\* `release-[0-9]+\.[0-9]+\.[0-9]+`",
            contents,
        )
    ):
        return "locked v2 record"
    return "legacy/manual record"


def _version_tree_errors(
    directory: Path,
    *,
    component: str,
    root: Path,
) -> list[str]:
    """Reject paths that the deterministic top-level index must never consume."""

    errors: list[str] = []
    try:
        directory_info = directory.lstat()
    except FileNotFoundError:
        return [f"{display_path(directory, root=root)}: versions directory is missing"]
    except OSError as error:
        return [f"{display_path(directory, root=root)}: cannot inspect: {error}"]
    if not stat.S_ISDIR(directory_info.st_mode) or stat.S_ISLNK(directory_info.st_mode):
        return [
            f"{display_path(directory, root=root)}: "
            "versions path must be a real directory"
        ]
    try:
        entries = sorted(directory.iterdir())
    except OSError as error:
        return [f"{display_path(directory, root=root)}: cannot enumerate: {error}"]
    for entry in entries:
        try:
            info = entry.lstat()
        except OSError as error:
            errors.append(f"{display_path(entry, root=root)}: cannot inspect: {error}")
            continue
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            allowed_directories = {
                "fetchii-core": {"locks", "manifests"},
                "aria2": {"evidence"},
                "ffmpeg": {"locks", "evidence"},
            }
            if entry.name in allowed_directories.get(component, set()):
                continue
            errors.append(
                f"{display_path(entry, root=root)}: nested version paths are forbidden"
            )
            continue
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_nlink != 1
            or entry.suffix != ".md"
        ):
            errors.append(
                f"{display_path(entry, root=root)}: "
                "versions directory contains an unexpected path"
            )
    return errors


def ffmpeg_record_errors(*, root: Path = ROOT) -> list[str]:
    """Validate every locked FFmpeg bundle and its exact sidecar paths."""
    spec = importlib.util.spec_from_file_location(
        "fetchii_ffmpeg_records", Path(__file__).with_name("ffmpeg_records.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    errors: list[str] = []
    directory = root / "ffmpeg" / "versions"
    try:
        info = directory.lstat()
    except OSError as error:
        return [f"{display_path(directory, root=root)}: cannot inspect: {error}"]
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        return [f"{display_path(directory, root=root)}: versions path must be a real directory"]
    for name in ("locks", "evidence"):
        sidecars = directory / name
        try:
            info = sidecars.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            return [f"{display_path(sidecars, root=root)}: cannot inspect: {error}"]
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            return [f"{display_path(sidecars, root=root)}: sidecar path must be a real directory"]
    versions: set[str] = set()
    for record in sorted(directory.glob("*.md")):
        if record.name == "TEMPLATE.md":
            continue
        try:
            raw = _stable_regular_bytes(
                record, label="FFmpeg record", max_bytes=MAX_RECORD_BYTES
            )
            if not raw.startswith(b"<!-- fetchii-ffmpeg-record/v1 -->\n"):
                errors.extend(validate_historical_recipe(
                    record, component="ffmpeg",
                    expected_digests=HISTORICAL_FFMPEG_RECIPE_SHA256, root=root,
                ))
                continue
            if not SEMVER.fullmatch(record.stem):
                raise ComplianceError("FFmpeg record filename must be exact x.y.z")
            versions.add(record.stem)
            lock, lock_raw = _load_canonical_json(
                directory / "locks" / f"{record.stem}.json", label="FFmpeg lock"
            )
            evidence, _ = _load_canonical_json(
                directory / "evidence" / f"{record.stem}.json", label="FFmpeg evidence"
            )
            module.validate_bundle(raw, lock, lock_raw, evidence, record.stem)
        except (ComplianceError, ValueError) as error:
            errors.append(f"{display_path(record, root=root)}: {error}")
    for name in ("locks", "evidence"):
        sidecars = directory / name
        try:
            info = sidecars.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            errors.append(f"{display_path(sidecars, root=root)}: cannot inspect: {error}")
            continue
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            errors.append(f"{display_path(sidecars, root=root)}: sidecar path must be a real directory")
            continue
        for path in sorted(sidecars.iterdir()):
            try:
                entry = path.lstat()
            except OSError as error:
                errors.append(f"{display_path(path, root=root)}: cannot inspect: {error}")
                continue
            if (not stat.S_ISREG(entry.st_mode) or stat.S_ISLNK(entry.st_mode)
                    or entry.st_nlink != 1 or path.suffix != ".json"
                    or not SEMVER.fullmatch(path.stem)):
                errors.append(f"{display_path(path, root=root)}: unexpected FFmpeg sidecar path")
            elif path.stem not in versions:
                errors.append(f"{display_path(path, root=root)}: FFmpeg sidecar has no locked v1 record")
    return errors


def generated_record_errors(*, root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    for component in ("aria2", "fetchii-core", "ffmpeg"):
        errors.extend(
            _version_tree_errors(
                root / component / "versions", component=component, root=root
            )
        )

    errors.extend(ffmpeg_record_errors(root=root))

    aria_directory = root / "aria2" / "versions"
    locked_aria_versions: set[str] = set()
    for record in sorted(aria_directory.glob("*.md")):
        contents = record.read_text(encoding="utf-8")
        if record_status("aria2", contents) == "locked v4 record":
            locked_aria_versions.add(record.stem)
            errors.extend(
                validate_aria2_v4_record(
                    record,
                    aria_directory / "evidence" / f"{record.stem}.json",
                    root=root,
                )
            )
        else:
            errors.extend(
                validate_historical_recipe(
                    record,
                    component="aria2",
                    expected_digests=HISTORICAL_ARIA2_RECIPE_SHA256,
                    root=root,
                )
            )

    aria_evidence_directory = aria_directory / "evidence"
    try:
        aria_evidence_info = aria_evidence_directory.lstat()
    except FileNotFoundError:
        aria_evidence_info = None
    except OSError as error:
        errors.append(
            f"{display_path(aria_evidence_directory, root=root)}: cannot inspect: {error}"
        )
        aria_evidence_info = None
    if aria_evidence_info is not None:
        if not stat.S_ISDIR(aria_evidence_info.st_mode) or stat.S_ISLNK(
            aria_evidence_info.st_mode
        ):
            errors.append(
                f"{display_path(aria_evidence_directory, root=root)}: "
                "evidence path must be a real directory"
            )
        else:
            for evidence in sorted(aria_evidence_directory.iterdir()):
                try:
                    evidence_info = evidence.lstat()
                except OSError as error:
                    errors.append(
                        f"{display_path(evidence, root=root)}: cannot inspect: {error}"
                    )
                    continue
                if (
                    evidence.suffix != ".json"
                    or not stat.S_ISREG(evidence_info.st_mode)
                    or stat.S_ISLNK(evidence_info.st_mode)
                    or evidence_info.st_nlink != 1
                ):
                    errors.append(
                        f"{display_path(evidence, root=root)}: "
                        "evidence directory contains an unexpected path"
                    )
                    continue
                if evidence.stem not in locked_aria_versions:
                    errors.append(
                        f"{display_path(evidence, root=root)}: "
                        "aria2 evidence has no locked v4 record"
                    )

    core_directory = root / "fetchii-core" / "versions"
    locked_core_versions: set[str] = set()
    for record in sorted(core_directory.glob("*.md")):
        if record.name == "TEMPLATE.md":
            continue
        contents = record.read_text(encoding="utf-8")
        if record_status("fetchii-core", contents) == "locked v3 record":
            locked_core_versions.add(record.stem)
            errors.extend(validate_manifest_bound_core_record(record, root=root))
        else:
            errors.extend(
                validate_historical_recipe(
                    record,
                    component="fetchii-core",
                    expected_digests=HISTORICAL_CORE_RECIPE_SHA256,
                    root=root,
                )
            )
    lock_directory = core_directory / "locks"
    try:
        lock_directory_info = lock_directory.lstat()
    except FileNotFoundError:
        lock_directory_info = None
    except OSError as error:
        errors.append(f"{lock_directory.relative_to(root)}: cannot inspect: {error}")
        lock_directory_info = None
    if lock_directory_info is not None:
        if not stat.S_ISDIR(lock_directory_info.st_mode) or stat.S_ISLNK(
            lock_directory_info.st_mode
        ):
            errors.append(
                f"{lock_directory.relative_to(root)}: "
                "locks path must be a real directory"
            )
            return errors
        for lock in sorted(lock_directory.iterdir()):
            try:
                lock_info = lock.lstat()
            except OSError as error:
                errors.append(f"{lock.relative_to(root)}: cannot inspect: {error}")
                continue
            if (
                lock.suffix != ".json"
                or not stat.S_ISREG(lock_info.st_mode)
                or stat.S_ISLNK(lock_info.st_mode)
                or lock_info.st_nlink != 1
            ):
                errors.append(
                    f"{lock.relative_to(root)}: "
                    "locks directory contains an unexpected path"
                )
                continue
            errors.extend(validate_lock(lock, root=root))
            if lock.stem not in locked_core_versions:
                errors.append(
                    f"{lock.relative_to(root)}: input lock has no fixed-path record"
                )

    manifest_directory = core_directory / "manifests"
    try:
        manifest_directory_info = manifest_directory.lstat()
    except FileNotFoundError:
        manifest_directory_info = None
    except OSError as error:
        errors.append(
            f"{manifest_directory.relative_to(root)}: cannot inspect: {error}"
        )
        manifest_directory_info = None
    if manifest_directory_info is not None:
        if not stat.S_ISDIR(manifest_directory_info.st_mode) or stat.S_ISLNK(
            manifest_directory_info.st_mode
        ):
            errors.append(
                f"{manifest_directory.relative_to(root)}: "
                "manifests path must be a real directory"
            )
            return errors
        for manifest in sorted(manifest_directory.iterdir()):
            try:
                manifest_info = manifest.lstat()
            except OSError as error:
                errors.append(f"{manifest.relative_to(root)}: cannot inspect: {error}")
                continue
            if (
                manifest.suffix != ".json"
                or not stat.S_ISREG(manifest_info.st_mode)
                or stat.S_ISLNK(manifest_info.st_mode)
                or manifest_info.st_nlink != 1
            ):
                errors.append(
                    f"{manifest.relative_to(root)}: "
                    "manifests directory contains an unexpected path"
                )
                continue
            errors.extend(validate_release_manifest(manifest, root=root))
            if manifest.stem not in locked_core_versions:
                errors.append(
                    f"{manifest.relative_to(root)}: "
                    "release manifest has no fixed-path record"
                )
    return errors


def _is_append_only_record_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if len(parts) == 3:
        component, versions, filename = parts
        return (
            versions == "versions"
            and filename.endswith(".md")
            and filename != "TEMPLATE.md"
            and component in {"aria2", "fetchii-core", "ffmpeg"}
        )
    if len(parts) == 4:
        component, versions, sidecar, filename = parts
        return (
            versions == "versions"
            and filename.endswith(".json")
            and (
                (component == "fetchii-core" and sidecar in {"locks", "manifests"})
                or (component == "aria2" and sidecar == "evidence")
                or (component == "ffmpeg" and sidecar in {"locks", "evidence"})
            )
        )
    return False


def _run_git(root: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise ComplianceError(f"cannot execute local git: {error}") from error


def append_only_history_errors(base_commit: str, *, root: Path = ROOT) -> list[str]:
    """Compare protected current bytes with their immutable PR-base blobs."""

    if not isinstance(base_commit, str) or not COMMIT.fullmatch(base_commit):
        return ["append-only base must be a full lowercase 40-character commit"]
    try:
        resolved_root = root.resolve(strict=True)
        top_level = _run_git(resolved_root, "rev-parse", "--show-toplevel")
    except (OSError, ComplianceError) as error:
        return [f"append-only history cannot inspect repository: {error}"]
    if top_level.returncode != 0:
        return ["append-only history requires a readable local git worktree"]
    try:
        reported_root = Path(top_level.stdout.decode("utf-8").strip()).resolve(
            strict=True
        )
    except (UnicodeDecodeError, OSError):
        return ["append-only history received an invalid git worktree root"]
    if reported_root != resolved_root:
        return ["append-only history root is not the git worktree root"]

    shallow = _run_git(resolved_root, "rev-parse", "--is-shallow-repository")
    if shallow.returncode != 0 or shallow.stdout.strip() != b"false":
        return ["append-only history requires a complete non-shallow checkout"]

    base_exists = _run_git(resolved_root, "cat-file", "-e", f"{base_commit}^{{commit}}")
    if base_exists.returncode != 0:
        return ["append-only base commit is unavailable in local history"]
    ancestor = _run_git(
        resolved_root, "merge-base", "--is-ancestor", base_commit, "HEAD"
    )
    if ancestor.returncode != 0:
        return ["append-only base commit is not an ancestor of HEAD"]

    tree = _run_git(
        resolved_root,
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        base_commit,
        "--",
        "aria2/versions",
        "fetchii-core/versions",
        "ffmpeg/versions",
    )
    if tree.returncode != 0:
        return ["append-only base tree cannot be enumerated"]

    errors: list[str] = []
    for raw_entry in tree.stdout.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, object_type, object_id = metadata.split(b" ", 2)
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return ["append-only base tree contains an unreadable entry"]
        if not _is_append_only_record_path(path):
            continue
        if (
            object_type != b"blob"
            or mode not in {b"100644", b"100755"}
            or not re.fullmatch(rb"[0-9a-f]{40}", object_id)
        ):
            errors.append(f"{path}: protected base entry is not a regular blob")
            continue
        base_blob = _run_git(
            resolved_root, "cat-file", "blob", object_id.decode("ascii")
        )
        if base_blob.returncode != 0:
            errors.append(f"{path}: protected base blob is unavailable")
            continue
        current_path = resolved_root.joinpath(*PurePosixPath(path).parts)
        try:
            current = _stable_regular_bytes(
                current_path,
                label=f"append-only path {path}",
                max_bytes=100_000_000,
            )
        except ComplianceError:
            errors.append(f"{path}: existing protected path was deleted or replaced")
            continue
        if current != base_blob.stdout:
            errors.append(f"{path}: existing protected bytes were modified")
    return errors


def workflow_policy_errors(*, root: Path = ROOT) -> list[str]:
    path = root / POLICY_WORKFLOW
    label = display_path(path, root=root)
    try:
        contents = _stable_regular_bytes(
            path, label="workflow policy", max_bytes=1_000_000
        ).decode("utf-8")
    except ComplianceError as error:
        return [f"{label}: {error}"]
    except UnicodeDecodeError as error:
        return [f"{label}: invalid UTF-8: {error}"]

    errors: list[str] = []
    if not re.search(r"(?m)^permissions:\n  contents: read\n\njobs:", contents):
        errors.append(f"{label}: workflow permissions must remain read-only")
    runtime_pattern = re.compile(
        r"(?m)^  offline-policy:\n"
        r"    runs-on: ubuntu-24\.04\n"
        r"    timeout-minutes: 10\n"
        r"    steps:$"
    )
    if not runtime_pattern.search(contents):
        errors.append(f"{label}: offline policy timeout must remain exactly 10 minutes")
    checkout_pattern = re.compile(
        r"(?m)^      - name: Checkout immutable record tree\n"
        r"        uses: actions/checkout@[0-9a-f]{40}(?: #[^\n]*)?\n"
        r"        with:\n"
        r"          persist-credentials: false\n"
        r"          fetch-depth: 0$"
    )
    if not checkout_pattern.search(contents):
        errors.append(f"{label}: checkout must fetch PR base history")
    unittest_pattern = re.compile(
        r"(?m)^      - name: Run complete compliance policy unit suite\n"
        r"        run: python3 -m unittest discover -s tests -v$"
    )
    if not unittest_pattern.search(contents):
        errors.append(f"{label}: full compliance unittest gate is missing")
    append_only_pattern = re.compile(
        r"(?m)^      - name: Enforce append-only compliance history\n"
        r"        if: github\.event_name == 'pull_request'\n"
        r"        env:\n"
        r"          FETCHII_POLICY_BASE: "
        r"\$\{\{ github\.event\.pull_request\.base\.sha \}\}\n"
        r"        run: python3 scripts/check_compliance\.py --append-only-base "
        r"\"\$FETCHII_POLICY_BASE\"$"
    )
    if "on:\n  pull_request:\n" not in contents or not append_only_pattern.search(
        contents
    ):
        errors.append(f"{label}: append-only PR-base gate is incomplete")
    for action in re.findall(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)", contents):
        _, separator, revision = action.rpartition("@")
        if not separator or not re.fullmatch(r"[0-9a-f]{40}", revision):
            errors.append(f"{label}: action is not pinned to a full commit: {action}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--append-only-base")
    args = parser.parse_args(argv)
    errors = []
    index = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate_index.py"), "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if index.returncode:
        errors.append((index.stderr or index.stdout).strip())
    errors.extend(local_link_errors())
    errors.extend(historical_repository_errors())
    errors.extend(generated_record_errors())
    errors.extend(workflow_policy_errors())
    if args.append_only_base is not None:
        errors.extend(append_only_history_errors(args.append_only_base))
    setup = (ROOT / "SETUP.md").read_text(encoding="utf-8")
    for forbidden in (
        'curl -fsSL "$SRC_URL"',
        "pip freeze",
        "after the binary is built",
        "digest-suffixed filenames",
    ):
        if forbidden in setup:
            errors.append(f"SETUP.md: obsolete reproduction instruction: {forbidden}")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "[`fetchii-releases.md`](fetchii-releases.md)" not in readme:
        errors.append("README.md: deterministic aggregate index link is missing")
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("OSS compliance policy checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
