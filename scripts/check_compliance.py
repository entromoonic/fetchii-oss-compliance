#!/usr/bin/env python3
"""Offline policy checks for compliance records, locks, docs, and local links."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

try:
    from packaging.version import InvalidVersion, Version
except ImportError:  # pragma: no cover - pip vendors packaging on CI runners.
    from pip._vendor.packaging.version import InvalidVersion, Version


ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
CALVER = re.compile(r"^[0-9]{4}\.[0-9]{2}\.[0-9]{2}$")
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
CORE_MANIFEST_SCHEMA_VERSION = 1
CORE_SOURCE_REPOSITORY = "https://github.com/yt-dlp/yt-dlp.git"
CORE_SOURCE_HOST = "downloads.beamdrop.entromoonic.com"
CORE_SOURCE_PREFIX = "/fetchii-core/sources"
CORE_ARTIFACT_PREFIX = "/fetchii-core"
DEPENDENCY_HOST = "files.pythonhosted.org"
MAX_SOURCE_ARCHIVE_BYTES = 1_000_000_000
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


def _load_canonical_json(
    path: Path, *, label: str = "lock"
) -> tuple[object, bytes]:
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
    if (
        value.get("schemaVersion") != CORE_MANIFEST_SCHEMA_VERSION
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
    if not isinstance(artifact_sha256, str) or not SHA256.fullmatch(
        artifact_sha256
    ):
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
    if value.get("schemaVersion") != 2 or value.get("component") != "fetchii-core":
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
    if parsed_source.hostname != CORE_SOURCE_HOST or parsed_source.path != expected_source_path:
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
            raise ComplianceError("core lock dependency names are not canonical and sorted")
        previous_name = canonical_name
        _require_exact_version(dependency.get("version"), name=canonical_name)
        artifacts = dependency.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise ComplianceError(f"core lock dependency {canonical_name} has no artifact")
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
    artifact_url = _require_immutable_core_artifact_url(
        artifact_url, version=version
    )
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


def validate_manifest_bound_core_record(
    path: Path, *, root: Path = ROOT
) -> list[str]:
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
                errors.append(f"{document.relative_to(ROOT)}: dead local link: {target}")
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
            if component == "fetchii-core" and entry.name in {
                "locks",
                "manifests",
            }:
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


def generated_record_errors(*, root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    for component in ("aria2", "fetchii-core", "ffmpeg"):
        errors.extend(
            _version_tree_errors(
                root / component / "versions", component=component, root=root
            )
        )

    aria_directory = root / "aria2" / "versions"
    for record in sorted(aria_directory.glob("*.md")):
        contents = record.read_text(encoding="utf-8")
        if (
            "`aria2-record/v2`" not in contents
            and "generated by release_records.py" not in contents
        ):
            continue
        if record_status("aria2", contents) != "locked v2 record":
            errors.append(
                f"{record.relative_to(root)}: v2 record evidence is incomplete"
            )

    core_directory = root / "fetchii-core" / "versions"
    core_versions: set[str] = set()
    for record in sorted(core_directory.glob("*.md")):
        if record.name == "TEMPLATE.md":
            continue
        errors.extend(validate_manifest_bound_core_record(record, root=root))
        core_versions.add(record.stem)
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
            if lock.stem not in core_versions:
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
            if manifest.stem not in core_versions:
                errors.append(
                    f"{manifest.relative_to(root)}: "
                    "release manifest has no fixed-path record"
                )
    return errors


def main() -> int:
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
    errors.extend(generated_record_errors())
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
