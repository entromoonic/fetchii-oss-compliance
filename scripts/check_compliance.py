#!/usr/bin/env python3
"""Offline policy checks for compliance records, docs, and local links."""

from __future__ import annotations

import json
import hashlib
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
CALVER = re.compile(r"^[0-9]{4}\.[0-9]{2}\.[0-9]{2}$")
PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")
PACKAGE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]*$")
REQUIRED_SCOPES = frozenset(("runtime", "build", "curl-arm64", "curl-x86-64"))
CORE_LOCK_LINK = re.compile(
    r"Input lock:\*\* \[`([0-9a-f]{64})`\]\(([^)]+\.json)\)"
)


def display_path(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


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


def validate_lock(path: Path) -> list[str]:
    errors = []
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return [f"{display_path(path)}: invalid lock JSON"]
    if not isinstance(value, dict):
        return [f"{display_path(path)}: lock is not an object"]
    if set(value) != {"schemaVersion", "component", "version", "source", "dependencies"}:
        return [f"{display_path(path)}: unexpected core lock fields"]
    source = value.get("source")
    dependencies = value.get("dependencies")
    if (
        value.get("schemaVersion") != 1
        or value.get("component") != "fetchii-core"
        or not CALVER.fullmatch(str(value.get("version", "")))
        or not isinstance(source, dict)
        or set(source) != {"repository", "commit", "archiveUrl", "archiveSha256"}
        or source.get("repository") != "https://github.com/yt-dlp/yt-dlp.git"
        or not COMMIT.fullmatch(str(source.get("commit", "")))
        or not SHA256.fullmatch(str(source.get("archiveSha256", "")))
        or not isinstance(source.get("archiveUrl"), str)
        or not source["archiveUrl"].startswith("https://")
        or not isinstance(dependencies, list)
        or not dependencies
    ):
        errors.append(f"{display_path(path)}: incomplete core lock schema")
        return errors
    names = set()
    previous_name = ""
    observed_scopes = set()
    mutagen_runtime = False
    for dependency in dependencies:
        if not isinstance(dependency, dict) or set(dependency) != {
            "name",
            "version",
            "artifacts",
        }:
            errors.append(f"{display_path(path)}: malformed dependency")
            continue
        name = dependency.get("name")
        version = dependency.get("version")
        artifacts = dependency.get("artifacts")
        if (
            not isinstance(name, str)
            or not PACKAGE_NAME.fullmatch(name)
            or name <= previous_name
            or not isinstance(version, str)
            or not PACKAGE_VERSION.fullmatch(version)
            or any(marker in version for marker in ("*", "<", ">", "=", "~", ","))
            or not isinstance(artifacts, list)
            or not artifacts
        ):
            errors.append(
                f"{display_path(path)}: dependency is floating or incomplete"
            )
        else:
            names.add(name)
            previous_name = name
        for artifact in artifacts if isinstance(artifacts, list) else []:
            if (
                not isinstance(artifact, dict)
                or set(artifact) != {"scope", "url", "sha256"}
                or artifact.get("scope") not in REQUIRED_SCOPES
                or not isinstance(artifact.get("url"), str)
                or not artifact["url"].startswith("https://")
                or not SHA256.fullmatch(str(artifact.get("sha256", "")))
            ):
                errors.append(
                    f"{display_path(path)}: dependency artifact lacks SHA-256"
                )
                continue
            observed_scopes.add(artifact["scope"])
            if name == "mutagen" and artifact["scope"] == "runtime":
                mutagen_runtime = True
    if observed_scopes != REQUIRED_SCOPES:
        errors.append(f"{display_path(path)}: lock does not cover required scopes")
    if "mutagen" not in names or not mutagen_runtime:
        errors.append(f"{display_path(path)}: runtime scope does not contain mutagen")
    canonical = (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if path.read_bytes() != canonical:
        errors.append(f"{display_path(path)}: lock bytes are not canonical")
    return errors


def generated_record_errors() -> list[str]:
    errors = []
    for component, schema in (
        ("aria2", "`aria2-record/v2`"),
        ("fetchii-core", "`fetchii-core-record/v2`"),
    ):
        directory = ROOT / component / "versions"
        for record in sorted(directory.glob("*.md")):
            if record.name == "TEMPLATE.md":
                continue
            contents = record.read_text(encoding="utf-8")
            claims_generated = "generated by release_records.py" in contents
            if schema not in contents and not claims_generated:
                continue
            from_status = record_status(component, contents)
            if from_status != "locked v2 record":
                errors.append(
                    f"{record.relative_to(ROOT)}: v2 record evidence is incomplete"
                )
                continue
            if component == "fetchii-core":
                match = CORE_LOCK_LINK.search(contents)
                if match is None:
                    errors.append(f"{record.relative_to(ROOT)}: input lock link is missing")
                    continue
                lock = (record.parent / match.group(2)).resolve()
                try:
                    lock.relative_to(ROOT)
                except ValueError:
                    errors.append(f"{record.relative_to(ROOT)}: input lock escapes repository")
                    continue
                if not lock.is_file():
                    errors.append(f"{record.relative_to(ROOT)}: input lock is missing")
                    continue
                digest = hashlib.sha256(lock.read_bytes()).hexdigest()
                if digest != match.group(1):
                    errors.append(f"{record.relative_to(ROOT)}: input lock digest mismatch")
                errors.extend(validate_lock(lock))
    lock_directory = directory / "locks"
    if lock_directory.exists():
        for lock in sorted(lock_directory.glob("*.json")):
            errors.extend(validate_lock(lock))
    return errors


def record_status(component: str, contents: str) -> str:
    if "<SHA256" in contents or "auto-filled" in contents:
        return "legacy recipe; digest not recorded"
    digests = re.findall(r"sha256: ([0-9a-f]{64})", contents)
    if component == "fetchii-core" and (
        "`fetchii-core-record/v2`" in contents
        and len(digests) >= 2
        and CORE_LOCK_LINK.search(contents)
        and re.search(r"yt-dlp commit:\*\* \[`[0-9a-f]{40}`\]", contents)
    ):
        return "locked v2 record"
    if component == "aria2" and (
        "`aria2-record/v2`" in contents
        and len(digests) >= 2
        and re.search(
            r"Source revision:\*\* `release-[0-9]+\.[0-9]+\.[0-9]+`",
            contents,
        )
    ):
        return "locked v2 record"
    return "legacy/manual record"


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
