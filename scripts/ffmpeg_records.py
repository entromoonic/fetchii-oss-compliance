"""Offline validation of Builder's deterministic FFmpeg v1 record bundle."""

from __future__ import annotations

import datetime
import hashlib
import json
import re


REPOSITORY = "dynamicfire/fetchii-aria2-builder"
CONFIGURE_FLAGS = [
    "--enable-videotoolbox",
    "--enable-libvpx",
    "--enable-libopus",
    "--enable-libvorbis",
    "--enable-libdav1d",
    "--enable-static",
    "--disable-shared",
    "--disable-doc",
    "--disable-ffplay",
    "--disable-debug",
    "--disable-libxcb",
    "--disable-libxcb-shm",
    "--disable-libxcb-xfixes",
    "--disable-libxcb-shape",
    "--disable-xlib",
]
VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
UPSTREAM_VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?"
SHA256 = r"[0-9a-f]{64}"
COMMIT = r"[0-9a-f]{40}"


def _object(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} has an invalid schema")
    return value


def _match(value: object, pattern: str, label: str) -> None:
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ValueError(f"{label} is invalid")


def _positive_size(value: object, label: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} must be a positive integer")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _render_record(lock: dict, lock_digest: str, evidence: dict) -> bytes:
    lines = [
        "<!-- fetchii-ffmpeg-record/v1 -->",
        f"# FFmpeg {lock['releaseVersion']} — signed universal LGPL build",
        "",
        f"- Release identity: `ffmpeg-v{lock['releaseVersion']}`",
        f"- Upstream FFmpeg version: `{lock['upstreamVersion']}`",
        f"- Input lock: `locks/{lock['releaseVersion']}.json` (sha256: `{lock_digest}`)",
        "- Artifact: `ffmpeg_macos.tar.gz` "
        f"(sha256: `{evidence['artifact']['sha256']}`)",
        "- Apple notarization: `Accepted` "
        f"(submission: `{evidence['notarization']['id']}`)",
        f"- Signing certificate SHA-256: `{evidence['signing']['certificateSha256']}`",
        f"- Signing Team ID: `{evidence['signing']['teamId']}`",
        "",
        "## Exact corresponding source",
        "",
    ]
    for source in lock["sources"]:
        lines.append(
            f"- `{source['archive']}`: revision `{source['revision']}`, "
            f"sha256 `{source['sha256']}`, origin {source['originUrl']}, "
            f"release {source['releaseUrl']}"
        )
    lines.extend(("", "Build flags: " + " ".join(CONFIGURE_FLAGS), ""))
    return "\n".join(lines).encode("utf-8")


def validate_bundle(
    record_bytes: bytes,
    lock: object,
    lock_bytes: bytes,
    evidence: object,
    version: str,
) -> None:
    """Validate record, canonical lock and parsed evidence without reading files.

    The caller must strictly parse and check canonical evidence JSON. Archive
    contents and external signing/publication claims are verified by the producer.
    """
    _match(version, VERSION, "FFmpeg record version")
    lock = _object(
        lock,
        {"schemaVersion", "component", "releaseVersion", "upstreamVersion", "build", "sources"},
        "FFmpeg input lock",
    )
    if type(lock["schemaVersion"]) is not int or lock["schemaVersion"] != 1:
        raise ValueError("FFmpeg input lock schema version is invalid")
    if lock["component"] != "ffmpeg" or lock["releaseVersion"] != version:
        raise ValueError("FFmpeg input lock release identity does not match its path")
    upstream = lock["upstreamVersion"]
    _match(upstream, UPSTREAM_VERSION, "FFmpeg upstream version")
    if lock["build"] != {
        "targetPlatform": "macos",
        "targetArchitecture": "universal2",
        "license": "LGPL-2.1-or-later",
        "configureFlags": CONFIGURE_FLAGS,
    }:
        raise ValueError("FFmpeg input lock build profile is invalid")

    sources = lock["sources"]
    if not isinstance(sources, list) or len(sources) != 6:
        raise ValueError("FFmpeg input lock requires exactly six ordered sources")
    descriptors = (
        ("ffmpeg", f"https://ffmpeg.org/releases/ffmpeg-{upstream}.tar.gz", upstream),
        ("libvpx", "https://chromium.googlesource.com/webm/libvpx", None),
        ("opus", "https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz", "1.5.2"),
        ("ogg", "https://downloads.xiph.org/releases/ogg/libogg-1.3.5.tar.gz", "1.3.5"),
        ("vorbis", "https://downloads.xiph.org/releases/vorbis/libvorbis-1.3.7.tar.gz", "1.3.7"),
        ("dav1d", "https://code.videolan.org/videolan/dav1d.git", None),
    )
    for source, (name, origin, revision) in zip(sources, descriptors):
        source = _object(
            source,
            {"name", "archive", "originUrl", "revision", "releaseUrl", "sha256", "size"},
            f"FFmpeg source {name}",
        )
        archive = f"{name}-source.tar.gz"
        if (
            source["name"] != name
            or source["archive"] != archive
            or source["originUrl"] != origin
            or source["releaseUrl"]
            != f"https://github.com/{REPOSITORY}/releases/download/ffmpeg-v{version}/{archive}"
        ):
            raise ValueError(f"FFmpeg source {name} descriptor is invalid")
        if revision is None:
            _match(source["revision"], COMMIT, f"FFmpeg source {name} revision")
        elif source["revision"] != revision:
            raise ValueError(f"FFmpeg source {name} revision is invalid")
        _match(source["sha256"], SHA256, f"FFmpeg source {name} digest")
        _positive_size(source["size"], f"FFmpeg source {name} size")

    canonical_lock = (
        json.dumps(lock, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    if lock_bytes != canonical_lock:
        raise ValueError("FFmpeg input lock bytes are not canonical JSON")
    lock_digest = _digest(lock_bytes)
    evidence = _object(
        evidence,
        {
            "schemaVersion", "component", "releaseVersion", "upstreamVersion",
            "inputLockSha256", "artifact", "signing", "notarization", "workflow",
            "generatedAt", "recordSha256",
        },
        "FFmpeg release evidence",
    )
    if type(evidence["schemaVersion"]) is not int or evidence["schemaVersion"] != 1:
        raise ValueError("FFmpeg release evidence schema version is invalid")
    if (
        evidence["component"] != "ffmpeg"
        or evidence["releaseVersion"] != version
        or evidence["upstreamVersion"] != upstream
        or evidence["inputLockSha256"] != lock_digest
    ):
        raise ValueError("FFmpeg release evidence does not bind the input lock")
    artifact = _object(
        evidence["artifact"],
        {"name", "sha256", "size", "checksumName", "checksumSha256"},
        "FFmpeg artifact evidence",
    )
    if artifact["name"] != "ffmpeg_macos.tar.gz" or artifact["checksumName"] != "ffmpeg_macos.tar.gz.sha256":
        raise ValueError("FFmpeg artifact names are invalid")
    _match(artifact["sha256"], SHA256, "FFmpeg artifact digest")
    _positive_size(artifact["size"], "FFmpeg artifact size")
    checksum = f"{artifact['sha256']}  ffmpeg_macos.tar.gz\n".encode("ascii")
    if artifact["checksumSha256"] != _digest(checksum):
        raise ValueError("FFmpeg checksum digest does not bind the canonical sidecar")
    signing = _object(
        evidence["signing"], {"certificateSha256", "teamId"}, "FFmpeg signing evidence"
    )
    _match(signing["certificateSha256"], SHA256, "FFmpeg signing certificate digest")
    _match(signing["teamId"], r"[A-Z0-9]{10}", "FFmpeg signing Team ID")
    notary = _object(evidence["notarization"], {"id", "message", "status"}, "FFmpeg Apple notary proof")
    _match(
        notary["id"],
        r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        "FFmpeg Apple notary submission ID",
    )
    message = notary["message"]
    if (
        not isinstance(message, str)
        or not message
        or len(message.encode("utf-8")) > 1_000
        or any(character in message for character in "\r\n\x00")
        or notary["status"] != "Accepted"
    ):
        raise ValueError("FFmpeg Apple notary proof is invalid or not Accepted")
    workflow = _object(
        evidence["workflow"],
        {"repository", "workflowPath", "workflowSha", "runId", "runAttempt"},
        "FFmpeg workflow evidence",
    )
    if workflow["repository"] != REPOSITORY or workflow["workflowPath"] != ".github/workflows/build-ffmpeg.yml":
        raise ValueError("FFmpeg workflow identity is invalid")
    _match(workflow["workflowSha"], COMMIT, "FFmpeg workflow commit")
    _match(workflow["runId"], r"[1-9][0-9]*", "FFmpeg workflow run ID")
    _match(workflow["runAttempt"], r"[1-9][0-9]*", "FFmpeg workflow run attempt")
    timestamp = evidence["generatedAt"]
    _match(timestamp, r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", "FFmpeg generation timestamp")
    datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
    if evidence["recordSha256"] != _digest(record_bytes):
        raise ValueError("FFmpeg release evidence does not bind the record bytes")
    if record_bytes != _render_record(lock, lock_digest, evidence):
        raise ValueError("FFmpeg record is not the deterministic evidence rendering")
