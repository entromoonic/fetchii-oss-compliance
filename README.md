# Fetchii — Open-Source Compliance & Corresponding Source

Fetchii, by **Entromoonic, Ltd.**, is a closed-source application, but it
redistributes a few components licensed under the GNU **GPL / LGPL**. This repository
exists to preserve the corresponding-source and build-input records associated with
redistributed binaries. Generated core v3 records bind an exact binary digest to a
locked source object, source revision, exact toolchain, and deterministic dependency
lock. Older recipe-only entries are retained and explicitly labelled as legacy; their
presence is not presented as proof that a missing historical digest was captured.

This repository is the public evidence and source-discovery location referenced from the
app's **About → Acknowledgments** screen. Whether a particular distribution satisfies
all applicable license obligations depends on that distribution and its complete record;
the repository index alone does not establish that conclusion.

## Components we redistribute under GPL / LGPL

| Component | License | Where it ships | Upstream | Records |
|-----------|---------|----------------|----------|---------|
| **aria2** (`aria2c`) | GPLv2 | bundled in the app `.app`/DMG | <https://github.com/aria2/aria2> | [`aria2/versions/`](aria2/versions/) |
| **FFmpeg** (`ffmpeg`, `ffprobe`) | LGPLv2.1 | bundled in the app `.app`/DMG | <https://github.com/FFmpeg/FFmpeg> | [`ffmpeg/versions/`](ffmpeg/versions/) |
| **mutagen** | GPLv2-or-later | bundled inside the runtime-downloaded `fetchii-core` engine | <https://github.com/quodlibet/mutagen> | [`fetchii-core/versions/`](fetchii-core/versions/) |

Notes:

- aria2 and FFmpeg are invoked as **separate executables**; they are not linked into
  the application (mere aggregation under the GPL/LGPL).
- `fetchii-core` is a [PyInstaller](https://pyinstaller.org/) bundle of
  [**yt-dlp**](https://github.com/yt-dlp/yt-dlp) (Unlicense — no source obligation). Its
  default dependency set bundles **mutagen** (GPLv2-or-later), which is why it is listed
  here. The other bundled dependencies (pycryptodomex, brotli, certifi, requests,
  urllib3, websockets) are under permissive licenses.
- FFmpeg is built **without** `--enable-gpl` (no x264/x265). It statically links only
  permissive (BSD/MIT) libraries — libvpx, libopus, libvorbis, libdav1d — and uses
  Apple VideoToolbox for hardware encoding.

## How to find the source for *your* version

The corresponding source must match the **exact binary received**. Generated records are
kept under each component's `versions/` directory and include the binary SHA-256. A
generated record points only to the source archive captured during the build and to its
recorded SHA-256 and byte length; it never asks a reviewer to rediscover provenance by
resolving an upstream tag or `latest` URL again. fetchii-core v3 records additionally
carry the exact yt-dlp tag and commit and a canonical v2 lock containing exact CPython
and pip versions for a macOS/universal2 toolchain, every dependency resolved across all
six build scopes, immutable PyPI artifact URLs, and source hashes. An independent
canonical release manifest supplies the expected display version, artifact URL and
artifact SHA-256; record policy never accepts those claims merely because the record
asserts them itself.

Immutable release paths are version-keyed rather than digest-suffixed:
`aria2/versions/{version}.md`, `fetchii-core/versions/{version}.md`, and
`fetchii-core/versions/locks/{version}.json`. Each core record also requires the fixed
sidecar `fetchii-core/versions/manifests/{version}.json`, whose canonical bytes bind to
the corresponding input-lock digest. Reusing a version with different bytes is a
conflict, not a new filename. Core records accept only the matching artifact URL
`https://downloads.beamdrop.entromoonic.com/fetchii-core/fetchii-core_macos_{version}.tar.gz`;
`latest`, a foreign host, or another path is invalid. Version records are top-level
files; nested record directories other than the fixed `locks/` and `manifests/`
sidecars are rejected and never indexed.

Pull-request policy compares every existing record, lock, and release-manifest byte
against the exact base commit. Existing protected paths cannot be edited, replaced, or
deleted; a release is represented only by adding new fixed-version paths. The check
fails closed when the base commit or its history is unavailable locally.

The deterministic [`fetchii-releases.md`](fetchii-releases.md) page is a convenience
index of component records. It is generated from the repository tree and checked in CI;
the per-component records remain the primary path. The index does not claim to map app
release numbers and does not turn a legacy recipe into a locked record.

The required Builder protocol is record-first: source/lock inputs are staged first, the
OSS record is preserved with a fast-forward-safe retry, and only then may a GitHub
Release, core binary object, or client `version.json` become visible. This repository
documents and validates the record format; Builder workflow policy must separately
verify that a production path enforces the ordering.

License texts live next to each component (`aria2/GPLv2.txt`, `ffmpeg/LGPLv2.1.txt`,
`fetchii-core/GPLv2.txt`).

## Source-availability contact

For questions or requests concerning the corresponding source associated with a
particular Fetchii distribution, contact **contact@entromoonic.com**. This discovery
page does not state a legal conclusion about a particular distribution or replace the
terms accompanying it.

## What is intentionally not here

This repository contains only the corresponding source the licenses require — the
upstream source and the component build recipes. Fetchii's proprietary build pipeline
(CI orchestration, code-signing, notarization, CDN distribution) is not part of any
GPL/LGPL component's corresponding source and is not included.
