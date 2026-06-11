# Fetchii — Open-Source Compliance & Corresponding Source

Fetchii, by **Entromoonic, Ltd.**, is a closed-source application, but it
redistributes a few components licensed under the GNU **GPL / LGPL**. This repository
exists to satisfy our obligations under those licenses: it provides the **complete
corresponding source** and the **exact build recipes** used to produce the binaries we
ship.

This repository is the "written offer" referenced in the app's **About → Acknowledgments**
screen.

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

The corresponding source you are entitled to is the one matching the **exact binary you
received**, so records are kept **per binary version** under each component's
`versions/` directory. Each record lists the exact upstream tag, a `fetch` line that
downloads and checksum-verifies that source, and the exact configure/build commands used.

Binary versions are recorded automatically by our build pipeline the moment a binary is
built — so a record exists for every version we have ever distributed. The optional
[`fetchii-releases.md`](fetchii-releases.md) maps each Fetchii app release to the binary
versions it shipped, for convenience.

License texts live next to each component (`aria2/GPLv2.txt`, `ffmpeg/LGPLv2.1.txt`,
`fetchii-core/GPLv2.txt`).

## Written offer

For any version of Fetchii distributed within the past **three (3) years**, Entromoonic,
Ltd. will also provide the complete corresponding source code for the GPL/LGPL components
on physical media at cost, on request. Contact: **contact@entromoonic.com**.

## What is intentionally not here

This repository contains only the corresponding source the licenses require — the
upstream source and the component build recipes. Fetchii's proprietary build pipeline
(CI orchestration, code-signing, notarization, CDN distribution) is not part of any
GPL/LGPL component's corresponding source and is not included.
