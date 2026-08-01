<!-- Documentation template only. Production bytes are rendered by release_records.py. -->
# fetchii-core YYYY.MM.DD — corresponding-source record

- **Schema:** `fetchii-core-record/v3`
- **Artifact:** exact
  `https://downloads.beamdrop.entromoonic.com/fetchii-core/fetchii-core_macos_{version}.tar.gz`
  URL plus exact SHA-256
- **Input lock:** relative link plus the exact lock SHA-256
- **yt-dlp tag and commit:** exact CalVer tag plus the full 40-character commit
- **Locked source object:** immutable version/commit/digest URL, SHA-256, and byte length
- **Toolchain:** exact CPython patch and pip versions targeting macOS universal2
- **License:** the bundle includes `mutagen` under GPLv2-or-later; see
  [`../GPLv2.txt`](../GPLv2.txt).
- **Build recipe:** `python3 -m bundle.pyinstaller --onedir --target-architecture universal2`

Reproduction accepts only the locked source object and dependency artifacts. It must not
clone a tag, resolve `latest`, parse an installed environment, or redownload an input to
discover its digest.

## Locked dependencies

The generated record contains a stable table of every dependency's canonical name,
exact canonical PEP 440 version, immutable PyPI URL, SHA-256, and resolution scope. The
six required scopes are `runtime`, `build`, `pyinstaller`, `repair`, `curl-arm64`, and
`curl-x86-64`. The canonical JSON lock is stored at `locks/{version}.json` and has these
required fields:

```json
{
  "schemaVersion": 2,
  "component": "fetchii-core",
  "version": "YYYY.MM.DD",
  "source": {
    "repository": "https://github.com/yt-dlp/yt-dlp.git",
    "tag": "YYYY.MM.DD",
    "commit": "<40 lowercase hex>",
    "archiveUrl": "https://downloads.beamdrop.entromoonic.com/fetchii-core/sources/YYYY.MM.DD/<commit>/<sha256>.tar.gz",
    "archiveSha256": "<64 lowercase hex>",
    "archiveSize": 123456
  },
  "toolchain": {
    "pythonImplementation": "CPython",
    "pythonVersion": "<exact X.Y.Z>",
    "pipVersion": "<canonical exact PEP 440 version>",
    "targetPlatform": "macos",
    "targetArchitecture": "universal2"
  },
  "dependencies": [
    {
      "name": "mutagen",
      "version": "<exact version>",
      "artifacts": [
        {"scope": "runtime", "url": "https://files.pythonhosted.org/packages/<immutable artifact>", "sha256": "<64 lowercase hex>"}
      ]
    }
  ]
}
```

Missing mutagen, any missing scope, a floating or non-canonical version, a mutable URL,
missing source identity/size, non-canonical bytes, or a lock/record/artifact digest
mismatch is release-blocking. Production records use the fixed path `{version}.md`; a
same-version byte conflict must never be hidden behind a digest-suffixed filename.
Production record bytes are matched in full against an independent lock-bound renderer;
extra, duplicate, conflicting, or nested record fields are not accepted.
