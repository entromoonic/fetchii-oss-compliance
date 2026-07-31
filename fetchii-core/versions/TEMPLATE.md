<!-- Documentation template only. Production bytes are rendered by release_records.py. -->
# fetchii-core YYYY.MM.DD — corresponding-source record

- **Schema:** `fetchii-core-record/v2`
- **Artifact:** immutable versioned URL plus exact SHA-256
- **Input lock:** relative link plus the exact lock SHA-256
- **yt-dlp commit:** full 40-character commit bound to the approved release tag
- **Locked source object:** the archive captured during the build plus exact SHA-256
- **License:** the bundle includes `mutagen` under GPLv2-or-later; see
  [`../GPLv2.txt`](../GPLv2.txt).
- **Build recipe:** `python3 -m bundle.pyinstaller --onedir --target-architecture universal2`

Reproduction accepts only the locked source object and dependency artifacts. It must not
clone a tag, resolve `latest`, parse an installed environment, or redownload an input to
discover its digest.

## Locked dependencies

The generated record contains a stable table of every dependency's canonical name,
exact version, source URL, SHA-256, and resolution scope. The canonical JSON lock is
stored under `locks/` and has these required fields:

```json
{
  "schemaVersion": 1,
  "component": "fetchii-core",
  "version": "YYYY.MM.DD",
  "source": {
    "repository": "https://github.com/yt-dlp/yt-dlp.git",
    "commit": "<40 lowercase hex>",
    "archiveUrl": "<immutable build-stage source object>",
    "archiveSha256": "<64 lowercase hex>"
  },
  "dependencies": [
    {
      "name": "mutagen",
      "version": "<exact version>",
      "artifacts": [
        {"scope": "runtime", "url": "<https source URL>", "sha256": "<64 lowercase hex>"}
      ]
    }
  ]
}
```

Missing mutagen, a floating version, missing commit/source digest, non-canonical bytes,
or a lock/record/artifact digest mismatch is release-blocking.
