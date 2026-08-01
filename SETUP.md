# Setup & automation (one-time)

This repository is designed for deterministic Builder tooling. A conforming production
run captures source and dependencies before the build, renders immutable records, and
preserves them here before a binary or client pointer becomes public. Release records
and the aggregate index are generated artifacts; repository policy rejects structural
drift but does not, by itself, prove a separate Builder run's ordering.

## 1. Publish this repo (public)

```sh
cd fetchii-oss-compliance
git init -b main
git add -A
git commit -m "Initial corresponding-source repository"
gh repo create entromoonic/fetchii-oss-compliance --public --source=. --push
```

> Contains only upstream pointers, build recipes, and license texts — no tokens, no keys.

## 2. Create a deploy key (write access, never expires)

A deploy key is scoped to **this one repo only** and does not expire — ideal for
unattended CI, and it isn't tied to any user account.

```sh
ssh-keygen -t ed25519 -C "fetchii-compliance-ci" -f compliance_deploy_key -N ""
```

- Add the **public** key (`compliance_deploy_key.pub`) to
  `entromoonic/fetchii-oss-compliance` → **Settings → Deploy keys → Add deploy key**,
  and **check "Allow write access"**.
- Add the **private** key (the whole `compliance_deploy_key` file, including the
  `-----BEGIN/END-----` lines) as a secret named **`COMPLIANCE_DEPLOY_KEY`** in the
  **`fetchii-aria2-builder`** repo (Settings → Secrets and variables → Actions).
- Delete the local key files afterward (`rm compliance_deploy_key*`).

## 3. Release transaction contract

Do not paste ad-hoc shell snippets into workflows. Builder owns the reviewed generators
and publisher. Every conforming production run must follow this order:

1. Resolve an exact source revision and capture the build-stage source archive.
2. Record the archive URL, SHA-256, and exact byte length. The immutable URL path is
   derived from release version, source commit, and digest. Reproduction must use this
   object; it must not resolve the upstream tag, `latest` URL, or package range again.
3. Before installing dependencies, turn exactly six resolver reports (`runtime`,
   `build`, `pyinstaller`, `repair`, `curl-arm64`, and `curl-x86-64`) into one canonical
   v2 input lock. The lock contains the full yt-dlp tag and commit, exact CPython and
   pip versions for the macOS/universal2 toolchain, exact mutagen version, every
   resolved dependency version, and each immutable PyPI URL/SHA-256. The build installs
   only lock entries.
4. Render the record and evidence from that lock and the final artifact digest. The
   core record's artifact URL is exactly
   `https://downloads.beamdrop.entromoonic.com/fetchii-core/fetchii-core_macos_{version}.tar.gz`.
   Write a canonical release manifest at `fetchii-core/versions/manifests/{version}.json`
   containing the independently captured display version, artifact URL, artifact
   SHA-256, and input-lock SHA-256. The evidence, object metadata, manifest, and OSS
   record must contain the same lock digest.
5. Stage only the immutable source/lock objects. Record paths are fixed at
   `aria2/versions/{version}.md`, `fetchii-core/versions/{version}.md`, and
   `fetchii-core/versions/locks/{version}.json` for the core lock, plus
   `fetchii-core/versions/manifests/{version}.json` for the independent release claims.
   Do not add other nested version-record directories; repository policy rejects them
   and the index ignores them.
   Pull requests fetch complete local history and run the append-only checker against
   the event's exact base commit. Any changed or deleted existing record/lock/manifest,
   missing base commit, shallow history, or unrelated base fails closed; only new fixed
   paths are accepted.
6. Publish the OSS record bundle with `publish_compliance.py`. It starts each retry from
   a fresh remote head, refuses conflicting immutable paths, regenerates the index, and
   uses a fast-forward-only push.
7. Only after a receipt proves the remote record bytes are visible may Builder create an
   aria2 GitHub Release or upload the core binary. The core publisher uploads immutable
   versioned objects, then advances `version.json` with compare-and-swap.

aria2 and fetchii-core use the same Builder concurrency group. The safe retry remains
required because manual changes and other writers can still race.

## 4. Failure and recovery rules

- Authentication, network, index-generation, or non-fast-forward failure before the
  receipt must leave no new GitHub Release, binary object, or client pointer.
- A retry may reuse an identical record, source object, lock, or binary object. The same
  immutable key with different bytes is a hard failure.
- If binary upload succeeds but pointer compare-and-swap fails, rerun the same inputs.
  The publisher verifies existing object metadata and retries only the pointer commit.
- A parallel aria2/core run must preserve both record files. Never force-push or use
  `--clobber` for a released binary.

## 5. Deterministic index and local policy

`fetchii-releases.md` is a generated component-record index, not an app-release map.

```sh
python3 scripts/generate_index.py
python3 scripts/check_compliance.py
```

CI runs the check form and a local Markdown-link scan. Adding a component record without
regenerating the index fails the policy check. A core record is accepted only when its
entire byte sequence matches the independent lock-bound renderer, including display
version, artifact, source, toolchain, license, build recipe, reproduction rules,
dependency table, and fixed lock link. The renderer receives display/artifact values
only from the canonical fixed-path manifest, never by parsing the record under test.

## Historical boundary

`aria2/versions/1.37.0.md` and `ffmpeg/versions/8.0.md` predate locked records and
contain recipe placeholders. They remain labelled legacy in the index; they must not be
used as templates or treated as proof of a captured digest. New aria2 and core records
use the fixed version paths above. An existing path with different bytes is
release-blocking; publishers must never silently replace it.
