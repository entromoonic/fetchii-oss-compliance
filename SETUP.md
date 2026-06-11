# Setup & automation (one-time)

This repo is meant to maintain itself: the builder CI writes a `versions/<v>.md`
record every time it builds a binary, so corresponding source is published before the
binary reaches users. Manual edits should never be needed after this setup.

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

## 3. Add a "Publish corresponding-source record" step to each builder workflow

Paste one step into each build workflow, after the binary is built. Each computes the
source SHA-256 and pushes a small record over SSH using the deploy key. Example for
**`build-aria2.yml`**:

```yaml
      - name: Publish corresponding-source record
        env:
          COMPLIANCE_DEPLOY_KEY: ${{ secrets.COMPLIANCE_DEPLOY_KEY }}
        run: |
          set -euo pipefail
          mkdir -p ~/.ssh
          echo "$COMPLIANCE_DEPLOY_KEY" > ~/.ssh/compliance_key
          chmod 600 ~/.ssh/compliance_key
          export GIT_SSH_COMMAND="ssh -i ~/.ssh/compliance_key -o StrictHostKeyChecking=accept-new"
          VER="1.37.0"                       # or your aria2 version variable
          SRC_URL="https://github.com/aria2/aria2/releases/download/release-${VER}/aria2-${VER}.tar.xz"
          SRC_SHA="$(curl -fsSL "$SRC_URL" | shasum -a 256 | cut -d' ' -f1)"
          git clone --depth 1 git@github.com:entromoonic/fetchii-oss-compliance.git c
          mkdir -p c/aria2/versions
          cat > "c/aria2/versions/${VER}.md" <<MD
          # aria2 ${VER} — corresponding source

          - Upstream: ${SRC_URL} (sha256: ${SRC_SHA})
          - License: GPLv2 (../GPLv2.txt) — macOS universal2, static, --with-appletls

          ## Build
              ./configure --host=arm64-apple-darwin --without-libxml2 --without-libexpat \\
                --without-sqlite3 --without-libssh2 --without-libcares --without-libnettle \\
                --without-libgmp --without-libgcrypt --with-appletls \\
                CFLAGS="-arch arm64 -O2" CXXFLAGS="-arch arm64 -O2" LDFLAGS="-arch arm64"
              make -j\$(sysctl -n hw.ncpu)   # repeat for x86_64, then lipo into universal2
          MD
          cd c
          git config user.name  "fetchii-ci"
          git config user.email "ci@entromoonic.com"
          git add -A
          git commit -m "aria2 ${VER} corresponding source" || { echo "no change"; exit 0; }
          git push
```

**`build-ffmpeg.yml`** — same shape, with:
- `VER` = ffmpeg version, `SRC_URL="https://ffmpeg.org/releases/ffmpeg-${VER}.tar.xz"`
- recipe = the FFmpeg `./configure` block (see `ffmpeg/versions/8.0.md`)
- write to `c/ffmpeg/versions/${VER}.md`

**`build-yt-dlp.yml`** — same shape, with:
- `VER` = `${{ github.event.inputs.version }}` (the yt-dlp CalVer)
- also copy the generated `requirements.txt` (it pins the exact `mutagen==` version) to
  `c/fetchii-core/versions/requirements-${VER}.txt`
- recipe = `python3 -m bundle.pyinstaller --onedir --target-architecture universal2`
- write to `c/fetchii-core/versions/${VER}.md` (see `fetchii-core/versions/TEMPLATE.md`)

The same one deploy key works for all three workflows (it grants write to this repo).

## 4. (Optional) Map each Fetchii release to its binary versions

In `Fetchii/.github/workflows/build-release.yml`, after the version is determined, append
a row to `fetchii-releases.md` here (add the same deploy key as a secret in the Fetchii
repo). Nice for users but not legally required — the per-binary records already cover the
obligation.

## After setup

Nothing. Every binary build auto-publishes its record. Update build recipes here only if
the actual configure/build flags change (rare); version bumps are recorded automatically.
