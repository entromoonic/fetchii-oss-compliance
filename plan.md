# FFmpeg corresponding-source policy support

- Core 2026.08.19 and aria2 Builder 1.37.1 records were published through checked squash PRs.
- FFmpeg Builder 8.0.1 completed source capture, universal builds, signing and Apple notarization. Its publication candidate preserves the original signed bytes and source closure.
- The required OSS policy check rejected the producer's evidence and lock directories because the checker had no FFmpeg v1 bundle support.
- Add only the defined FFmpeg directories, strict paired record/lock/evidence validation, and append-only protection for both JSON sidecars. Preserve the exact historical 8.0 record; reject new legacy-format replacements and orphan or unsafe sidecar paths.
- Keep the pinned index generator unchanged. No branch protection or required check is bypassed.
- Completed strict bundle validation and 19 targeted regression tests. All 69 repository tests, the policy check against the actual signed candidate, append-only checks against ec77822fd2690e60a530663b45dc53ae1c4daade, and git diff --check pass.
- Publish this policy change separately from the unmerged candidate. Its publication job timed out while the required check failed; rerun the existing FFmpeg workflow with the same inputs after the policy PR merges, preserving each run's source and signing evidence identity.
- No FFmpeg 8.0.1 version record has been merged and no GitHub binary release has been published yet.
