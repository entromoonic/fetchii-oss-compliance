from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION = "8.0.1"
RECORDS = ROOT / "ffmpeg" / "versions"
FIXTURE = ROOT / "tests" / "fixtures" / "ffmpeg-8.0.1"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


ffmpeg_records = load("ffmpeg_records", ROOT / "scripts" / "ffmpeg_records.py")
check_compliance = load("ffmpeg_policy", ROOT / "scripts" / "check_compliance.py")


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class FFmpegBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        # These immutable files are the real 8.0.1 production candidate.
        self.record = (FIXTURE / "record.md").read_bytes()
        self.lock_raw = (FIXTURE / "input-lock.json").read_bytes()
        self.lock = json.loads(self.lock_raw)
        self.evidence = json.loads(
            (FIXTURE / "release-evidence.json").read_bytes()
        )

    def assert_invalid(self, *, lock=None, evidence=None, replacements=(), version=VERSION):
        lock = copy.deepcopy(self.lock if lock is None else lock)
        evidence = copy.deepcopy(self.evidence if evidence is None else evidence)
        record = self.record
        for before, after in replacements:
            self.assertIn(before, record)
            record = record.replace(before, after)
        raw = canonical(lock)
        record = record.replace(self.evidence["inputLockSha256"].encode(), sha256(raw).encode())
        evidence["inputLockSha256"] = sha256(raw)
        evidence["recordSha256"] = sha256(record)
        with self.assertRaises(ValueError):
            ffmpeg_records.validate_bundle(record, lock, raw, evidence, version)

    def test_real_production_candidate_passes(self) -> None:
        self.assertEqual(self.lock_raw, canonical(self.lock))
        self.assertEqual(sha256(self.lock_raw), self.evidence["inputLockSha256"])
        self.assertEqual(sha256(self.record), self.evidence["recordSha256"])
        self.assertIsNone(ffmpeg_records.validate_bundle(
            self.record, self.lock, self.lock_raw, self.evidence, VERSION
        ))

    def test_lock_schema_and_release_identity_are_exact(self) -> None:
        mutations = (
            ("schemaVersion", True), ("schemaVersion", 2),
            ("component", "aria2"), ("releaseVersion", "8.0.2"),
            ("upstreamVersion", "8.0-beta"), ("unexpected", "field"),
        )
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                lock = copy.deepcopy(self.lock)
                lock[key] = value
                self.assert_invalid(lock=lock)
        lock = copy.deepcopy(self.lock)
        del lock["build"]
        self.assert_invalid(lock=lock)
        for version in ("8.0", "08.0.1", "8.0.2", "../8.0.1"):
            with self.subTest(version=version):
                self.assert_invalid(version=version)

    def test_exact_six_ordered_unique_sources_are_required(self) -> None:
        for label, sources in (
            ("missing", self.lock["sources"][:-1]),
            ("duplicate", self.lock["sources"][:-1] + [self.lock["sources"][0]]),
            ("extra", self.lock["sources"] + [self.lock["sources"][0]]),
            ("reordered", list(reversed(self.lock["sources"]))),
        ):
            with self.subTest(label=label):
                lock = copy.deepcopy(self.lock)
                lock["sources"] = sources
                self.assert_invalid(lock=lock)

    def test_source_origins_release_urls_and_revisions_are_bound(self) -> None:
        mutations = (
            (0, "originUrl", "https://example.com/ffmpeg-8.0.tar.gz"),
            (0, "releaseUrl", self.lock["sources"][0]["releaseUrl"].replace("8.0.1", "8.0.2")),
            (0, "archive", "ffmpeg.tar.gz"),
            (0, "name", "other"),
            (0, "revision", "8.0.2"),
            (1, "revision", "d168454"),
            (5, "revision", "main"),
            (2, "revision", "1.5.1"),
            (3, "originUrl", "https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz"),
        )
        for index, key, value in mutations:
            with self.subTest(index=index, key=key):
                lock = copy.deepcopy(self.lock)
                before = lock["sources"][index][key]
                lock["sources"][index][key] = value
                replacements = () if key == "name" else ((before.encode(), value.encode()),)
                self.assert_invalid(lock=lock, replacements=replacements)

    def test_source_metadata_requires_exact_fields_hashes_and_positive_integer_size(self) -> None:
        for key, value in (
            ("sha256", "x" * 64), ("sha256", "A" * 64),
            ("size", True), ("size", 0), ("size", -1), ("size", 1.5),
            ("unexpected", "field"),
        ):
            with self.subTest(key=key, value=value):
                lock = copy.deepcopy(self.lock)
                before = lock["sources"][0].get(key)
                lock["sources"][0][key] = value
                replacements = ((before.encode(), value.encode()),) if key == "sha256" else ()
                self.assert_invalid(lock=lock, replacements=replacements)
        lock = copy.deepcopy(self.lock)
        del lock["sources"][0]["size"]
        self.assert_invalid(lock=lock)

    def test_build_license_targets_and_flags_are_fixed(self) -> None:
        for key, value in (
            ("license", "GPL-3.0-only"), ("targetPlatform", "linux"),
            ("targetArchitecture", "arm64"), ("unexpected", "field"),
        ):
            with self.subTest(key=key):
                lock = copy.deepcopy(self.lock)
                lock["build"][key] = value
                self.assert_invalid(lock=lock)
        flags = self.lock["build"]["configureFlags"]
        for changed in (flags + ["--enable-gpl"], flags[:-1], list(reversed(flags))):
            with self.subTest(flags=changed):
                lock = copy.deepcopy(self.lock)
                lock["build"]["configureFlags"] = changed
                self.assert_invalid(lock=lock, replacements=((
                    " ".join(flags).encode(), " ".join(changed).encode()
                ),))

    def test_evidence_schema_and_versions_are_exact(self) -> None:
        for key, value in (
            ("schemaVersion", True), ("schemaVersion", 2),
            ("component", "aria2"), ("releaseVersion", "8.0.2"),
            ("upstreamVersion", "8.1"), ("unexpected", "field"),
        ):
            with self.subTest(key=key):
                evidence = copy.deepcopy(self.evidence)
                evidence[key] = value
                self.assert_invalid(evidence=evidence)
        evidence = copy.deepcopy(self.evidence)
        del evidence["artifact"]
        self.assert_invalid(evidence=evidence)

    def test_artifact_and_checksum_metadata_are_bound(self) -> None:
        for key, value in (
            ("name", "other.tar.gz"), ("checksumName", "other.sha256"),
            ("checksumSha256", "f" * 64), ("sha256", "A" * 64),
            ("size", True), ("size", 0), ("size", -1), ("size", 1.5),
            ("unexpected", "field"),
        ):
            with self.subTest(key=key, value=value):
                evidence = copy.deepcopy(self.evidence)
                evidence["artifact"][key] = value
                self.assert_invalid(evidence=evidence)

    def test_signing_and_notarization_claims_are_strict(self) -> None:
        mutations = (
            ("signing", "certificateSha256", "A" * 64),
            ("signing", "teamId", "invalid"),
            ("signing", "unexpected", "field"),
            ("notarization", "id", "invalid"),
            ("notarization", "status", "Rejected"),
            ("notarization", "message", ""),
            ("notarization", "message", "injected\nline"),
            ("notarization", "message", "x" * 1001),
            ("notarization", "unexpected", "field"),
        )
        for section, key, value in mutations:
            with self.subTest(section=section, key=key):
                evidence = copy.deepcopy(self.evidence)
                before = evidence[section].get(key)
                evidence[section][key] = value
                replacements = ((before.encode(), value.encode()),) if (
                    before and before.encode() in self.record
                ) else ()
                self.assert_invalid(evidence=evidence, replacements=replacements)

    def test_workflow_identity_and_timestamp_are_strict(self) -> None:
        for key, value in (
            ("repository", "other/fetchii-aria2-builder"),
            ("workflowPath", ".github/workflows/build-deno.yml"),
            ("workflowSha", "3773585"), ("runId", 34189567944),
            ("runId", "0"), ("runAttempt", "01"), ("unexpected", "field"),
        ):
            with self.subTest(key=key, value=value):
                evidence = copy.deepcopy(self.evidence)
                evidence["workflow"][key] = value
                self.assert_invalid(evidence=evidence)
        for value in ("2026-02-30T04:59:24Z", "2026-09-08T04:59:24+00:00", 1):
            with self.subTest(generatedAt=value):
                evidence = copy.deepcopy(self.evidence)
                evidence["generatedAt"] = value
                self.assert_invalid(evidence=evidence)

    def test_lock_and_record_digest_mismatches_are_rejected(self) -> None:
        for key in ("inputLockSha256", "recordSha256"):
            with self.subTest(key=key):
                evidence = copy.deepcopy(self.evidence)
                evidence[key] = "f" * 64
                with self.assertRaises(ValueError):
                    ffmpeg_records.validate_bundle(
                        self.record, self.lock, self.lock_raw, evidence, VERSION
                    )

    def test_record_rewrite_still_fails_after_rehashing_evidence(self) -> None:
        self.assert_invalid(replacements=((b"signed universal LGPL build", b"unverified build"),))
        self.assert_invalid(replacements=((b"\n", b"\r\n"),))


class FFmpegPolicyIntegrationTests(unittest.TestCase):
    def make_tree(self, root: Path) -> Path:
        directory = root / "ffmpeg" / "versions"
        for name in ("locks", "evidence"):
            (directory / name).mkdir(parents=True)
            fixture = "input-lock.json" if name == "locks" else "release-evidence.json"
            shutil.copyfile(FIXTURE / fixture, directory / name / f"{VERSION}.json")
        shutil.copyfile(FIXTURE / "record.md", directory / f"{VERSION}.md")
        shutil.copyfile(RECORDS / "8.0.md", directory / "8.0.md")
        return directory

    def test_real_tree_passes_with_only_the_two_allowed_sidecar_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = self.make_tree(root)
            self.assertEqual(check_compliance.ffmpeg_record_errors(root=root), [])
            self.assertEqual(check_compliance._version_tree_errors(
                directory, component="ffmpeg", root=root
            ), [])
            (directory / "other").mkdir()
            self.assertTrue(check_compliance._version_tree_errors(
                directory, component="ffmpeg", root=root
            ))

    def test_missing_or_orphaned_bundle_member_is_rejected(self) -> None:
        for name in (f"{VERSION}.md", f"locks/{VERSION}.json", f"evidence/{VERSION}.json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                directory = self.make_tree(root)
                (directory / name).unlink()
                self.assertTrue(check_compliance.ffmpeg_record_errors(root=root))
        for folder in ("locks", "evidence"):
            with self.subTest(folder=folder), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                directory = self.make_tree(root)
                shutil.copyfile(directory / folder / f"{VERSION}.json", directory / folder / "8.0.2.json")
                self.assertTrue(check_compliance.ffmpeg_record_errors(root=root))

    def test_sidecar_directories_reject_nested_linked_or_unexpected_members(self) -> None:
        for folder in ("locks", "evidence"):
            for kind in ("nested", "symlink", "hardlink", "unexpected", "wrong-version"):
                with self.subTest(folder=folder, kind=kind), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    directory = self.make_tree(root)
                    target = directory / folder / f"{VERSION}.json"
                    extra = directory / folder / "extra.json"
                    if kind == "nested":
                        extra.mkdir()
                    elif kind == "symlink":
                        extra.symlink_to(target.name)
                    elif kind == "hardlink":
                        os.link(target, extra)
                    else:
                        extra = directory / folder / ("unexpected.txt" if kind == "unexpected" else "8.0.json")
                        shutil.copyfile(target, extra)
                    self.assertTrue(check_compliance.ffmpeg_record_errors(root=root))

    def test_sidecar_directory_itself_cannot_be_a_symlink(self) -> None:
        for folder in ("locks", "evidence"):
            with self.subTest(folder=folder), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                directory = self.make_tree(root)
                backing = root / folder
                (directory / folder).rename(backing)
                (directory / folder).symlink_to(backing, target_is_directory=True)
                self.assertTrue(check_compliance.ffmpeg_record_errors(root=root))

    def test_noncanonical_or_duplicate_json_is_rejected(self) -> None:
        for folder in ("locks", "evidence"):
            for kind in ("whitespace", "duplicate", "boolean-schema", "NaN"):
                with self.subTest(folder=folder, kind=kind), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    directory = self.make_tree(root)
                    target = directory / folder / f"{VERSION}.json"
                    raw = target.read_bytes()
                    if kind == "whitespace":
                        changed = raw + b"\n"
                    elif kind == "duplicate":
                        changed = raw.replace(b"{", b'{"component":"ffmpeg",', 1)
                    else:
                        changed = raw.replace(b'"schemaVersion":1', b'"schemaVersion":' + (b"true" if kind == "boolean-schema" else b"NaN"))
                    target.write_bytes(changed)
                    self.assertTrue(check_compliance.ffmpeg_record_errors(root=root))

    def test_new_manual_record_and_historical_rewrite_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = self.make_tree(root)
            (directory / "8.0.2.md").write_text("# Unlocked FFmpeg record\n")
            self.assertTrue(check_compliance.ffmpeg_record_errors(root=root))
            (directory / "8.0.2.md").unlink()
            (directory / "8.0.md").write_text("# Rewritten history\n")
            self.assertTrue(check_compliance.ffmpeg_record_errors(root=root))

    def test_append_only_history_protects_both_ffmpeg_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = self.make_tree(root)
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"

            def git(*arguments: str) -> str:
                return subprocess.run(
                    ["git", "-c", "user.name=Policy Test", "-c", "user.email=policy@example.invalid", *arguments],
                    cwd=root, env=environment, check=True, capture_output=True, text=True,
                ).stdout.strip()

            git("init", "-q")
            git("add", ".")
            git("commit", "-qm", "Initial immutable FFmpeg bundle")
            base = git("rev-parse", "HEAD")
            self.assertEqual(check_compliance.append_only_history_errors(base, root=root), [])
            for folder in ("locks", "evidence"):
                path = directory / folder / f"{VERSION}.json"
                original = path.read_bytes()
                for mutation in ("rewrite", "delete"):
                    with self.subTest(folder=folder, mutation=mutation):
                        if mutation == "rewrite":
                            path.write_bytes(original + b"\n")
                        else:
                            path.unlink()
                        errors = check_compliance.append_only_history_errors(base, root=root)
                        self.assertTrue(any(str(path.relative_to(root)) in error for error in errors), errors)
                        path.write_bytes(original)
            for folder in ("locks", "evidence"):
                (directory / folder / "8.0.2.json").write_bytes(b"{}\n")
            self.assertEqual(check_compliance.append_only_history_errors(base, root=root), [])


if __name__ == "__main__":
    unittest.main()
