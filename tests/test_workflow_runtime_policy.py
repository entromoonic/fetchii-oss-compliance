from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_policy():
    path = ROOT / "scripts" / "check_compliance.py"
    spec = importlib.util.spec_from_file_location("runtime_check_compliance", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


check_compliance = load_policy()


class WorkflowRuntimePolicyTests(unittest.TestCase):
    def test_offline_policy_timeout_is_exact_and_fail_closed(self) -> None:
        source = (ROOT / check_compliance.POLICY_WORKFLOW).read_text(encoding="utf-8")
        self.assertIn("    timeout-minutes: 10\n", source)
        for label, mutated in (
            ("removed", source.replace("    timeout-minutes: 10\n", "", 1)),
            (
                "relaxed",
                source.replace(
                    "    timeout-minutes: 10\n",
                    "    timeout-minutes: 360\n",
                    1,
                ),
            ),
        ):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                workflow = root / check_compliance.POLICY_WORKFLOW
                workflow.parent.mkdir(parents=True)
                workflow.write_text(mutated, encoding="utf-8")
                errors = check_compliance.workflow_policy_errors(root=root)
                self.assertTrue(
                    any("timeout must remain exactly 10 minutes" in error for error in errors),
                    errors,
                )


if __name__ == "__main__":
    unittest.main()
