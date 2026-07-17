from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "binary-release.yml"


class CIWorkflowContractTest(unittest.TestCase):
    def test_release_candidate_validation_matrix_is_present(self) -> None:
        content = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "push:",
            "pull_request:",
            "go test ./... -count=1",
            "go vet ./...",
            "go test -race",
            "./internal/vowifi/ipsec3gpp",
            "npm ci --prefix web",
            "npm run lint --prefix web",
            "npm run typecheck --prefix web",
            "npm run build --prefix web",
            "python3 scripts/check-repository-privacy.py",
            "bash scripts/tests/check-runtime-deps_test.sh",
            "bash scripts/verify-release-bundle.sh",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, content)

    def test_ci_has_read_only_repository_permissions(self) -> None:
        content = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", content)

    def test_release_workflow_uses_the_same_full_validation_contract(self) -> None:
        content = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        for fragment in (
            "go test ./... -count=1",
            "go vet ./...",
            "go test -race",
            "npm run lint --prefix web",
            "npm run typecheck --prefix web",
            "bash scripts/verify-release-bundle.sh",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, content)
        self.assertNotIn("-skip", content)


if __name__ == "__main__":
    unittest.main()
