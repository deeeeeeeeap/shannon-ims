from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "binary-release.yml"


def workflow_job(content: str, name: str) -> str:
    marker = f"  {name}:\n"
    start = content.index(marker)
    next_job = content.find("\n  ", start + len(marker))
    while next_job != -1:
        line_end = content.find("\n", next_job + 1)
        line = content[next_job + 1 : line_end if line_end != -1 else None]
        if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
            return content[start:next_job]
        next_job = content.find("\n  ", next_job + 1)
    return content[start:]


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

    def test_clean_checkout_go_validation_uses_built_frontend_assets(self) -> None:
        ci_content = WORKFLOW.read_text(encoding="utf-8")
        ci_go = workflow_job(ci_content, "go")
        self.assertIn("needs: frontend", ci_go)
        self.assertIn("uses: actions/download-artifact@v4", ci_go)
        self.assertIn("name: ci-web-dist", ci_go)
        self.assertIn("cp -R web/dist internal/web/dist", ci_go)
        self.assertLess(
            ci_go.index("cp -R web/dist internal/web/dist"),
            ci_go.index("go test ./... -count=1"),
        )

        release_content = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        release_frontend = workflow_job(release_content, "frontend")
        release_validate = workflow_job(release_content, "validate")
        release_build = workflow_job(release_content, "build")
        self.assertNotIn("needs: validate", release_frontend)
        self.assertIn("needs: frontend", release_validate)
        self.assertIn("uses: actions/download-artifact@v4", release_validate)
        self.assertIn("name: web-dist", release_validate)
        self.assertIn("cp -R web/dist internal/web/dist", release_validate)
        self.assertLess(
            release_validate.index("cp -R web/dist internal/web/dist"),
            release_validate.index("go test ./... -count=1"),
        )
        self.assertIn("needs: [frontend, validate]", release_build)


if __name__ == "__main__":
    unittest.main()
