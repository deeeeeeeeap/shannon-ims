from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "binary-release.yml"
README = ROOT / "README.md"
RELEASE_CHECKLIST = ROOT / "RELEASE_CHECKLIST.md"


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

    def test_local_swu_module_has_test_race_and_vet_gates(self) -> None:
        swu_test_step = """      - name: SWu module tests
        working-directory: third_party/swu-go
        run: go test ./... -count=1"""
        swu_vet_step = """      - name: SWu module vet
        working-directory: third_party/swu-go
        run: go vet ./..."""
        swu_race_step = """      - name: SWu critical race tests
        working-directory: third_party/swu-go
        run: >-
          go test -race
          ./pkg/crypto
          ./pkg/ikev2
          ./pkg/ipsec
          ./pkg/swu
          -count=1"""

        ci_content = WORKFLOW.read_text(encoding="utf-8")
        ci_go = workflow_job(ci_content, "go")
        ci_race = workflow_job(ci_content, "race")
        self.assertIn(swu_test_step, ci_go)
        self.assertIn(swu_vet_step, ci_go)
        self.assertIn(swu_race_step, ci_race)
        self.assertIn("third_party/swu-go/go.sum", ci_go)
        self.assertIn("third_party/swu-go/go.sum", ci_race)

        release_content = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        release_validate = workflow_job(release_content, "validate")
        self.assertIn(swu_test_step, release_validate)
        self.assertIn(swu_vet_step, release_validate)
        self.assertIn(swu_race_step, release_validate)
        self.assertIn("third_party/swu-go/go.sum", release_validate)

    def test_documented_local_validation_includes_swu_module(self) -> None:
        readme = README.read_text(encoding="utf-8")
        for fragment in (
            "(cd third_party/swu-go && go test ./... -count=1)",
            "(cd third_party/swu-go && go vet ./...)",
            "(cd third_party/swu-go && go test -race \\",
        ):
            with self.subTest(fragment=fragment):
                if fragment not in readme:
                    self.fail(f"README missing local validation command: {fragment}")

        checklist = RELEASE_CHECKLIST.read_text(encoding="utf-8")
        if "third_party/swu-go" not in checklist:
            self.fail("release checklist does not name the local swu-go module")
        if "all three Go modules" not in checklist:
            self.fail("release checklist does not require all three Go modules")

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
