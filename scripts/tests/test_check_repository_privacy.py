from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check-repository-privacy.py"
SPEC = importlib.util.spec_from_file_location("repository_privacy", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
repository_privacy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repository_privacy)


class RepositoryPrivacyRulesTest(unittest.TestCase):
    def findings(self, relative: str, content: str) -> set[str]:
        return set(repository_privacy.content_findings(relative, content))

    def test_rejects_web_password_as_session_hmac_key(self) -> None:
        rules = self.findings(
            "internal/api/server.go",
            'h := hmac.New(sha256.New, []byte(s.auth.Password))',
        )
        self.assertIn("session_hmac_uses_web_password", rules)

    def test_rejects_weak_web_password_default(self) -> None:
        rules = self.findings(
            "internal/config/config.go",
            'viper.SetDefault("web.password", "admin")',
        )
        self.assertIn("weak_web_password_default", rules)

    def test_rejects_raw_ims_authentication_log_fields(self) -> None:
        rules = self.findings(
            "vowifi-go/internal/vowifi/imscore/register.go",
            'logger.String("auts", result.AUTS)',
        )
        self.assertIn("ims_sensitive_log_field", rules)

    def test_accepts_ims_diagnostic_metadata(self) -> None:
        rules = self.findings(
            "vowifi-go/internal/vowifi/imscore/register.go",
            "\n".join(
                [
                    'logger.Int("challenge_round", round)',
                    'logger.Int("auts_len", len(result.AUTS))',
                    'logger.Bool("auts_present", true)',
                    'logger.String("nonce_fingerprint", fingerprint)',
                ]
            ),
        )
        self.assertNotIn("ims_sensitive_log_field", rules)

    def test_rejects_runtime_raw_log_bypass(self) -> None:
        rules = self.findings(
            "pkg/logger/sensitive.go",
            'return envEnabled("VOHIVE_SIP_LOG_RAW")',
        )
        self.assertIn("raw_log_runtime_bypass", rules)

    def test_rejects_raw_aka_hex_output_in_probe(self) -> None:
        rules = self.findings(
            "cmd/mbimprobe/main.go",
            'fmt.Printf("AKA response: %X\\n", resp)',
        )
        self.assertIn("aka_material_output", rules)

    def test_runtime_bypass_fixture_is_allowed_in_tests(self) -> None:
        rules = self.findings(
            "pkg/logger/sensitive_test.go",
            't.Setenv("VOHIVE_SIP_LOG_RAW", "true")',
        )
        self.assertNotIn("raw_log_runtime_bypass", rules)

    def test_rejects_raw_identity_log_fields_in_sms_pipeline(self) -> None:
        for relative in (
            "internal/device/incoming_sms_pipeline.go",
            "internal/device/sms_send.go",
            "internal/modem/sms_inbox.go",
        ):
            with self.subTest(relative=relative):
                rules = self.findings(
                    relative,
                    'logger.Info("stored", "sender", sender, "content", text)',
                )
                self.assertIn("sensitive_profile_log_field", rules)

    def test_accepts_sms_pipeline_diagnostic_metadata(self) -> None:
        rules = self.findings(
            "internal/device/sms_send.go",
            'logger.Info("sent", "to_fingerprint", logger.Fingerprint(to), "parts", parts)',
        )
        self.assertNotIn("sensitive_profile_log_field", rules)

    def test_profile_log_rule_only_names_files_that_exist(self) -> None:
        # A path that no longer exists would leave the code that replaced it
        # outside the rule without anyone noticing.
        for relative in sorted(repository_privacy.PROFILE_LOG_PATHS):
            with self.subTest(relative=relative):
                self.assertTrue((repository_privacy.ROOT / relative).is_file())


if __name__ == "__main__":
    unittest.main()
