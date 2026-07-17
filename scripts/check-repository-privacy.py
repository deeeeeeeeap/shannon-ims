#!/usr/bin/env python3
"""Fail when publishable files contain common private artifacts or secrets."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", "node_modules", "dist", "__pycache__"}
FORBIDDEN_SUFFIXES = {
    ".db", ".sqlite", ".sqlite3", ".log", ".trace", ".dump",
    ".pcap", ".pcapng", ".har", ".pem", ".key", ".p12", ".pfx",
}
CONTENT_RULES = {
    "carrier_private_label": re.compile("vo" + "xi", re.IGNORECASE),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    "credential_in_url": re.compile(r"https?://[^\s/:]+:[^\s/@]+@"),
}

SESSION_HMAC_PASSWORD_RE = re.compile(
    r"hmac\.New\([^,\n]+,\s*\[\]byte\([^\n)]*\.Password\)\)"
)
WEAK_WEB_PASSWORD_DEFAULT_RE = re.compile(
    r"SetDefault\(\s*[\"']web\.password[\"']\s*,\s*[\"']admin[\"']\s*\)"
)
RAW_LOG_RUNTIME_BYPASS_RE = re.compile(
    r"VOHIVE_(?:SIP_LOG_RAW|SMS_LOG_CONTENT)"
)
IMS_SENSITIVE_LOG_FIELD_RE = re.compile(
    r"logger\.(?:String|Any|Binary)\(\s*[\"']"
    r"(?:authorization|initial_authorization|rand|autn|auts|res|xres|ck|ik|nonce|"
    r"route|request_uri|destination|content|pdu|payload|imsi|imei|iccid|phone|number|token)"
    r"[\"']"
)
PROFILE_SENSITIVE_LOG_FIELD_RE = re.compile(
    r"[\"'](?:imsi|imei|iccid|sender|content|pdu)[\"']\s*,"
)
AKA_MATERIAL_OUTPUT_RE = re.compile(
    r"fmt\.Printf\([^\n]*%[^\s\"']*[xX][^\n]*,\s*"
    r"(?:apdu|resp|rand\w*|autn\w*|auts\w*|res\w*|ck|ik|sres|kc)\b"
)

IMS_LOG_PATH_PREFIXES = (
    "vowifi-go/internal/vowifi/imscore/",
    "vowifi-go/runtimehost/voiceclient/",
)
PROFILE_LOG_PATHS = {
    "internal/device/vowifi_start_profile.go",
    "internal/modem/manager.go",
    "internal/sms/poller.go",
}


def content_findings(relative: str, content: str) -> list[str]:
    """Return privacy rule names for one UTF-8 source file."""
    findings: list[str] = []
    lower = relative.lower()
    is_go = lower.endswith(".go")
    is_test = lower.endswith("_test.go") or "/tests/" in lower

    if lower == "config/config.example.yaml" or lower.endswith("/files/config.yaml"):
        for match in re.finditer(
            r"(?im)^\s*password\s*:\s*['\"]?([^'\"#\r\n]+)", content
        ):
            value = match.group(1).strip()
            if value and not value.startswith("CHANGE_ME"):
                findings.append("weak_default_password")

    for rule_name, pattern in CONTENT_RULES.items():
        if pattern.search(content):
            findings.append(rule_name)

    if is_go and SESSION_HMAC_PASSWORD_RE.search(content):
        findings.append("session_hmac_uses_web_password")
    if is_go and WEAK_WEB_PASSWORD_DEFAULT_RE.search(content):
        findings.append("weak_web_password_default")
    if is_go and not is_test and RAW_LOG_RUNTIME_BYPASS_RE.search(content):
        findings.append("raw_log_runtime_bypass")
    if is_go and lower.startswith(IMS_LOG_PATH_PREFIXES) and IMS_SENSITIVE_LOG_FIELD_RE.search(content):
        findings.append("ims_sensitive_log_field")
    if is_go and lower in PROFILE_LOG_PATHS and PROFILE_SENSITIVE_LOG_FIELD_RE.search(content):
        findings.append("sensitive_profile_log_field")
    if lower == "cmd/mbimprobe/main.go" and AKA_MATERIAL_OUTPUT_RE.search(content):
        findings.append("aka_material_output")

    return sorted(set(findings))


def candidate_files() -> list[Path]:
    try:
        output = subprocess.check_output(
            ["git", "ls-files", "-co", "--exclude-standard"],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
        )
        return [ROOT / line for line in output.splitlines() if line]
    except (OSError, subprocess.CalledProcessError):
        return [
            path
            for path in ROOT.rglob("*")
            if path.is_file() and not any(part in SKIP_PARTS for part in path.parts)
        ]


def scan() -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for path in candidate_files():
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT).as_posix()
        lower = relative.lower()
        name_lower = path.name.lower()

        if lower == "config/config.yaml":
            findings.append((relative, "runtime_config"))
        top_level = lower.split("/", 1)[0]
        if top_level in {"data", "logs"}:
            findings.append((relative, "runtime_state"))
        if name_lower == ".env" or name_lower.startswith(".env."):
            findings.append((relative, "environment_file"))
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            findings.append((relative, "private_artifact"))
        if name_lower in {"session-secret", ".shannon-ims-session-secret"}:
            findings.append((relative, "runtime_secret"))

        if path.stat().st_size > 2_000_000:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for rule_name in content_findings(relative, content):
            findings.append((relative, rule_name))
    return sorted(set(findings))


def main() -> int:
    findings = scan()
    if findings:
        for path, rule in findings:
            print(f"privacy_check_failed file={path} rule={rule}")
        return 1
    print("privacy_check_passed=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
