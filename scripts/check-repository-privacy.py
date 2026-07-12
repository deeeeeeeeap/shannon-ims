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

        if path.stat().st_size > 2_000_000:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if lower == "config/config.example.yaml" or lower.endswith("/files/config.yaml"):
            for match in re.finditer(r"(?im)^\s*password\s*:\s*['\"]?([^'\"#\r\n]+)", content):
                value = match.group(1).strip()
                if value and not value.startswith("CHANGE_ME"):
                    findings.append((relative, "weak_default_password"))
        for rule_name, pattern in CONTENT_RULES.items():
            if pattern.search(content):
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
