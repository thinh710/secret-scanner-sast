from __future__ import annotations

from collections import defaultdict
from typing import Iterable


def generate_guidance(findings: Iterable) -> list[str]:
    findings = list(findings)
    if not findings:
        return ["✅ No issues found. Nothing to fix."]

    lines: list[str] = []
    lines.append("🛠️ FIX GUIDANCE (Secrets + SAST)")
    lines.append("")
    lines.append("Priority order:")
    lines.append("1) Critical  2) High  3) Medium  4) Low")
    lines.append("")
    lines.append("General steps:")
    lines.append("• Fix the root cause in code/config.")
    lines.append("• Re-scan to confirm.")
    lines.append("• If any real secret was exposed: rotate/revoke immediately.")
    lines.append("• If pushed to remote: consider cleaning git history AFTER rotating secrets.")
    lines.append("")

    by_type = defaultdict(int)
    by_rule = defaultdict(int)
    for f in findings:
        by_type[getattr(f, "finding_type", "unknown")] += 1
        by_rule[getattr(f, "rule_name", "unknown")] += 1

    if by_type.get("secret"):
        lines.append("Secrets leakage – recommended fixes:")
        lines.append("• Move secrets out of source code into environment variables (.env) or a secrets manager.")
        lines.append("• Add .env to .gitignore and commit only a .env.example template.")
        lines.append("• Rotate/revoke exposed tokens/keys (GitHub/AWS/Slack/DB).")
        lines.append("")

    if by_type.get("sast"):
        lines.append("SAST findings (code risk patterns) – recommended fixes:")
        rules_lc = " | ".join(k.lower() for k in by_rule.keys())
        if "sql injection" in rules_lc or "sqli" in rules_lc:
            lines.append("• Injection (SQL): use parameterized queries / prepared statements. Never concatenate user input into SQL.")
        if "command injection" in rules_lc or "exec" in rules_lc or "system" in rules_lc:
            lines.append("• Injection (Command): avoid shell execution with user input; pass arguments as arrays; validate/allowlist inputs; avoid `shell=True`.")
        if "insecure file upload" in rules_lc:
            lines.append("• File upload: allowlist extensions/MIME, limit size, store outside webroot, rename files safely, disable execute permissions, scan uploads.")
        if "hardcoded password" in rules_lc:
            lines.append("• Hardcoded creds: remove from code; load via env/secret manager; rotate credentials if previously exposed.")
        lines.append("")

    lines.append("Per-finding checklist:")
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings_sorted = sorted(findings, key=lambda f: sev_order.get(getattr(f, "severity", "Medium"), 9))
    for f in findings_sorted:
        loc = f"{f.file_path}:{f.line_number}"
        lines.append(f"- [{f.severity}] {f.rule_name} ({f.finding_type}) @ {loc}")
        rem = (getattr(f, "remediation", "") or "").strip()
        if rem:
            lines.append(f"  Fix: {rem}")
        else:
            lines.append("  Fix: Review this code path and apply least-privilege + input validation + secure defaults.")
    lines.append("")
    return lines


def save_guidance(findings: Iterable, output_path: str) -> None:
    lines = generate_guidance(findings)
    with open(output_path, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln + "\n")
