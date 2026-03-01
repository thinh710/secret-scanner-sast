from __future__ import annotations

from pathlib import Path
import chardet

from .ignore import IgnoreFilter
from .rules import load_rules
from .utils import get_language_from_extension


class Finding:
    def __init__(
        self,
        file_path,
        line_number,
        matched_text,
        rule_name,
        confidence,
        severity,
        remediation,
        finding_type,
        rule_id=None,
    ):
        self.file_path = str(file_path)
        self.line_number = int(line_number)
        self.matched_text = matched_text or ""
        self.rule_name = rule_name
        self.rule_id = rule_id
        self.confidence = confidence
        self.severity = severity
        self.remediation = remediation
        self.finding_type = finding_type
        self.masked_text = self.mask(self.matched_text)

    @staticmethod
    def mask(text, visible=4):
        text = str(text or "")
        if len(text) <= visible * 2:
            return "*" * len(text)
        return text[:visible] + "*" * (len(text) - visible * 2) + text[-visible:]

    def to_dict(self, show_values: bool = False):
        base = {
            "file": self.file_path,
            "line": self.line_number,
            "masked": self.masked_text,
            "rule": self.rule_name,
            "rule_id": self.rule_id,
            "confidence": self.confidence,
            "severity": self.severity,
            "remediation": self.remediation,
            "type": self.finding_type,
        }


class Scanner:
    def __init__(self, path, ignore_patterns=None, rules_path=None, include_sast=True, max_file_size_mb=5):
        self.root = Path(path).resolve()
        self.ignore_filter = IgnoreFilter(self.root, ignore_patterns)
        self.rules = load_rules(rules_path)
        if not include_sast:
            self.rules = [r for r in self.rules if r.type != "sast"]
        self.max_file_size_bytes = int(max_file_size_mb) * 1024 * 1024
        self.findings = []

    def scan(self):
        for file_path in self.root.rglob("*"):
            if not file_path.is_file():
                continue
            if self.ignore_filter.is_ignored(file_path):
                continue
            try:
                if file_path.stat().st_size > self.max_file_size_bytes:
                    continue
            except Exception:
                continue
            self._scan_file(file_path)
        return self.findings

    def _scan_file(self, file_path):
        language = get_language_from_extension(file_path)

        try:
            with open(file_path, "rb") as f:
                raw = f.read(4096)
                if b"\x00" in raw:
                    return  # skip binary
                result = chardet.detect(raw)
                encoding = result.get("encoding") or "utf-8"
        except Exception:
            return

        try:
            with open(file_path, "r", encoding=encoding, errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return

        for i, line in enumerate(lines, start=1):
            if len(line) > 20000:
                continue
            for rule in self.rules:
                if rule.type == "sast":
                    if language not in rule.languages and "*" not in rule.languages:
                        continue
                matches = rule.match(line)
                for m in matches:
                    secret_text = m.get("secret_text") or m.get("text")
                    finding = Finding(
                        file_path=file_path,
                        line_number=i,
                        matched_text=secret_text,
                        rule_name=m["rule"],
                        confidence=m["confidence"],
                        severity=m["severity"],
                        remediation=m["remediation"],
                        finding_type=m["type"],
                        rule_id=m.get("rule_id"),
                    )
                    self.findings.append(finding)
