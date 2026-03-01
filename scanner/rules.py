from __future__ import annotations

import json
import re
from pathlib import Path

from .utils import keyword_nearby, shannon_entropy


class Rule:
    def __init__(self, rule_dict: dict):
        self.id = rule_dict.get("id") or rule_dict.get("name", "rule").lower().replace(" ", "_")
        self.type = rule_dict.get("type", "secret")
        self.name = rule_dict["name"]
        self.pattern = re.compile(rule_dict["pattern"], re.IGNORECASE)
        self.confidence = rule_dict.get("confidence", "Medium")
        self.severity = rule_dict.get("severity", "Medium")
        self.remediation = rule_dict.get("remediation", "")
        self.languages = rule_dict.get("language", ["*"])
        self.keywords = rule_dict.get("keywords", [])
        self.entropy_threshold = rule_dict.get("entropy_threshold")
        self.min_length = int(rule_dict.get("min_length", 0) or 0)
        self.capture_group = rule_dict.get("capture_group")
        self.proximity_window = int(rule_dict.get("proximity_window", 120) or 120)

    def match(self, line: str):
        matches = []
        for m in self.pattern.finditer(line):
            full_text = m.group(0)

            # choose secret text (mask only secret part)
            secret_text = full_text
            if self.capture_group is not None:
                try:
                    secret_text = m.group(int(self.capture_group)) or full_text
                    start = m.start(int(self.capture_group))
                    end = m.end(int(self.capture_group))
                except Exception:
                    start, end = m.start(), m.end()
            else:
                start, end = m.start(), m.end()

            if self.min_length and len(secret_text) < self.min_length:
                continue

            if self.entropy_threshold is not None:
                ent = shannon_entropy(secret_text)
                if ent < float(self.entropy_threshold):
                    continue

            if self.keywords:
                if not keyword_nearby(line, self.keywords, start, end, window=self.proximity_window):
                    continue

            matches.append({
                "start": start,
                "end": end,
                "text": full_text,
                "secret_text": secret_text,
                "rule": self.name,
                "rule_id": self.id,
                "confidence": self.confidence,
                "severity": self.severity,
                "remediation": self.remediation,
                "type": self.type,
            })
        return matches


def load_rules(rules_path=None):
    if rules_path is None:
        rules_path = Path(__file__).parent.parent / "config" / "rules.json"
    with open(rules_path, "r", encoding="utf-8") as f:
        rules_data = json.load(f)
    return [Rule(r) for r in rules_data]
