from __future__ import annotations

import json
import csv
from pathlib import Path
from jinja2 import Template


def print_report(findings, show_values: bool = False):
    if not findings:
        print("✅ No issues found.")
        return
    print(f"🔍 Found {len(findings)} potential issues:\n")
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings_sorted = sorted(findings, key=lambda f: severity_order.get(f.severity, 9))
    for f in findings_sorted:
        rid = f" [{f.rule_id}]" if getattr(f, "rule_id", None) else ""
        print(f"[{f.severity}] {f.rule_name}{rid} in {f.file_path}:{f.line_number} ({f.finding_type})")
        val = f.matched_text if show_values else f.masked_text
        print(f"    Value: {val}")
        if f.remediation:
            print(f"    Remediation: {f.remediation}")
    print()


def save_json(findings, output_path, show_values: bool = False):
    data = [f.to_dict(show_values=show_values) for f in findings]
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"📄 JSON report saved to {output_path}")


def save_csv(findings, output_path, show_values: bool = False):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Severity", "Type", "Rule", "RuleID", "File", "Line", "Masked Value", "Confidence", "Remediation"])
        for finding in findings:
            writer.writerow([
                finding.severity,
                finding.finding_type,
                finding.rule_name,
                getattr(finding, "rule_id", "") or "",
                finding.file_path,
                finding.line_number,
                (finding.matched_text if show_values else finding.masked_text),
                finding.confidence,
                finding.remediation,
            ])
    print(f"📄 CSV report saved to {output_path}")


def save_html(findings, output_path, show_values: bool = False):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 9))

    html_template = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Secret Scanner Report</title>
  <style>
    body { font-family: sans-serif; margin: 20px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
    th { background-color: #f2f2f2; position: sticky; top: 0; }
    .Critical { background-color: #ffcccc; }
    .High { background-color: #ffffcc; }
    .Medium { background-color: #e6ffe6; }
    .Low { background-color: #e6f3ff; }
    input { padding: 8px; width: 420px; margin-bottom: 12px; }
    code { font-family: Consolas, monospace; }
  </style>
</head>
<body>
  <h1>Secret Scanner Report</h1>
  <p>Found <b>{{ findings|length }}</b> issues ({% if show_values %}<b>VALUES UNMASKED</b>{% else %}values are masked{% endif %}).</p>
  <input id="q" placeholder="Filter..." oninput="filterRows()"/>
  <table id="t">
    <tr>
      <th>Severity</th><th>Type</th><th>Rule</th><th>RuleID</th><th>File</th><th>Line</th><th>Masked Value</th><th>Confidence</th><th>Remediation</th>
    </tr>
    {% for f in findings %}
    <tr class="{{ f.severity }}">
      <td>{{ f.severity }}</td>
      <td>{{ f.finding_type }}</td>
      <td>{{ f.rule_name }}</td>
      <td><code>{{ f.rule_id or "" }}</code></td>
      <td>{{ f.file_path }}</td>
      <td>{{ f.line_number }}</td>
      <td><code>{{ (f.matched_text if show_values else f.masked_text) }}</code></td>
      <td>{{ f.confidence }}</td>
      <td>{{ f.remediation }}</td>
    </tr>
    {% endfor %}
  </table>

<script>
function filterRows() {
  const q = document.getElementById('q').value.toLowerCase();
  document.querySelectorAll('#t tr').forEach((r, idx) => {
    if (idx === 0) return;
    r.style.display = r.innerText.toLowerCase().includes(q) ? '' : 'none';
  });
}
</script>
</body>
</html>
"""
    template = Template(html_template)
    html_content = template.render(findings=findings, show_values=show_values)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"📄 HTML report saved to {output_path}")
