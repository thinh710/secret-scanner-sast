#!/usr/bin/env python
from __future__ import annotations

import click
from pathlib import Path

from scanner.scanner import Scanner
from scanner.reporter import print_report, save_json, save_csv, save_html
from scanner.fix_advisor import save_guidance


@click.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option("--ignore", "-i", multiple=True, help="Additional ignore patterns (gitignore style)")
@click.option("--output", "-o", type=click.Path(), help="Output file (extension determines format if not specified)")
@click.option("--advice-out", type=click.Path(), help="Write fix guidance to a text file (optional)")
@click.option("--show-values", is_flag=True, help="Show unmasked values in output (DANGEROUS; use only for local testing)")
@click.option("--format", "fmt", type=click.Choice(["text", "json", "csv", "html"]), default=None, help="Output format")
@click.option("--sast/--no-sast", default=True, help="Enable/disable SAST scanning")
@click.option(
    "--severity-threshold",
    type=click.Choice(["Critical", "High", "Medium", "Low"]),
    default="Low",
    help="Minimum severity to report",
)
@click.option("--max-file-size-mb", type=int, default=5, show_default=True, help="Skip files larger than this size")
def scan(path, ignore, output, advice_out, show_values, fmt, sast, severity_threshold, max_file_size_mb):
    """Scan a directory for secrets and security vulnerabilities."""
    scanner = Scanner(path, ignore_patterns=list(ignore), include_sast=sast, max_file_size_mb=max_file_size_mb)
    findings = scanner.scan()

    # Filter by severity
    severity_levels = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    min_level = severity_levels[severity_threshold]
    findings = [f for f in findings if severity_levels.get(f.severity, 9) <= min_level]

    if fmt is None:
        if not output:
            fmt = "text"
        else:
            ext = Path(output).suffix.lower()
            fmt = {".json": "json", ".csv": "csv", ".html": "html", ".htm": "html"}.get(ext, "json")

    if fmt == "text":
        print_report(findings, show_values=show_values)
        if output:
            print("Text output cannot be saved to file. Use --format json/csv/html with --output.")
    elif fmt == "json":
        if not output:
            print("Error: --output required for JSON format")
            return
        save_json(findings, output, show_values=show_values)
    elif fmt == "csv":
        if not output:
            print("Error: --output required for CSV format")
            return
        save_csv(findings, output, show_values=show_values)
    elif fmt == "html":
        if not output:
            print("Error: --output required for HTML format")
            return
        save_html(findings, output, show_values=show_values)



    if show_values:
        click.echo("⚠️ WARNING: --show-values will export UNMASKED values. Use only with fake/test data.")
    if advice_out:
        save_guidance(findings, advice_out)
        print(f"📝 Fix guidance saved to {advice_out}")

if __name__ == "__main__":
    scan()
