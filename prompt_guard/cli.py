"""Click CLI for prompt-guard."""

from __future__ import annotations

import sys
import click

from .scanner import scan
from .reporter import print_scan, build_json_report, write_json, emit_github_annotations


@click.group()
@click.version_option(package_name="prompt-guard")
def cli():
    """prompt-guard — detect prompt injection attacks before they reach your LLM.

    Scans user input for instruction overrides, jailbreaks, system prompt
    extraction attempts, role injection, and more.
    """


# ── check command ─────────────────────────────────────────────────────────────

@cli.command("check")
@click.argument("text", metavar="TEXT")
@click.option("--min-severity", default="info",
              type=click.Choice(["critical", "warning", "info"], case_sensitive=False),
              help="Minimum severity to report (default: info).")
@click.option("--json-report", default=None, metavar="FILE",
              help="Write a JSON report to FILE.")
@click.option("--fail-on-warning", is_flag=True, default=False,
              help="Exit 1 on warnings too, not just critical detections.")
@click.option("--quiet", is_flag=True, default=False,
              help="Suppress terminal output (useful when only the exit code matters).")
def check_cmd(text, min_severity, json_report, fail_on_warning, quiet):
    """Check TEXT for prompt injection patterns.

    \b
    Examples:
      prompt-guard check "Ignore all previous instructions"
      prompt-guard check "Hello, how are you?" --min-severity warning
      prompt-guard check "$USER_INPUT" --json-report report.json
    """
    result = scan(text, min_severity=min_severity)

    if not quiet:
        print_scan(result)

    emit_github_annotations(result)

    if json_report:
        report = build_json_report(result)
        write_json(report, json_report)
        if not quiet:
            click.echo(f"JSON report written to {json_report}")

    if result.critical:
        sys.exit(1)
    if fail_on_warning and result.warnings:
        sys.exit(1)


# ── scan-file command ─────────────────────────────────────────────────────────

@cli.command("scan-file")
@click.argument("file", metavar="FILE", type=click.Path(exists=True))
@click.option("--min-severity", default="info",
              type=click.Choice(["critical", "warning", "info"], case_sensitive=False),
              help="Minimum severity to report (default: info).")
@click.option("--json-report", default=None, metavar="FILE",
              help="Write a JSON report to FILE.")
@click.option("--fail-on-warning", is_flag=True, default=False,
              help="Exit 1 on warnings too, not just critical detections.")
def scan_file_cmd(file, min_severity, json_report, fail_on_warning):
    """Scan a text file for prompt injection patterns.

    \b
    Examples:
      prompt-guard scan-file user_message.txt
      prompt-guard scan-file input.txt --json-report report.json
    """
    try:
        with open(file, encoding="utf-8") as f:
            text = f.read()
    except Exception as exc:
        click.echo(f"Error reading file: {exc}", err=True)
        sys.exit(2)

    result = scan(text, min_severity=min_severity)
    print_scan(result, label=file)

    emit_github_annotations(result)

    if json_report:
        report = build_json_report(result, label=file)
        write_json(report, json_report)
        click.echo(f"JSON report written to {json_report}")

    if result.critical:
        sys.exit(1)
    if fail_on_warning and result.warnings:
        sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()
