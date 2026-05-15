"""Output formatters — terminal (coloured) and JSON."""

from __future__ import annotations

import datetime
import json
import os
import sys
from typing import Optional

from .scanner import ScanResult, Detection

# ── ANSI colours ──────────────────────────────────────────────────────────────

_NO_COLOR = not sys.stdout.isatty() or os.environ.get("NO_COLOR")

def _c(code: str, text: str) -> str:
    if _NO_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"

RED    = lambda t: _c("31;1", t)
YELLOW = lambda t: _c("33;1", t)
CYAN   = lambda t: _c("36;1", t)
GREEN  = lambda t: _c("32;1", t)
GRAY   = lambda t: _c("90",   t)
BOLD   = lambda t: _c("1",    t)
DIM    = lambda t: _c("2",    t)

SEP = GRAY("─" * 66)

_ICONS = {
    "critical": RED("🔴 [CRITICAL]"),
    "warning":  YELLOW("🟡 [WARNING] "),
    "info":     CYAN("🔵 [INFO]    "),
}

_RISK_LABEL = {
    "critical": RED("CRITICAL — do not send to LLM"),
    "warning":  YELLOW("WARNING  — review before sending"),
    "info":     CYAN("INFO     — low-risk pattern detected"),
    "safe":     GREEN("SAFE     — no injection detected"),
}


# ── Terminal report ───────────────────────────────────────────────────────────

def print_scan(result: ScanResult, label: Optional[str] = None):
    """Print a human-readable scan report to stdout."""
    src = label or _truncate(result.input_text, 60)

    print()
    print(BOLD("prompt-guard — Injection Scan Report"))
    print(GRAY(f"  Input : {src}"))
    print(SEP)
    print()

    if not result.detections:
        print(GREEN("  ✅  No injection patterns detected."))
        print()
    else:
        for det in result.detections:
            icon = _ICONS.get(det.severity, det.severity.upper())
            print(f"  {icon}  [{det.category}]")
            print(f"           {det.description}")
            print(DIM(f"           matched: {_truncate(det.matched_text, 70)!r}"))
            print()

    nc = len(result.critical)
    nw = len(result.warnings)
    ni = len(result.info)
    parts = []
    if nc: parts.append(RED(f"{nc} critical"))
    if nw: parts.append(YELLOW(f"{nw} warning(s)"))
    if ni: parts.append(CYAN(f"{ni} info"))
    summary = ", ".join(parts) if parts else GREEN("0 detections")

    print(SEP)
    print(f"  Total : {summary}")
    print(f"  Risk  : {_RISK_LABEL[result.risk_level]}")
    print()


# ── JSON report ───────────────────────────────────────────────────────────────

def build_json_report(result: ScanResult, label: Optional[str] = None) -> dict:
    return {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "input": label or result.input_text,
        "risk_level": result.risk_level,
        "is_injection": result.is_injection,
        "summary": {
            "critical": len(result.critical),
            "warnings": len(result.warnings),
            "info":     len(result.info),
            "total":    result.total,
        },
        "detections": [
            {
                "rule_id":      d.rule_id,
                "severity":     d.severity,
                "category":     d.category,
                "description":  d.description,
                "matched_text": d.matched_text,
            }
            for d in result.detections
        ],
    }


def write_json(report: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


# ── GitHub Actions annotations ────────────────────────────────────────────────

def emit_github_annotations(result: ScanResult):
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    for det in result.detections:
        level = {"critical": "error", "warning": "warning", "info": "notice"}.get(
            det.severity, "notice"
        )
        msg = det.description.replace("\n", " ").replace("%", "%25")
        title = f"{det.rule_id}: {det.category}"
        print(f"::{level} title={title}::{msg}", file=sys.stderr)


# ── helpers ───────────────────────────────────────────────────────────────────

def _truncate(text: str, max_len: int) -> str:
    text = text.replace("\n", " ").strip()
    if len(text) <= max_len:
        return text
    return text[:max_len - 1] + "…"
