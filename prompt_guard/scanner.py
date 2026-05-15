"""
Core scanning engine.

Takes a text string (user input) and returns a ScanResult with all
detected injection patterns.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import List, Optional

from .patterns import RULES, Rule


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class Detection:
    rule_id: str
    severity: str        # "critical" | "warning" | "info"
    category: str
    description: str
    matched_text: str    # the specific substring that triggered the rule
    start: int           # character offset in normalised input
    end: int


@dataclass
class ScanResult:
    input_text: str
    normalised_text: str
    detections: List[Detection] = field(default_factory=list)

    # ── Convenience accessors ─────────────────────────────────────────────────

    @property
    def critical(self) -> List[Detection]:
        return [d for d in self.detections if d.severity == "critical"]

    @property
    def warnings(self) -> List[Detection]:
        return [d for d in self.detections if d.severity == "warning"]

    @property
    def info(self) -> List[Detection]:
        return [d for d in self.detections if d.severity == "info"]

    @property
    def is_injection(self) -> bool:
        """True if any critical or warning detections were found."""
        return bool(self.critical or self.warnings)

    @property
    def is_safe(self) -> bool:
        return not self.is_injection

    @property
    def risk_level(self) -> str:
        if self.critical:
            return "critical"
        if self.warnings:
            return "warning"
        if self.info:
            return "info"
        return "safe"

    @property
    def total(self) -> int:
        return len(self.detections)


# ── Normalisation ─────────────────────────────────────────────────────────────

_UNICODE_HOMOGLYPHS = str.maketrans({
    # Common zero-width / invisible characters
    "​": "",   # zero width space
    "‌": "",   # zero width non-joiner
    "‍": "",   # zero width joiner
    "⁠": "",   # word joiner
    "﻿": "",   # BOM
    "­": "",   # soft hyphen
    # Lookalike letter substitutions (common in bypass attempts)
    "ⅰ": "i", "ⅼ": "l", "ⅽ": "c",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",   # Cyrillic
    "і": "i", "ј": "j",
})


def _normalise(text: str) -> str:
    """
    Normalise input to defeat simple obfuscation:
    - Strip zero-width and invisible characters
    - Collapse unicode homoglyphs to ASCII equivalents
    - Normalise whitespace (but preserve newlines for context)
    - NFC unicode normalisation
    """
    text = unicodedata.normalize("NFC", text)
    text = text.translate(_UNICODE_HOMOGLYPHS)
    # Collapse runs of spaces/tabs but keep newlines
    text = re.sub(r"[^\S\n]+", " ", text)
    return text


# ── Scanner ───────────────────────────────────────────────────────────────────

def scan(
    text: str,
    *,
    min_severity: str = "info",
    rules: Optional[List[Rule]] = None,
) -> ScanResult:
    """
    Scan *text* for prompt injection patterns.

    Parameters
    ----------
    text : str
        The user-supplied text to scan (e.g. a chat message, form input).
    min_severity : str
        Minimum severity to include in results. One of "critical", "warning",
        "info". Defaults to "info" (include everything).
    rules : list[Rule] | None
        Custom rule set. Defaults to the built-in RULES.

    Returns
    -------
    ScanResult
    """
    _severity_order = {"critical": 0, "warning": 1, "info": 2}
    min_rank = _severity_order.get(min_severity, 2)

    normalised = _normalise(text)
    active_rules = rules if rules is not None else RULES
    seen_rule_ids: set = set()
    detections: List[Detection] = []

    for rule in active_rules:
        if _severity_order.get(rule.severity, 2) > min_rank:
            continue

        for m in rule.compile().finditer(normalised):
            # Deduplicate: only report a rule once per scan
            if rule.rule_id in seen_rule_ids:
                break
            seen_rule_ids.add(rule.rule_id)

            detections.append(Detection(
                rule_id=rule.rule_id,
                severity=rule.severity,
                category=rule.category,
                description=rule.description,
                matched_text=m.group(0).strip(),
                start=m.start(),
                end=m.end(),
            ))
            break   # one detection per rule per scan

    # Sort: critical first, then warning, then info
    detections.sort(key=lambda d: _severity_order.get(d.severity, 2))

    return ScanResult(
        input_text=text,
        normalised_text=normalised,
        detections=detections,
    )


def scan_batch(texts: List[str], **kwargs) -> List[ScanResult]:
    """Scan a list of texts. Returns one ScanResult per input."""
    return [scan(t, **kwargs) for t in texts]
