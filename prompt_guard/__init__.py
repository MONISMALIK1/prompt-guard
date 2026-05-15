"""prompt-guard — detect prompt injection attacks before they reach your LLM."""

__version__ = "0.1.0"

from .scanner import scan, scan_batch, ScanResult, Detection
from .patterns import RULES, Rule

__all__ = [
    "scan",
    "scan_batch",
    "ScanResult",
    "Detection",
    "RULES",
    "Rule",
]
