"""
Detection rules for prompt injection attacks.

Each rule is a dict with:
  rule_id    : str   — unique machine-readable identifier
  severity   : str   — "critical" | "warning" | "info"
  category   : str   — human label for the attack class
  pattern    : str   — regex (case-insensitive, applied to normalised input)
  description: str   — human-readable explanation shown in report
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Rule:
    rule_id: str
    severity: str        # "critical" | "warning" | "info"
    category: str
    pattern: str
    description: str
    _compiled: Optional[re.Pattern] = None

    def compile(self) -> re.Pattern:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, re.IGNORECASE | re.DOTALL)
        return self._compiled

    def match(self, text: str) -> Optional[re.Match]:
        return self.compile().search(text)


# ── Rule definitions ──────────────────────────────────────────────────────────

RULES: List[Rule] = [

    # ── 1. Instruction override ────────────────────────────────────────────────
    Rule(
        rule_id="INSTRUCTION_OVERRIDE",
        severity="critical",
        category="Instruction Override",
        pattern=(
            r"ignore\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|context|rules?|constraints?)"
            r"|disregard\b.{0,20}\b(instructions?|prompts?|context|rules?)"
            r"|forget\s+(everything|all|what|your)\s*(you\s*(were|have|was))?(told|said|instructed|know)?"
            r"|override\s+(your\s+)?(instructions?|system\s+prompt|programming|directives?)"
            r"|do\s+not\s+follow\s+(your\s+)?(previous|prior|original)\s+(instructions?|rules?)"
        ),
        description="Attempts to override or nullify the system prompt or prior instructions.",
    ),

    # ── 2. Role injection ──────────────────────────────────────────────────────
    Rule(
        rule_id="ROLE_INJECTION",
        severity="critical",
        category="Role Injection",
        pattern=(
            r"you\s+are\s+now\s+(?!an?\s+(assistant|helper|chatbot))"
            r"|act\s+as\s+(a\s+|an\s+)?(different|new|another|evil|unfiltered|unrestricted|uncensored)"
            r"|pretend\s+(you\s+are|to\s+be)\s+(a\s+|an\s+)?"
            r"|your\s+(new\s+)?(role|persona|identity|name|purpose)\s+is"
            r"|from\s+now\s+on\s+(you\s+are|act\s+as|you\s+will\s+be)"
            r"|roleplay\s+as\s+(a\s+|an\s+)?(hacker|evil|malicious|unethical)"
            r"|switch\s+(your\s+)?(mode|role|persona)\s+to"
        ),
        description="Attempts to reassign the model's role, persona, or identity.",
    ),

    # ── 3. System prompt extraction ────────────────────────────────────────────
    Rule(
        rule_id="SYSTEM_PROMPT_LEAK",
        severity="critical",
        category="System Prompt Extraction",
        pattern=(
            r"(output|print|repeat|reveal|show|tell\s+me|display|share|dump)(\s+me)?\s+"
            r"(your\s+)?(system\s+prompt|initial\s+instructions?|original\s+prompt|full\s+prompt|base\s+prompt|hidden\s+prompt)"
            r"|what\s+(are\s+your\s+|were\s+you\s+)(instructions?|told|programmed|trained|given)"
            r"|repeat\s+(everything|all|the\s+text)\s+(above|before|prior)"
            r"|show\s+me\s+what\s+you\s+(were\s+told|have\s+been\s+instructed)"
        ),
        description="Attempts to extract or reveal the system prompt or hidden instructions.",
    ),

    # ── 4. Jailbreak patterns ──────────────────────────────────────────────────
    Rule(
        rule_id="JAILBREAK",
        severity="critical",
        category="Jailbreak",
        pattern=(
            r"\bDAN\b"                                  # Do Anything Now
            r"|\bdo\s+anything\s+now\b"
            r"|\bdeveloper\s+mode\b"
            r"|\bjailbreak\b"
            r"|\bunfiltered\s+(mode|response|output)"
            r"|\bno\s+restrictions?\b"
            r"|\bbypass\s+(your\s+)?(safety|filters?|restrictions?|guidelines?|rules?)"
            r"|\bdisable\s+(your\s+)?(safety|filters?|restrictions?|content\s+policy)"
            r"|\bunlock\s+(your\s+)?(full|true|real|unrestricted)\s+(potential|capabilities?|mode)"
        ),
        description="Classic jailbreak technique attempting to bypass model safety guidelines.",
    ),

    # ── 5. Indirect injection (delimiter attacks) ──────────────────────────────
    Rule(
        rule_id="DELIMITER_INJECTION",
        severity="critical",
        category="Delimiter Injection",
        pattern=(
            r"<\|?(system|user|assistant|im_start|im_end)\|?>"    # OpenAI/Qwen tokens
            r"|\[INST\]|\[/INST\]"                                 # Llama tokens
            r"|<</SYS>>|<<SYS>>"                                   # Llama system tags
            r"|\[SYSTEM\]|\[USER\]|\[ASSISTANT\]"
            r"|###\s*(System|Instruction|Prompt|Human|Assistant)"
            r"|\bHUMAN:\s*\n|\bASSISTANT:\s*\n|\bSYSTEM:\s*\n"
        ),
        description="Injects model-specific delimiter tokens to manipulate conversation structure.",
    ),

    # ── 6. Data / credential exfiltration ─────────────────────────────────────
    Rule(
        rule_id="DATA_EXFILTRATION",
        severity="critical",
        category="Data Exfiltration",
        pattern=(
            r"(send|email|post|upload|transmit|exfiltrate|leak|expose)\b.{0,20}\b(user\s+data|database|credentials?|api\s+keys?|passwords?|secrets?|tokens?|private\s+data)"
            r"|(print|output|reveal|show)\b.{0,20}\b(database\s+contents?|stored\s+data|user\s+records?|api\s+keys?)"
            r"|access\s+(the\s+)?(database|file\s+system|environment\s+variables?|secrets?)"
        ),
        description="Attempts to extract sensitive data, credentials, or access internal resources.",
    ),

    # ── 7. Prompt termination / context escape ─────────────────────────────────
    Rule(
        rule_id="CONTEXT_ESCAPE",
        severity="warning",
        category="Context Escape",
        pattern=(
            r"---+\s*(end|stop|terminate|new\s+prompt|reset)"
            r"|\*{3,}\s*(end|stop|reset)"
            r"|={3,}\s*(end|stop|new\s+session)"
            r"|\[END\s+OF\s+(PROMPT|CONTEXT|INSTRUCTION)\]"
            r"|\bstart\s+(a\s+)?(new|fresh|clean)\s+(conversation|session|context|chat)\b"
            r"|\breset\s+(your\s+)?(context|memory|conversation|chat)\b"
        ),
        description="Attempts to terminate the current context and start a fresh unconstrained session.",
    ),

    # ── 8. Authority impersonation ─────────────────────────────────────────────
    Rule(
        rule_id="AUTHORITY_IMPERSONATION",
        severity="warning",
        category="Authority Impersonation",
        pattern=(
            r"(i\s+am|this\s+is)\s+(your\s+)?(developer|creator|admin|administrator|anthropic|openai|google|owner|operator)"
            r"|(as\s+your\s+|i'm\s+your\s+)(developer|creator|admin|administrator|owner|operator)"
            r"|\bspecial\s+(admin|developer|override|maintenance)\s+(mode|access|command|token)\b"
            r"|\bauthorized\s+(by|from)\s+(anthropic|openai|google|the\s+developer)"
        ),
        description="Impersonates the model's creator or administrator to claim elevated permissions.",
    ),

    # ── 9. Objective hijacking ─────────────────────────────────────────────────
    Rule(
        rule_id="OBJECTIVE_HIJACK",
        severity="warning",
        category="Objective Hijacking",
        pattern=(
            r"your\s+(real|true|actual|primary|only)\s+(purpose|goal|objective|task|job|mission)\s+is"
            r"|\binstead\s+of\s+.{0,40}(you\s+should|your\s+job\s+is|focus\s+on)"
            r"|\bstop\s+(being|acting\s+as)\s+a\s+(helpful|useful|safe|harmless)"
            r"|\bforget\s+(being|that\s+you\s+are)\s+a\s+(helpful|useful|safe|harmless|assistant)"
        ),
        description="Attempts to replace or override the model's stated objective.",
    ),

    # ── 10. Encoded / obfuscated instructions ──────────────────────────────────
    Rule(
        rule_id="ENCODED_INJECTION",
        severity="warning",
        category="Encoded Injection",
        pattern=(
            r"base64[:\s]+[A-Za-z0-9+/]{20,}={0,2}"   # Base64 encoded payload
            r"|decode\s+(this|the\s+following)\s+(base64|hex|rot13|caesar)"
            r"|rot13\s*[:(\s]"
            r"|(run|execute|eval)\s+(this|the\s+following)\s*(code|script|command|payload)"
        ),
        description="Uses encoding or obfuscation to hide injection payloads from filters.",
    ),

    # ── 11. Prompt leaking via translation ────────────────────────────────────
    Rule(
        rule_id="TRANSLATION_LEAK",
        severity="info",
        category="Translation / Indirect Leak",
        pattern=(
            r"translate\s+(your\s+)?(system\s+prompt|instructions?|rules?)\s+to"
            r"|summarize\s+(your\s+)?(system\s+prompt|initial\s+instructions?|original\s+context)"
            r"|paraphrase\s+(your\s+)?(instructions?|system\s+prompt)"
        ),
        description="Attempts to extract prompt contents indirectly via translation or summarisation.",
    ),
]


def get_rules_by_severity(severity: str) -> List[Rule]:
    return [r for r in RULES if r.severity == severity]
