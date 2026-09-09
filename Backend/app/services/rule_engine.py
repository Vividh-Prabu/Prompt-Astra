"""Explainable, local rules for common prompt-security threats."""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class RuleAnalysis:
    rule_score: float
    threat_category: str
    reason: str


RULES: tuple[tuple[str, float, tuple[str, ...]], ...] = (
    (
        "Malicious Instructions",
        0.95,
        (
            r"\b(?:steal|exfiltrate)\b.*\b(?:passwords?|credentials?|tokens?|bank details)\b",
            r"\b(?:create|write|develop)\b.*\b(?:malware|ransomware|keylogger|phishing)\b",
            r"\b(?:bypass|disable)\b.*\b(?:authentication|security controls?)\b",
            r"\b(?:delete|destroy|encrypt)\b.*\b(?:all )?(?:files|data|database)\b",
        ),
    ),
    (
        "Jailbreak Attempt",
        0.95,
        (
            r"\b(?:you are now )?dan\b",
            r"\bdo anything now\b",
            r"\b(?:unrestricted|uncensored) ai\b",
            r"\b(?:disable|remove|bypass)\b.*\b(?:safety|restrictions?|guardrails?)\b",
            r"\bpretend (?:you are|to be) unrestricted\b",
        ),
    ),
    (
        "System Prompt Extraction",
        0.90,
        (
            r"\b(?:reveal|show|display|print|tell me)\b.*\b(?:system prompt|system message|system instructions|hidden instructions?)\b",
            r"\bwhat (?:are|is) your (?:system prompt|system instructions|hidden rules)\b",
        ),
    ),
    (
        "Instruction Override",
        0.90,
        (
            r"\b(?:ignore|disregard|forget)\b.*\b(?:previous|earlier|prior|system)\b.*\b(?:instructions?|rules?|message)\b",
            r"\b(?:follow|obey)\b.*\b(?:only )?my instructions\b",
            r"\boverride\b.*\b(?:system|instructions?|rules?)\b",
        ),
    ),
    (
        "Prompt Injection",
        0.85,
        (
            r"\bignore previous instructions\b",
            r"\bnew instructions?:\b",
            r"\bdeveloper mode\b",
            r"\bprompt injection\b",
        ),
    ),
    (
        "Obfuscation",
        0.65,
        (
            r"\b(?:base64|rot13|url[- ]?encode[dt]?)\b",
            r"(?:%[0-9a-f]{2}){3,}",
            r"\b[a-z0-9+/]{32,}={0,2}\b",
        ),
    ),
)


def analyze_rules(prompt: str) -> RuleAnalysis:
    """Return the highest-severity explainable rule match for a prompt."""
    normalized_prompt = prompt.lower().strip()

    for category, score, patterns in RULES:
        for pattern in patterns:
            match = re.search(pattern, normalized_prompt, flags=re.IGNORECASE)
            if match:
                return RuleAnalysis(
                    rule_score=score,
                    threat_category=category,
                    reason=(
                        f"Matched {category.lower()} rule: "
                        f"'{match.group(0)}'."
                    ),
                )

    return RuleAnalysis(
        rule_score=0.0,
        threat_category="None",
        reason="No rule-based threat indicators were detected.",
    )
