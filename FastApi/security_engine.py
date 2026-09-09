import re
import math
from typing import List, Dict, Tuple
try:
    import config
except ImportError:
    from . import config

# Comprehensive Signature Matrices
ATTACK_SIGNATURES = {
    "system_leak": [
        r"(reveal|output|display|show|leak|repeat|print|dump)\s+(the\s+)?(initial|original|system|core|hidden|internal)\s+(instructions|prompt|rules|credentials|directives)",
        r"what\s+are\s+your\s+(initial|system|underlying)\s+instructions",
        r"print\s+everything\s+above",
        r"show\s+(me\s+)?(your\s+)?system\s+prompt",
        r"(show|reveal|display|give|tell)\s+(me\s+)?(your\s+)?(hidden|secret|internal|private)\s+(system\s+)?(instructions|prompt|rules)",
        r"(reveal|show|display|print)\s+(your\s+)?(hidden|secret|internal)\s+(system\s+)?instructions"
    ],

    "instruction_override": [
        r"(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)",
        r"(enter|enable|activate|start|switch\s+to)\s+developer\s+mode",
        r"developer\s+mode",
        r"(start\s+acting\s+as|simulate|pretend\s+to\s+be)",
        r"(dan|jailbreak|unrestricted|god)\s+mode",
        r"you\s+are\s+now\s+(in\s+developer\s+mode|unrestricted|an\s+unfiltered)"
    ],

    "privilege_escalation": [
        r"sudo\s+mode",
        r"disable\s+(all\s+)?(safety|content|security)\s+filters",
        r"remove\s+(all\s+)?(safety|content|security)\s+(restrictions|filters)",
        r"you\s+have\s+no\s+restrictions",
        r"act\s+without\s+(any\s+)?restrictions",
        r"simulate\s+unfiltered",
        r"pretend\s+all\s+restrictions\s+have\s+been\s+removed",
        r"(bypass|ignore|disable)\s+(all\s+)?safety\s+(rules|checks|filters)"
    ],

    "encoded_payload": [
        r"base64",
        r"rot13",
        r"decode\s+and\s+execute",
        r"decode\s+(this|the)?\s*(encoded|encrypted)?\s*payload"
    ]
}


def calculate_shannon_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a text string."""
    if not text:
        return 0.0

    freq: Dict[str, int] = {}

    for char in text:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    text_len = len(text)

    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)

    return round(entropy, 2)


def run_heuristic_scan(prompt: str) -> Tuple[List[str], Dict[str, float]]:
    """Scan a prompt for suspicious signatures and possible obfuscation."""

    matches: List[str] = []

    category_scores: Dict[str, float] = {
        "instruction_override": 0.0,
        "system_leak": 0.0,
        "privilege_escalation": 0.0,
        "encoded_payload": 0.0
    }

    if not prompt:
        return matches, category_scores

    # Signature-based detection
    for category, patterns in ATTACK_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                matches.append(
                    f"Detected {category.replace('_', ' ')} signature"
                )
                category_scores[category] = 1.0

    # Remove duplicate messages while preserving order
    matches = list(dict.fromkeys(matches))

    # Entropy-based obfuscation detection
    entropy = calculate_shannon_entropy(prompt)

    if entropy > 4.6 and len(prompt) > 80:
        matches.append(
            "High-entropy string detected "
            "(possible obfuscated payload)"
        )
        category_scores["encoded_payload"] = 0.85

    return matches, category_scores


def sanitize_prompt(prompt: str) -> str:
    """Redact known suspicious patterns from a prompt."""

    sanitized = prompt

    for patterns in ATTACK_SIGNATURES.values():
        for pattern in patterns:
            sanitized = re.sub(
                pattern,
                "[REDACTED_BY_PROMPTGUARD]",
                sanitized,
                flags=re.IGNORECASE
            )

    return sanitized