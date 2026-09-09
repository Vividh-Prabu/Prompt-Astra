"""
API Client abstraction layer for PromptGuard.
Decouples frontend from specific backend/ML services.
If an external ML model or gateway endpoint is specified via PROMPTGUARD_API_URL,
it proxies requests there; otherwise gracefully falls back to the deterministic
local security engine in Demo Mode.
"""

import os
import json
import urllib.request
import urllib.error
from typing import Dict, Any
from .security_utils import SecurityAnalyzer


class PromptGuardClient:
    """
    Unified client for PromptGuard analysis.
    Supports live HTTP backend integration or zero-dependency Demo Mode fallback.
    """

    def __init__(self):
        self.api_url = os.environ.get("PROMPTGUARD_API_URL", "").strip()
        self.api_key = os.environ.get("PROMPTGUARD_API_KEY", "").strip()
        self.timeout = float(os.environ.get("PROMPTGUARD_TIMEOUT", "5.0"))

    @property
    def is_live_backend_configured(self) -> bool:
        return bool(self.api_url)

    def analyze_prompt(self, prompt: str) -> Dict[str, Any]:
        """
        Sends the prompt for security evaluation.
        Falls back to deterministic local security heuristic engine if live API is unconfigured or unreachable.
        """
        if self.is_live_backend_configured:
            try:
                headers = {"Content-Type": "application/json"}
                if self.api_key:
                    headers["Authorization"] = f"Bearer {self.api_key}"

                payload = json.dumps({"prompt": prompt}).encode("utf-8")
                req = urllib.request.Request(
                    f"{self.api_url.rstrip('/')}/analyze",
                    data=payload,
                    headers=headers,
                    method="POST"
                )

                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        data["demo_mode"] = False
                        data["backend_source"] = "LIVE_ML_SERVICE"
                        return data
            except Exception as e:
                # Log error and fall back seamlessly to demo engine
                # Never crash the UI or leak raw exceptions
                pass

        # Demo mode / local heuristic fallback
        result = SecurityAnalyzer.analyze_text(prompt)
        result["backend_source"] = "PROMPTGUARD_HEURISTIC_ENGINE (DEMO_MODE)"
        return result


# Singleton instance
client = PromptGuardClient()
