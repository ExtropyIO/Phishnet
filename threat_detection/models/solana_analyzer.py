

import json
import os
import re
from datetime import datetime
from typing import Dict, Any, List


class SolanaAnalyzer:
    def __init__(self, rules_path=None):
        if rules_path is None:
            rules_path = os.path.join(os.path.dirname(__file__), "solana_rules.json")
        with open(rules_path, "r") as f:
            self.rules = json.load(f)

        # Index wallets and validators for quick lookup
        self.malicious_wallets = {r["address"]: r for r in self.rules if r["type"] == "wallet"}
        self.malicious_validators = {r["address"]: r for r in self.rules if r["type"] == "validator"}

    def analyze_transaction(self, tx):
        """
        Analyze a Solana transaction.
        tx: SolanaTransaction Pydantic model
        Returns a dict with alerts, verdict, severity
        """
        alerts = []

        # Check sender
        if tx.from_address in self.malicious_wallets:
            alerts.append({
                "id": f"malicious_from_{tx.from_address}",
                "description": self.malicious_wallets[tx.from_address]["description"],
                "severity": self.malicious_wallets[tx.from_address]["severity"]
            })

        # Check receiver
        if tx.to_address in self.malicious_wallets:
            alerts.append({
                "id": f"malicious_to_{tx.to_address}",
                "description": self.malicious_wallets[tx.to_address]["description"],
                "severity": self.malicious_wallets[tx.to_address]["severity"]
            })

        # Check validator if provided
        if getattr(tx, "validator", None) and tx.validator in self.malicious_validators:
            alerts.append({
                "id": f"malicious_validator_{tx.validator}",
                "description": self.malicious_validators[tx.validator]["description"],
                "severity": self.malicious_validators[tx.validator]["severity"]
            })

        # Determine verdict
        severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        max_sev = 0
        for a in alerts:
            sev = severity_levels.get(a["severity"].lower(), 1)
            if sev > max_sev:
                max_sev = sev

        severity_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
        final_severity = severity_map.get(max_sev, "low")
        verdict = "safe" if max_sev <= 1 else "unsafe"

        return {
            "transaction": tx.dict(),
            "alerts": alerts,
            "verdict": verdict,
            "severity": final_severity
        }
