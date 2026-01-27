import json
import os
import re
from datetime import datetime
from typing import Dict, Any, List

EMBEDDED_SOLANA_RULES_JSON = r"""[
  {
    "id": "malicious_dev_wallet_1",
    "address": "5Jfb3n8eW4JyQrKJktMNBFXnC1zx2YHjRSkzRrTT5QHh",
    "type": "wallet",
    "description": "Malicious developer wallet detected in previous incidents",
    "severity": "critical"
  }, 
  {
    "id": "malicious_dev_wallet_2",
    "address": "ESSfP3aAcW6Z59ozut9Jkqy9btaX5YTHt25b3Vhs2hsf",
    "type": "wallet",
    "description": "Malicious developer wallet #2",
    "severity": "critical"
  },
  {
    "id": "malicious_dev_wallet_3",
    "address": "GrXoxqM2a6QFKSBdZ9RLWJCBVTFvuuH8eCjjsLbjhpiR",
    "type": "wallet",
    "description": "Malicious developer wallet #3",
    "severity": "critical"
  },
  {
    "id": "malicious_validator_1",
    "address": "4SKy65C9373k9WZnq2ViR7nq8eCu32TkLhoXq45MYQm6",
    "type": "validator",
    "description": "Malicious validator (known bad node)",
    "severity": "high"
  },
  {
    "id": "malicious_validator_2",
    "address": "7Q79sw9Sb625PFzxTvRzhgYme8Jb6mzuTR1CaU3UfV1w",
    "type": "validator",
    "description": "Malicious validator (known bad node) #2",
    "severity": "high"
  },
  {
    "id": "zero_address",
    "address": "11111111111111111111111111111111",
    "type": "wallet",
    "description": "Zero address (commonly used as null or burn address)",
    "severity": "medium"
  },
  {
    "id": "malicious_contract_scam_coin",
    "address": "9mNjA6BizTwpvd4DS3o7BjwZ6aPM9DC2jLHS7JFGbonk",
    "type": "contract",
    "description": "Scam token contract (scam coin)",
    "severity": "critical"
  },
  {
    "id": "malicious_hacking_contract",
    "address": "5HYjArGt81naevDdwMaEx8yeGNw9jYBSDJa8YavT9Mp4",
    "type": "contract",
    "description": "Hacking contract used in known exploit activity",
    "severity": "critical"
  },
  {
    "id": "malicious_extension_1",
    "address": "5UMucMksJweA1AtgyxrK8DJeBXr3DQGEGRs5Kkq2pZjr",
    "type": "extension",
    "description": "Malicious browser/-wallet extension identifier",
    "severity": "high"
  }
]"""


class SolanaAnalyzer:
    def __init__(self, rules_path=None):
        loaded_rules = None

        if rules_path is None:
            base_dir = os.path.dirname(__file__)
            candidate_paths = [
                os.path.join(base_dir, "solana_rules.json"),
                os.path.join(os.path.dirname(base_dir), "solana_rules.json"),
            ]
            for path in candidate_paths:
                if os.path.exists(path):
                    rules_path = path
                    break

        if rules_path is not None:
            try:
                with open(rules_path, "r") as f:
                    loaded_rules = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                loaded_rules = None

        if loaded_rules is None:
            loaded_rules = json.loads(EMBEDDED_SOLANA_RULES_JSON)

        self.rules = loaded_rules

        # Index wallets and validators for quick lookup
        self.malicious_wallets = {r["address"]: r for r in self.rules if r["type"] == "wallet"}
        self.malicious_validators = {r["address"]: r for r in self.rules if r["type"] == "validator"}

    def analyze_transaction(self, tx):
    
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
