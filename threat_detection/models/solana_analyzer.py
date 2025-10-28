

import json
import os
import re
from datetime import datetime
from typing import Dict, Any, List

class SolanaAnalyzer:
    def __init__(self, rules_path=None):
        if rules_path is None:
            rules_path = os.path.join(os.path.dirname(__file__), "..", "solana_rules.json")
        try:
            with open(rules_path, "r") as f:
                rules = json.load(f)
        except Exception:
            rules = []
        # normalize blacklist map for quick lookup
        self.blacklist = {r["address"]: r for r in rules}
        # precompute lowercase keys for substring search
        self.blacklist_addresses = set(self.blacklist.keys())

    def _extract_addresses_from_text(self, text: str) -> List[str]:
        """
        Very permissive Base58-like address extractor (doesn't validate checksum).
        Solana addresses are base58 strings ~32 bytes -> length typically 32-44 characters.
        We'll look for tokens of length 32-44 composed of base58 chars.
        """
        if not text:
            return []
        base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        # token regex: 32-44 chars using base58 alphabet
        patt = rf"\b[{re.escape(base58_chars)}]{{32,44}}\b"
        return re.findall(patt, text)

    def analyze_transaction(self, tx: Dict[str, Any] or str) -> Dict[str, Any]:
        """
        tx: either a dict with fields (signature, from_address, to_address, instructions, etc.)
            or a free-form string (e.g., user pasted a tx id or raw metadata).
        Returns a report dict similar to URL analyzer output.
        """
        evidence = {"matches": [], "checked_addresses": []}
        input_text = ""

        # Normalize input to text and candidate addresses list
        if isinstance(tx, dict):
            # collect fields likely to contain addresses
            candidates = []
            for k in ("signature", "from_address", "to_address", "program_id", "instruction_data"):
                v = tx.get(k)
                if v:
                    candidates.append(str(v))
            # instructions may be present as list/dict
            inst = tx.get("instructions")
            if inst:
                candidates.append(str(inst))
            input_text = " ".join(candidates)
        else:
            input_text = str(tx)

        # extract address-like tokens
        extracted = self._extract_addresses_from_text(input_text)
        evidence["checked_addresses"] = extracted

        # check explicit fields too (if dict provided)
        if isinstance(tx, dict):
            for key in ("from_address", "to_address"):
                v = tx.get(key)
                if v:
                    extracted.append(str(v))

        # check each found token against blacklist
        for addr in set(extracted):
            if addr in self.blacklist_addresses:
                rule = self.blacklist[addr]
                evidence["matches"].append({
                    "address": addr,
                    "rule_id": rule.get("id"),
                    "type": rule.get("type"),
                    "description": rule.get("description"),
                    "severity": rule.get("severity")
                })

        # Determine verdict based on matches
        if evidence["matches"]:
            # highest severity among matches
            sev_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            maxv = 0
            max_sev = "low"
            for m in evidence["matches"]:
                s = m.get("severity", "low").lower()
                v = sev_rank.get(s, 1)
                if v > maxv:
                    maxv = v
                    max_sev = s
            verdict = "unsafe"
            severity = max_sev
        else:
            verdict = "safe"
            severity = "low"

        report = {
            "artifact_type": "solana_transaction",
            "input": tx,
            "verdict": verdict,
            "severity": severity,
            "alerts": evidence["matches"],
            "evidence": evidence,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        return report
