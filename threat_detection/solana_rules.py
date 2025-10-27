# threat_detection/solana_rules.py
"""
Simple hardcoded list of malicious Solana program IDs / wallet addresses
"""

MALICIOUS_SOLANA_IDS = {
    # Malicious dev / bad wallets (provided)
    "5Jfb3n8eW4JyQrKJktMNBFXnC1zx2YHjRSkzRrTT5QHh": {
        "label": "malicious_dev_wallet_1",
        "reason": "Known malicious dev wallet (demo list)",
        "severity": "high"
    },
    "ESSfP3aAcW6Z59ozut9Jkqy9btaX5YTHt25b3Vhs2hsf": {
        "label": "malicious_dev_wallet_2",
        "reason": "Known malicious dev wallet (demo list)",
        "severity": "high"
    },
    "GrXoxqM2a6QFKSBdZ9RLWJCBVTFvuuH8eCjjsLbjhpiR": {
        "label": "malicious_dev_wallet_3",
        "reason": "Known malicious dev wallet (demo list)",
        "severity": "high"
    },

    # Malicious validators
    "4SKy65C9373k9WZnq2ViR7nq8eCu32TkLhoXq45MYQm6": {
        "label": "malicious_validator_1",
        "reason": "Known malicious validator (demo list)",
        "severity": "high"
    },
    "7Q79sw9Sb625PFzxTvRzhgYme8Jb6mzuTR1CaU3UfV1w": {
        "label": "malicious_validator_2",
        "reason": "Known malicious validator (demo list)",
        "severity": "high"
    },
}

def is_malicious_solana_address(addr: str):
    """
    Check if the provided Solana address (program/wallet/validator id) is in the hardcoded list.
    Returns (bool, info_dict_or_None)
    """
    if not addr:
        return False, None
    normalized = addr.strip()
    info = MALICIOUS_SOLANA_IDS.get(normalized)
    return (info is not None), info
