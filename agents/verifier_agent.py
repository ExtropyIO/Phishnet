# verifier_agent.py
import json, os
from typing import Dict, Any
from verify_helper import fetch_and_verify

def agent_verify(input_payload: Dict[str, Any]) -> Dict[str, Any]:
    sig = input_payload.get("sig")
    if not isinstance(sig, str) or not sig.strip():
        raise ValueError("'sig' is required")
    return fetch_and_verify(
        sig,
        expected_url=input_payload.get("url"),
        expected_attestation_json=input_payload.get("attestation"),
        expected_cid=input_payload.get("cid"),
        expected_verdict=input_payload.get("verdict"),
        rpc_url=os.getenv("SOLANA_RPC"),
    )

if __name__ == "__main__":
    import sys
    print(json.dumps(agent_verify(json.loads(sys.stdin.read() or "{}")), indent=2))
