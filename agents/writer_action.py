# writer_action.py
import json
from typing import Dict, Any
from agent_mvp import DirectSolanaAuditClient

def agent_submit(input_payload: Dict[str, Any]) -> Dict[str, Any]:
    url = input_payload.get("url")
    verdict = input_payload.get("verdict")
    if not isinstance(url, str) or not url.strip():
        raise ValueError("'url' is required")
    if verdict not in (0, 1, 2):
        raise ValueError("'verdict' must be 0, 1, or 2")

    quote = input_payload.get("quote")
    if not isinstance(quote, str) or not quote.strip():
        raise ValueError("'quote' (Nitro attestation) is required")

    attestation = {"quote": quote}
    cert_chain = input_payload.get("cert_chain")
    if isinstance(cert_chain, str) and cert_chain:
        attestation["cert_chain"] = cert_chain

    client = DirectSolanaAuditClient()
    return client.submit_scan(
        url=url,
        verdict=verdict,
        attestation=attestation,
        scan_id=input_payload.get("scan_id"),
        metadata={"cid": input_payload.get("cid")} if input_payload.get("cid") else None,
    )

if __name__ == "__main__":
    import sys
    print(json.dumps(agent_submit(json.loads(sys.stdin.read() or "{}")), indent=2))
