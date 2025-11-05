# verify_helper.py
import json, base64, os, hashlib
from typing import Any, Dict, Optional
from solana.rpc.api import Client
from solders.pubkey import Pubkey

MEMO_PROGRAM_ID = str(Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"))

def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def canonicalise_url(raw: str) -> str:
    from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
    raw = (raw or "").strip()
    p = urlparse(raw)
    scheme = (p.scheme or "").lower()
    host = (p.hostname or "").lower()
    port = p.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        netloc = host
    elif port:
        netloc = f"{host}:{port}"
    else:
        netloc = host
    path = p.path or "/"
    if path != "/":
        path = path.rstrip("/")
    query = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
    return urlunparse((scheme, netloc, path, "", query, ""))

def _extract_memo(tx_json: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    instrs = tx_json.get("result", {}).get("transaction", {}).get("message", {}).get("instructions", [])
    for ix in instrs:
        if ix.get("programId") == MEMO_PROGRAM_ID and ix.get("data"):
            try:
                return json.loads(base64.b64decode(ix["data"]).decode("utf-8"))
            except Exception:
                pass
    # fallback: parsed
    meta = tx_json.get("result", {}).get("meta") or {}
    for log in meta.get("logMessages") or []:
        if "Memo" in log and "{" in log and "}" in log:
            try:
                s = log[log.index("{"): log.rindex("}")+1]
                return json.loads(s)
            except Exception:
                continue
    return None

def fetch_and_verify(sig: str, *, expected_url: Optional[str] = None,
                     expected_attestation_json: Optional[Dict[str, Any]] = None,
                     expected_cid: Optional[str] = None,
                     expected_verdict: Optional[int] = None,
                     rpc_url: Optional[str] = None) -> Dict[str, Any]:
    client = Client(rpc_url or os.getenv("SOLANA_RPC", "https://api.devnet.solana.com"))
    tx = client.get_transaction(sig)
    memo = _extract_memo(tx)
    if not memo:
        raise RuntimeError("No SPL Memo found in transaction")

    checks, ok = [], True
    if expected_url:
        h = sha256_hex(canonicalise_url(expected_url))
        m = memo.get("url_sha256") == h
        checks.append({"field": "url_sha256", "match": m})
        ok &= m
    if expected_attestation_json is not None:
        h = sha256_hex(json.dumps(expected_attestation_json, separators=(",", ":")))
        m = memo.get("att_sha256") == h
        checks.append({"field": "att_sha256", "match": m})
        ok &= m
    if expected_cid is not None:
        m = memo.get("cid") == expected_cid
        checks.append({"field": "cid", "match": m})
        ok &= m
    if expected_verdict is not None:
        m = memo.get("verdict") == expected_verdict
        checks.append({"field": "verdict", "match": m})
        ok &= m

    return {"ok": bool(ok), "memo": memo, "checks": checks}
