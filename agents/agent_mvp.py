# agent_mvp.py
# Core Solana writer logic (solana 0.36.x + solders 0.26.x compatible)
#
# Provides DirectSolanaAuditClient.submit_scan(...) which writes a compact JSON
# to the SPL Memo program on devnet (or whatever RPC you point at).
#
# Usage (example):
#   export SOLANA_KEYFILE="$PWD/devnet-keypair.json"
#   export SOLANA_RPC="https://api.devnet.solana.com"
#   python -c 'from agent_mvp import DirectSolanaAuditClient; print(DirectSolanaAuditClient().submit_scan(url="https://evil.example", verdict=2, attestation={"quote":"x"}, scan_id=None, metadata={"cid":"bafy..."}))'
#
import os
import json
import time
import hashlib
import asyncio
from typing import Optional, Dict, Any

from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.instruction import Instruction, AccountMeta
from solders.message import Message
from solders.transaction import Transaction
from solders.signature import Signature

from solana.rpc.async_api import AsyncClient

MEMO_PROGRAM_ID = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")


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


def load_keypair() -> Keypair:
    """
    Load a solders.Keypair from either:
      - SOLANA_KEYFILE path containing a JSON array of bytes
      - SOLANA_PRIVATE_KEY_JSON env value containing the same JSON array
    Raises RuntimeError if neither is present.
    """
    keyfile = os.getenv("SOLANA_KEYFILE")
    if keyfile and os.path.exists(keyfile):
        with open(keyfile, "r", encoding="utf-8") as f:
            arr = json.load(f)
        return Keypair.from_bytes(bytes(arr))

    env_json = os.getenv("SOLANA_PRIVATE_KEY_JSON")
    if env_json:
        arr = json.loads(env_json)
        return Keypair.from_bytes(bytes(arr))

    raise RuntimeError("No Solana key provided: set SOLANA_PRIVATE_KEY_JSON or SOLANA_KEYFILE")


class DirectSolanaAuditClient:
    """
    Simple client that writes a compact audit memo to the SPL Memo program.
    submit_scan is blocking (synchronous) for convenience in simple scripts,
    but uses the async RPC client internally.
    """

    def __init__(self, rpc_url: Optional[str] = None, timeout_s: int = 15):
        self.rpc_url = rpc_url or os.getenv("SOLANA_RPC", "https://api.devnet.solana.com")
        self.timeout_s = int(os.getenv("REQUEST_TIMEOUT_S", str(timeout_s)))
        self.payer = load_keypair()

    async def _submit_scan_async(
        self,
        *,
        url: str,
        verdict: int,
        attestation: Dict[str, Any],
        scan_id: Optional[str],
        metadata: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        ts = int(time.time())
        url_canon = canonicalise_url(url)
        url_hash = sha256_hex(url_canon)
        att_hash = sha256_hex(json.dumps(attestation, separators=(",", ":")))
        cid = (metadata or {}).get("cid", "")

        compact = {
            "v": 1,
            "scan_id": scan_id or f"scan-{ts}",
            "verdict": int(verdict),
            "url_sha256": url_hash,
            "att_sha256": att_hash,
            "cid": cid,
            "ts": ts,
        }
        memo_bytes = json.dumps(compact, separators=(",", ":")).encode("utf-8")

        payer_pub = self.payer.pubkey()

        # Create the Memo instruction. Including the payer as an AccountMeta (is_signer=True)
        # is fine; Memo actually doesn't require writable accounts.
        ix = Instruction(
            program_id=MEMO_PROGRAM_ID,
            accounts=[AccountMeta(pubkey=payer_pub, is_signer=True, is_writable=False)],
            data=memo_bytes,
        )

        # Use AsyncClient to fetch blockhash, sign and send
        async with AsyncClient(self.rpc_url, timeout=self.timeout_s) as client:
            bh_resp = await client.get_latest_blockhash()
            if not bh_resp.value:
                raise RuntimeError(f"Failed to fetch blockhash: {bh_resp}")

            # recent_blockhash is already a Hash-like object in the response
            recent_blockhash = bh_resp.value.blockhash

            # Build message and transaction, sign in-place
            msg = Message.new_with_blockhash([ix], payer_pub, recent_blockhash)
            tx = Transaction.new_unsigned(msg)
            tx.sign([self.payer], recent_blockhash)  # mutates in place

            # Send and capture Signature object
            send_resp = await client.send_raw_transaction(bytes(tx))
            signature_obj: Signature = send_resp.value
            sig_str = str(signature_obj)

            # Confirm using the Signature object (NOT a string)
            await client.confirm_transaction(signature_obj)

            return {"txSignature": sig_str, "payer": str(payer_pub), "memo": compact}

    def submit_scan(
        self,
        *,
        url: str,
        verdict: int,
        attestation: Dict[str, Any],
        scan_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Synchronous wrapper around the async submit function for simple scripts and agents.
        Returns: {"txSignature": str, "payer": str, "memo": {...}}
        """
        return asyncio.run(
            self._submit_scan_async(url=url, verdict=verdict, attestation=attestation, scan_id=scan_id, metadata=metadata)
        )


# Optional CLI quick-run support
if __name__ == "__main__":
    import sys
    import uuid

    # Read JSON from stdin (matches writer_action style)
    payload = json.loads(sys.stdin.read() or "{}")
    url = payload.get("url")
    verdict = payload.get("verdict")
    quote = payload.get("quote")
    cert_chain = payload.get("cert_chain")
    scan_id = payload.get("scan_id") or str(uuid.uuid4())
    cid = payload.get("cid")

    if not isinstance(url, str) or not url.strip():
        print("Missing required 'url' field", file=sys.stderr)
        sys.exit(2)
    if verdict not in (0, 1, 2):
        print("'verdict' must be 0, 1, or 2", file=sys.stderr)
        sys.exit(2)
    if not isinstance(quote, str) or not quote.strip():
        print("Missing required 'quote' (Nitro attestation)", file=sys.stderr)
        sys.exit(2)

    attestation = {"quote": quote}
    if isinstance(cert_chain, str) and cert_chain:
        attestation["cert_chain"] = cert_chain

    client = DirectSolanaAuditClient()
    res = client.submit_scan(url=url, verdict=verdict, attestation=attestation, scan_id=scan_id, metadata={"cid": cid} if cid else None)
    print(json.dumps(res, indent=2))