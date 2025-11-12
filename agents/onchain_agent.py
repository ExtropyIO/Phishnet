import os
import sys
import hashlib
from datetime import datetime
from uagents import Agent, Context
import asyncio

from schema import SignedReport, ChatMessage, ChatResponse, LogResponse

# Import real Solana blockchain writer
try:
    from agent_mvp import DirectSolanaAuditClient
    SOLANA_AVAILABLE = True
except ImportError:
    SOLANA_AVAILABLE = False

TESTNET_RPC = "https://api.devnet.solana.com"

agent = Agent(
         name="OnchainAgent",
         seed="onchain-agent-seed"
     )

def get_validated_rpc() -> tuple[str, str]:
    rpc_url = TESTNET_RPC
    cluster = "devnet"
    
    return rpc_url, cluster

def verdict_to_int(verdict_str: str) -> int:
    """Convert verdict string to integer for blockchain storage"""
    verdict_map = {
        "safe": 0,
        "suspicious": 1,
        "malicious": 2,
        "error": 2  # Treat errors as malicious for safety
    }
    return verdict_map.get(verdict_str.lower(), 1)

async def write_to_blockchain(msg: SignedReport) -> LogResponse:
    """Write verified report to Solana blockchain via SPL Memo program"""
    
    if not SOLANA_AVAILABLE:
        raise RuntimeError(
            "Solana blockchain integration not available. "
        )
    
    # Get RPC and cluster info
    rpc_url, cluster = get_validated_rpc()
    
    # Extract URL from evidence if available
    url = "unknown"
    if isinstance(msg.evidence, dict):
        if "url" in msg.evidence:
            url = msg.evidence["url"]
        elif "transaction" in msg.evidence and isinstance(msg.evidence["transaction"], dict):
            tx_sig = msg.evidence["transaction"].get("signature", "")
            if tx_sig:
                url = f"solana_tx:{tx_sig}"
            else:
                # Fallback: use from/to addresses
                from_addr = msg.evidence["transaction"].get("from_address", "")
                to_addr = msg.evidence["transaction"].get("to_address", "")
                if from_addr and to_addr:
                    url = f"solana_tx:{from_addr}->{to_addr}"
                else:
                    url = "solana_transaction"
    
    verdict_int = verdict_to_int(msg.verdict)
    
    # Build attestation data from referee verification
    attestation = {}
    if isinstance(msg.evidence, dict) and 'referee_verification' in msg.evidence:
        attestation = {
            "quote": msg.signature,
            "referee_status": msg.evidence['referee_verification']['status'],
            "verified_by": msg.evidence['referee_verification']['verified_by'],
            "signature_valid": msg.evidence['referee_verification'].get('signature_valid', False)
        }
    else:
        # Fallback if no referee verification
        attestation = {"quote": msg.signature}
    
    try:
        # Create client with explicit RPC
        client = DirectSolanaAuditClient(rpc_url=rpc_url)
        
        # Run the sync submit_scan in executor to avoid blocking
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: client.submit_scan(
                url=url,
                verdict=verdict_int,
                attestation=attestation,
                scan_id=msg.ticket_id,
                metadata={"report_hash": msg.report_hash, "attestation": msg.attestation}
            )
        )
        
        # Convert to LogResponse format
        tx_sig = result["txSignature"]
        
        return LogResponse(
            tx_signature=tx_sig,
            explorer_url=f"https://explorer.solana.com/tx/{tx_sig}?cluster={cluster}",
            block_height=None,
            confirmed=True
        )
    
    except Exception as exc:
        raise RuntimeError(f"Blockchain write failed: {exc}") from exc

@agent.on_event("startup")
async def startup(ctx: Context):
    
    # Check if Solana integration is available
    if SOLANA_AVAILABLE:
        ctx.logger.info("Solana blockchain integration ENABLED")
        
        # Get validated RPC
        rpc_url, cluster = get_validated_rpc()
        
        # Display network configuration
        ctx.logger.info(f"RPC Endpoint: {rpc_url}")
        ctx.logger.info(f"Network: {cluster.upper()}")

    else:
        ctx.logger.error("Solana integration NOT available")

@agent.on_message(model=SignedReport)
async def handle_report(ctx: Context, sender: str, msg: SignedReport):
    """Receive verified report and record it on-chain"""
    ticket_id = getattr(msg, 'ticket_id', 'unknown')
    chat_sender = getattr(msg, 'chat_sender', None)
    ctx.logger.info(f"Received SignedReport: {msg.report_hash} for ticket {ticket_id}")
    
    # Check if this is a verified report (only record verified reports)
    is_verified = msg.attestation and '_verified' in msg.attestation
    
    if is_verified:
        ctx.logger.info(f"Recording VERIFIED report {msg.report_hash} on-chain...")
        
        try:
            # Write to real Solana blockchain
            log_response = await write_to_blockchain(msg)
            
            ctx.logger.info(f"Report recorded on blockchain: {log_response.tx_signature}")
            ctx.logger.info(f"Explorer URL: {log_response.explorer_url}")
            
        except Exception as exc:
            ctx.logger.error(f"Blockchain recording FAILED: {exc}")
            return
        
        # If we have the original chat_sender, send blockchain confirmation directly to user
        if chat_sender:
            try:
                from uagents_core.contrib.protocols.chat import (
                    ChatMessage as CPChatMessage,
                    TextContent as CPTextContent,
                )
                
                blockchain_message = f"""⛓️ Blockchain Confirmation

Report recorded on-chain

TX Signature: {log_response.tx_signature[:16]}...

Explorer: {log_response.explorer_url}

Status: {'Confirmed' if log_response.confirmed else 'Pending'}"""
                
                await ctx.send(chat_sender, CPChatMessage(
                    timestamp=datetime.utcnow(),
                    msg_id=__import__('uuid').uuid4(),
                    content=[CPTextContent(type="text", text=blockchain_message)]
                ))
                ctx.logger.info(f"Sent blockchain confirmation to user")
            except Exception as exc:
                ctx.logger.error(f"Failed to send blockchain confirmation to user: {exc}")
        
        # Also send back to intake agent for logging
        await ctx.send(sender, log_response)
        ctx.logger.info(f"Sent LogResponse back to {sender}")
    else:
        ctx.logger.warning(f"Received unverified report {msg.report_hash}, skipping on-chain recording")

@agent.on_message(model=ChatMessage)
async def hello(ctx: Context, sender: str, msg: ChatMessage):
    await ctx.send(sender, ChatResponse(
        response="Onchain agent is running. Send a verified SignedReport to persist proof on-chain.",
        requires_action=False
    ))

if __name__ == "__main__":
    agent.run()