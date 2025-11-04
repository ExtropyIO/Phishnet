import os
import hashlib
from datetime import datetime
from uagents import Agent, Context

from schema import SignedReport, ChatMessage, ChatResponse, LogResponse

agent = Agent(
         name="OnchainAgent",
         seed="onchain-agent-seed"
     )

def simulate_blockchain_write(report_hash: str, verdict: str) -> LogResponse:
    """Simulate writing report hash to blockchain and return transaction details"""
    # Generate a simulated transaction signature (in production this would be real)
    tx_data = f"{report_hash}:{verdict}:{datetime.utcnow().isoformat()}"
    tx_signature = hashlib.sha256(tx_data.encode()).hexdigest()
    
    # Simulate Solana explorer URL (could also be EVM)
    explorer_url = f"https://explorer.solana.com/tx/{tx_signature}?cluster=devnet"
    
    return LogResponse(
        tx_signature=tx_signature,
        explorer_url=explorer_url,
        block_height=None,  # Would be populated in real implementation
        confirmed=True
    )

@agent.on_event("startup")
async def startup(ctx: Context):
    ctx.logger.info("OnchainAgent ready - will record verified reports on-chain")

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
        
        # Simulate blockchain write (in production: call actual blockchain API)
        log_response = simulate_blockchain_write(msg.report_hash, msg.verdict)
        
        ctx.logger.info(f"✓ Report recorded on-chain: {log_response.tx_signature}")
        ctx.logger.info(f"Explorer URL: {log_response.explorer_url}")
        
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