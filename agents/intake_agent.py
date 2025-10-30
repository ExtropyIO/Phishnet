"""
IntakeAgent - uAgents Framework Implementation
Receives user artifacts and initiates analysis workflow
Uses proper uAgents communication patterns
"""

import os
import uuid
import json
from datetime import datetime
from typing import Dict, Any
from uagents import Agent, Context, Model
import asyncio

# Import schemas
try:
    from shared.schemas.artifact_schema import (
        Artifact, ArtifactType, AnalysisTicket, AnalysisRequest, SignedReport,
        ChatMessage, ChatResponse, SolanaTransaction
    )
except ImportError:
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from shared.schemas.artifact_schema import (
        Artifact, ArtifactType, AnalysisTicket, AnalysisRequest, SignedReport,
        ChatMessage, ChatResponse, SolanaTransaction
    )

# Create agent
intake_agent = Agent(
    name="IntakeAgent",
    seed="intake-agent-seed",
    port=8001,
    endpoint=["http://127.0.0.1:8001/submit"]
)

# Core agent logic
class IntakeAgentCore:
    def __init__(self):
        self.tickets: Dict[str, AnalysisTicket] = {}
        self.analyzer_address = os.getenv("ANALYZER_ADDRESS")
        self.referee_address = os.getenv("REFEREE_ADDRESS")
        self.onchain_address = os.getenv("ONCHAIN_ADDRESS")
    
    def receive_artifact(self, artifact: Artifact) -> AnalysisTicket:
        """Receive and validate artifact from user"""
        ticket_id = str(uuid.uuid4())
        ticket = AnalysisTicket(
            ticket_id=ticket_id,
            artifact=artifact,
            timestamp=datetime.now().isoformat(),
            status="received"
        )
        self.tickets[ticket_id] = ticket
        return ticket
    
    def package_for_analysis(self, ticket: AnalysisTicket) -> AnalysisRequest:
        """Package artifact for TEE analysis"""
        return AnalysisRequest(
            ticket_id=ticket.ticket_id,
            artifact=ticket.artifact,
            nonce="",  # Will be filled by AnalyzerAgent
            session_id=""
        )

core = IntakeAgentCore()

# ChatMessage and ChatResponse are imported from shared schemas

@intake_agent.on_event("startup")
async def startup(ctx: Context):
    """Agent startup handler"""
    ctx.logger.info("IntakeAgent started - ready to receive artifacts")
    ctx.logger.info(f"Agent address: {intake_agent.address}")
    if core.analyzer_address:
        ctx.logger.info(f"AnalyzerAgent address: {core.analyzer_address}")
    else:
        ctx.logger.warning("ANALYZER_ADDRESS not set - analysis requests will be queued")
    if getattr(core, "referee_address", None):
        ctx.logger.info(f"RefereeAgent address: {core.referee_address}")
    else:
        ctx.logger.warning("REFEREE_ADDRESS not set - signature verification will be skipped!")
    if getattr(core, "onchain_address", None):
        ctx.logger.info(f"OnchainAgent address: {core.onchain_address}")
    else:
        ctx.logger.warning("ONCHAIN_ADDRESS not set - onchain reporting disabled!")

@intake_agent.on_message(model=ChatMessage)
async def handle_chat(ctx: Context, sender: str, msg: ChatMessage):
    """Handle chat messages from users"""
    ctx.logger.info(f"Received chat from {sender}: {msg.message}")
    
    # Extract artifact type and content
    message_text = msg.message.lower()
    artifact_type = None
    
    if 'url' in message_text or message_text.startswith('http'):
        artifact_type = ArtifactType.URL
    elif 'solana' in message_text or 'transaction' in message_text:
        artifact_type = ArtifactType.SOLANA_TRANSACTION
    
    if artifact_type:
        # Create artifact
        solana_tx = None

        if artifact_type == ArtifactType.SOLANA_TRANSACTION:
            try:
                tx_payload = json.loads(msg.message)
                solana_tx = SolanaTransaction(**tx_payload)
            except Exception as exc:
                ctx.logger.warning(f"Failed to parse Solana transaction payload: {exc}")

        artifact = Artifact(
            type=artifact_type,
            content=msg.message,
            user_id=msg.user_id,
            solana_tx=solana_tx
        )
        
        # Process artifact
        ticket = core.receive_artifact(artifact)
        analysis_request = core.package_for_analysis(ticket)
        
        ctx.logger.info(f"Created ticket {ticket.ticket_id} for analysis")
        
        # Send to AnalyzerAgent if available
        if core.analyzer_address:
            try:
                # Send analysis request to AnalyzerAgent
                await ctx.send(core.analyzer_address, analysis_request)
                # ctx.logger.info(f"Sent analysis request to AnalyzerAgent for ticket {ticket.ticket_id}")
                
                response = ChatResponse(
                    response=f"✅ Received your {artifact_type} for analysis. Ticket ID: {ticket.ticket_id}\n\n🔍 Sending to AnalyzerAgent for processing...",
                    requires_action=True,
                    action_type="analysis"
                )
            except Exception as e:
                ctx.logger.error(f"Failed to send to AnalyzerAgent: {e}")
                response = ChatResponse(
                    response=f"✅ Received your {artifact_type} for analysis. Ticket ID: {ticket.ticket_id}\n\n⚠️ AnalyzerAgent not available - analysis queued",
                    requires_action=True,
                    action_type="analysis"
                )
        else:
            response = ChatResponse(
                response=f"✅ Received your {artifact_type} for analysis. Ticket ID: {ticket.ticket_id}\n\n⚠️ AnalyzerAgent not configured",
                requires_action=True,
                action_type="analysis"
            )
    else:
        response = ChatResponse(
            response="Hello! I can analyze URLs and Solana transactions for phishing threats. What would you like me to check?",
            requires_action=False
        )
    
    await ctx.send(sender, response)

@intake_agent.on_message(model=SignedReport)
async def handle_analysis_result(ctx: Context, sender: str, msg: SignedReport):
    ctx.logger.info(f"Received analysis result: {msg.verdict}")

    # Forward to referee if configured, wait for verification
    referee_verdict = None
    if getattr(core, "referee_address", None):
        try:
            # Send the signed report to referee agent for verification
            ctx.logger.info(f"Sending SignedReport for ticket {getattr(msg, 'ticket_id', '')} to RefereeAgent @ {core.referee_address}")
            await ctx.send(core.referee_address, msg)

            # Wait for a ChatResponse (verified verdict)
            @intake_agent.on_message(model=ChatResponse)
            async def receive_verification(ctx2: Context, sender2: str, verification_resp: ChatResponse):
                nonlocal referee_verdict
                referee_verdict = verification_resp.response
                ctx2.logger.info(f"Received referee verdict: {referee_verdict}")

            # Wait up to ~5 seconds (rudimentary coroutine yield; in production, use a pub/sub/push or state channel)
            for _ in range(25):
                await asyncio.sleep(0.2)
                if referee_verdict:
                    break
        except Exception as exc:
            ctx.logger.error(f"Error during referee signature verification: {exc}")

    # Send to OnchainAgent after referee (regardless of referee outcome)
    if getattr(core, "onchain_address", None):
        try:
            ctx.logger.info(f"Forwarding SignedReport for ticket {getattr(msg, 'ticket_id', '')} to OnchainAgent @ {core.onchain_address}")
            await ctx.send(core.onchain_address, msg)
        except Exception as exc:
            ctx.logger.error(f"Failed to forward SignedReport to OnchainAgent: {exc}")

    # Present verdict to user
    if referee_verdict:
        verdict_message = f"\n🔍 Analysis Complete!\nReferee says: {referee_verdict}"
    else:
        verdict_message = f"""
🔍 Analysis Complete!

Severity: {msg.severity.upper()}
Verdict: {msg.verdict}
Evidence: {msg.evidence}

Report Hash: {msg.report_hash}
Timestamp: {msg.timestamp}
        """
    # Log and send to user
    ctx.logger.info(f"Analysis result: {verdict_message}")

if __name__ == "__main__":
    intake_agent.run()