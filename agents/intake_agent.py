import os
import uuid
import json
from datetime import datetime
from typing import Dict, Any
from uagents import Agent, Context, Model, Protocol
from uagents_core.contrib.protocols.chat import (
    ChatMessage as CPChatMessage,
    ChatAcknowledgement as CPChatAcknowledgement,
    TextContent as CPTextContent,
    EndSessionContent as CPEndSessionContent,
    StartSessionContent as CPStartSessionContent,
    chat_protocol_spec,
)
import asyncio

from schema import (
        Artifact, ArtifactType, AnalysisTicket, AnalysisRequest, SignedReport,
        ChatMessage, ChatResponse, SolanaTransaction
)

intake_agent = Agent(
    name="IntakeAgent",
    seed="intake-agent-seed"
)

chat_proto = Protocol(spec=chat_protocol_spec)

@chat_proto.on_message(CPChatMessage)
async def handle_chat_protocol_message(ctx: Context, sender: str, msg: CPChatMessage):
    """Handle chat protocol messages from Agentverse"""
    ctx.logger.info(f"Received chat protocol message from {sender}")
    
    # Send acknowledgement
    await ctx.send(sender, CPChatAcknowledgement(
        timestamp=datetime.utcnow(),
        acknowledged_msg_id=getattr(msg, "msg_id", None)
    ))
    
    # Extract text content from message
    text_parts = []
    for item in (msg.content or []):
        if isinstance(item, CPStartSessionContent):
            ctx.logger.info(f"Session started with {sender}")
        elif isinstance(item, CPTextContent):
            text_parts.append(item.text)
        elif isinstance(item, CPEndSessionContent):
            ctx.logger.info(f"Session ended with {sender}")
    
    raw_text = " ".join(text_parts).strip()
    
    if not raw_text:
        await ctx.send(sender, CPChatMessage(
            timestamp=datetime.utcnow(),
            msg_id=uuid.uuid4(),
            content=[CPTextContent(type="text", text="Please provide a URL or Solana transaction JSON for analysis.")]
        ))
        return
    
    # Detect artifact type
    lower_text = raw_text.lower()
    artifact_type = None
    if 'url' in lower_text or lower_text.startswith('http'):
        artifact_type = ArtifactType.URL
    elif 'solana' in lower_text or 'transaction' in lower_text or raw_text.strip().startswith('{'):
        artifact_type = ArtifactType.SOLANA_TRANSACTION
    
    if not artifact_type:
        await ctx.send(sender, CPChatMessage(
            timestamp=datetime.utcnow(),
            msg_id=uuid.uuid4(),
            content=[CPTextContent(type="text", text="I can analyze URLs and Solana transactions. Please send a URL or Solana transaction JSON.")]
        ))
        return
    
    # Parse Solana transaction if needed
    solana_tx = None
    if artifact_type == ArtifactType.SOLANA_TRANSACTION:
        try:
            tx_payload = json.loads(raw_text)
            solana_tx = SolanaTransaction(**tx_payload)
        except Exception as exc:
            ctx.logger.warning(f"Failed to parse Solana transaction: {exc}")
    
    # Create artifact and ticket
    artifact = Artifact(
        type=artifact_type,
        content=raw_text,
        user_id=None,
        solana_tx=solana_tx
    )
    ticket = core.receive_artifact(artifact)
    analysis_request = core.package_for_analysis(ticket)
    
    # Track chat sender for this ticket
    IntakeAgentCore.chat_ticket_senders[ticket.ticket_id] = sender
    
    ctx.logger.info(f"Created ticket {ticket.ticket_id} for chat protocol request")
    
    # Send to AnalyzerAgent
    if core.analyzer_address:
        try:
            await ctx.send(core.analyzer_address, analysis_request)
            await ctx.send(sender, CPChatMessage(
                timestamp=datetime.utcnow(),
                msg_id=uuid.uuid4(),
                content=[CPTextContent(type="text", text=f"Received. Ticket ID: {ticket.ticket_id}. Running analysis...")]
            ))
        except Exception as e:
            ctx.logger.error(f"Failed to send to AnalyzerAgent: {e}")
            await ctx.send(sender, CPChatMessage(
                timestamp=datetime.utcnow(),
                msg_id=uuid.uuid4(),
                content=[CPTextContent(type="text", text=f"Received. Ticket ID: {ticket.ticket_id}. Analyzer unavailable.")]
            ))
    else:
        await ctx.send(sender, CPChatMessage(
            timestamp=datetime.utcnow(),
            msg_id=uuid.uuid4(),
            content=[CPTextContent(type="text", text="Analyzer not configured.")]
        ))

# Handle chat protocol acknowledgements
@chat_proto.on_message(CPChatAcknowledgement)
async def handle_chat_protocol_ack(ctx: Context, sender: str, msg: CPChatAcknowledgement):
    ctx.logger.info(f"Received chat protocol acknowledgement from {sender} for message: {getattr(msg, 'acknowledged_msg_id', None)}")


# Core agent logic
class IntakeAgentCore:

    analyzer_address = "agent1qft9yl88cvl9nad2jst2pj7z3yzrgctmgauzky7vqjmu6mwy3k0xsee4aw2"
    referee_address = "agent1q2ewhrl4f4qhhsyjt6wx36rz4xghv3wfpp9x9rt5fkrjqh5pn7sg736dz5g"
    onchain_address = "agent1qgt3szegqq32c6x2q2ne5ts5j3er5zj0z2y3nk2vwypej9zuqekyke20t02"
    tickets: Dict[str, AnalysisTicket] = {}
    chat_ticket_senders: Dict[str, str] = {}  # Map ticket_id -> chat protocol sender address
    
    def receive_artifact(self, artifact: Artifact) -> AnalysisTicket:
        """Receive and validate artifact from user"""
        ticket_id = str(uuid.uuid4())
        ticket = AnalysisTicket(
            ticket_id=ticket_id,
            artifact=artifact,
            timestamp=datetime.now().isoformat(),
            status="received"
        )
        IntakeAgentCore.tickets[ticket_id] = ticket
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
        f"""
    # Log and send to user
    ctx.logger.info(f"Analysis result: {verdict_message}")
    
    # If request came from chat protocol, send response via chat protocol
    ticket_id = getattr(msg, 'ticket_id', None)
    if ticket_id and ticket_id in IntakeAgentCore.chat_ticket_senders:
        chat_sender = IntakeAgentCore.chat_ticket_senders.pop(ticket_id, None)
        if chat_sender:
            summary = f"Analysis Complete! Verdict: {msg.verdict.upper()} | Severity: {msg.severity.upper()}\nReport Hash: {msg.report_hash}"
            await ctx.send(chat_sender, CPChatMessage(
                timestamp=datetime.utcnow(),
                msg_id=uuid.uuid4(),
                content=[CPTextContent(type="text", text=summary), CPEndSessionContent(type="end-session")]
            ))

# Include chat protocol and publish manifest to Agentverse
intake_agent.include(chat_proto, publish_manifest=True)

if __name__ == "__main__":
    intake_agent.run()