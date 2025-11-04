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
        ChatMessage, ChatResponse, SolanaTransaction, LogResponse
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

    # Include chat sender in the analysis request
    analysis_request = core.package_for_analysis(ticket, sender)

    ctx.logger.info(f"Created ticket {ticket.ticket_id} for chat protocol request")
    ctx.logger.info(f"Sending analysis request with chat_sender: {sender}")

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

@chat_proto.on_message(CPChatAcknowledgement)
async def handle_chat_protocol_ack(ctx: Context, sender: str, msg: CPChatAcknowledgement):
    ctx.logger.info(f"Received chat protocol acknowledgement from {sender} for message: {getattr(msg, 'acknowledged_msg_id', None)}")


# Core agent logic

# Global storage for original reports (minimal state management)
_original_reports: Dict[str, SignedReport] = {}

class IntakeAgentCore:

    analyzer_address = "agent1qft9yl88cvl9nad2jst2pj7z3yzrgctmgauzky7vqjmu6mwy3k0xsee4aw2"
    referee_address = "agent1q2ewhrl4f4qhhsyjt6wx36rz4xghv3wfpp9x9rt5fkrjqh5pn7sg736dz5g"
    onchain_address = "agent1qgt3szegqq32c6x2q2ne5ts5j3er5zj0z2y3nk2vwypej9zuqekyke20t02"
    tickets: Dict[str, AnalysisTicket] = {}
    
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
    
    def package_for_analysis(self, ticket: AnalysisTicket, chat_sender: str = None) -> AnalysisRequest:
        """Package artifact for TEE analysis"""
        return AnalysisRequest(
            ticket_id=ticket.ticket_id,
            artifact=ticket.artifact,
            nonce="",  # Will be filled by AnalyzerAgent
            session_id="",
            chat_sender=chat_sender  # Pass through the chat sender
        )

core = IntakeAgentCore()

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

@intake_agent.on_message(model=ChatResponse)
async def handle_chat_response(ctx: Context, sender: str, msg: ChatResponse):
    """Handle ChatResponse messages (legacy compatibility)"""
    ctx.logger.info(f"Received ChatResponse from {sender}: {msg.response}")

@intake_agent.on_message(model=LogResponse)
async def handle_onchain_log(ctx: Context, sender: str, msg: LogResponse):
    """Handle blockchain transaction confirmation from OnchainAgent"""
    ctx.logger.info(f"Received LogResponse from {sender}: {msg.tx_signature}")
    
    # Store the log response - we'll match it to a ticket when sending final response
    # For now, just log it as the onchain agent responds asynchronously
    ctx.logger.info(f"Blockchain TX: {msg.tx_signature}")
    ctx.logger.info(f"Explorer: {msg.explorer_url}")
    ctx.logger.info(f"Confirmed: {msg.confirmed}")

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
        
        ticket = core.receive_artifact(artifact)
        analysis_request = core.package_for_analysis(ticket, sender)

        ctx.logger.info(f"Created ticket {ticket.ticket_id} for analysis")

        if core.analyzer_address:
            try:
                await ctx.send(core.analyzer_address, analysis_request)
                
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
    ticket_id = getattr(msg, 'ticket_id', 'unknown')
    ctx.logger.info(f"Received SignedReport: {msg.verdict} from {sender} (attestation: {msg.attestation}) for ticket {ticket_id}")
    
    # Check if this is a verified report coming back from referee
    is_verified = msg.attestation and '_verified' in msg.attestation
    has_referee_verification = (
        isinstance(msg.evidence, dict) and 
        'referee_verification' in msg.evidence
    )
    
    if is_verified or has_referee_verification:
        # This is the verified report coming back from referee
        ctx.logger.info(f"Received VERIFIED report from referee for ticket {ticket_id}")
        
        # Extract verification status from the verified report
        verification_status = "UNKNOWN"
        if isinstance(msg.evidence, dict) and 'referee_verification' in msg.evidence:
            verification_status = msg.evidence['referee_verification']['status']
        
        final_message = f"""🔍 Analysis Complete!
        

Referee Verification: {verification_status}

Verdict: {msg.verdict.upper()}

Severity: {msg.severity.upper()}

Report Hash: {msg.report_hash}

Attestation: {msg.attestation}"""
        
        # Send final response to user
        chat_sender = getattr(msg, 'chat_sender', None)
        if chat_sender:
            try:
                await ctx.send(chat_sender, CPChatMessage(
                    timestamp=datetime.utcnow(),
                    msg_id=uuid.uuid4(),
                    content=[CPTextContent(type="text", text=final_message), CPEndSessionContent(type="end-session")]
                ))
                ctx.logger.info(f"Final verified verdict sent to user")
            except Exception as exc:
                ctx.logger.error(f"Failed to send to user: {exc}")
        else:
            ctx.logger.warning(f"No chat_sender found in verified report")
        
        # Forward verified report to OnchainAgent
        if core.onchain_address:
            try:
                await ctx.send(core.onchain_address, msg)
                ctx.logger.info(f"Forwarded to OnchainAgent")
            except Exception as exc:
                ctx.logger.error(f"Failed to forward to OnchainAgent: {exc}")
        
        _original_reports.pop(ticket_id, None)
        return
        
    else:
        ctx.logger.info(f"Received initial analysis from analyzer for ticket {ticket_id}")
        
        _original_reports[ticket_id] = msg
        
        if core.referee_address:
            try:
                ctx.logger.info(f"Forwarding to Referee for verification...")
                
                await ctx.send(core.referee_address, msg)
                ctx.logger.info(f"Sent to referee, verified report will arrive separately")
                
                return
                    
            except Exception as exc:
                ctx.logger.error(f"Referee verification error: {exc}")
        
        final_message = f"""🔍 Analysis Complete!

⚠️ No Referee Verification

Verdict: {msg.verdict.upper()}

Severity: {msg.severity.upper()}

Report Hash: {msg.report_hash}"""
        
        ctx.logger.info(f"Sending unverified verdict to user...")
        
        chat_sender = getattr(msg, 'chat_sender', None)
        if chat_sender:
            try:
                await ctx.send(chat_sender, CPChatMessage(
                    timestamp=datetime.utcnow(),
                    msg_id=uuid.uuid4(),
                    content=[CPTextContent(type="text", text=final_message), CPEndSessionContent(type="end-session")]
                ))
                ctx.logger.info(f"Unverified verdict sent to user")
            except Exception as exc:
                ctx.logger.error(f"Failed to send to user: {exc}")
        
        if core.onchain_address:
            try:
                await ctx.send(core.onchain_address, msg)
            except Exception as exc:
                ctx.logger.error(f"Failed to forward to OnchainAgent: {exc}")
        
        _original_reports.pop(ticket_id, None)

intake_agent.include(chat_proto, publish_manifest=True)

if __name__ == "__main__":
    intake_agent.run()