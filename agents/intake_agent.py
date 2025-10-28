"""
IntakeAgent - receives artifacts and initiates analysis workflow.
Publishes a public endpoint via shared bootstrap and exposes /intake/health on :8080.
"""

import os
import uuid
from datetime import datetime
from typing import Dict

from uagents import Agent, Context



# Import schemas
try:
    from shared.schemas.artifact_schema import (
        Artifact, ArtifactType, AnalysisTicket, AnalysisRequest, SignedReport,
        ChatMessage, ChatResponse
    )
except ImportError:
    import sys, pathlib
    sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
    from shared.schemas.artifact_schema import (
        Artifact, ArtifactType, AnalysisTicket, AnalysisRequest, SignedReport,
        ChatMessage, ChatResponse
    )

# Import MeTTa KG client
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from metta_kg_client import MeTTaKGClient

# Create agent
chat_protocol = Protocol(name="PhishingAnalysisProtocol", version="1.0.0")

# Start the :8080 health/proxy (uses SERVICE_BASE, PORT, UAGENTS_PORT envs)
start_sidecars()

intake_agent = Agent(
    name="IntakeAgent",
    seed="intake-agent-seed",
    port=8001,
    protocols=[query_protocol],
    mailbox=True,
    endpoint="http://TeeAge-Alb16-asYi7vJYnLGj-755747286.eu-west-1.elb.amazonaws.com/intake/"
)

# -------------------------
# Core agent logic
# -------------------------
class IntakeAgentCore:
    def __init__(self):
        self.tickets: Dict[str, AnalysisTicket] = {}
        self.analyzer_address = os.getenv("ANALYZER_ADDRESS")

        self.kg_client = MeTTaKGClient()
        self.ticket_senders: Dict[str, str] = {}
  # Track original senders for each ticket (for agent-to-agent messaging)
    # def receive_artifact(self, artifact: Artifact) -> AnalysisTicket:  
    
    def create_analysis_request(self, artifact: Artifact, sender: str) -> AnalysisRequest:
        """Create analysis request directly from artifact"""
        ticket_id = str(uuid.uuid4())
        ticket = AnalysisTicket(
            ticket_id=ticket_id,
            artifact=artifact,
            timestamp=datetime.now().isoformat(),
            status="received",
        )
        self.tickets[ticket_id] = ticket

        # Track the original sender for this ticket
        self.ticket_senders[ticket_id] = sender

        # Add submission to KG
        self.kg_client.add_fact(
            fact_type="url_submission" if artifact.type == ArtifactType.URL else "transaction_submission",
            fact_value=artifact.content,
            metadata={"user_id": artifact.user_id}
        )
        
        # Create analysis request
        return AnalysisRequest(
            ticket_id=ticket.ticket_id,
            artifact=ticket.artifact,
            nonce="",      # set by analyzer
            session_id="", # set by analyzer
        )

core = IntakeAgentCore()


# -------------------------
# Handlers
# -------------------------
@agent.on_event("startup")
async def startup(ctx: Context):
    ctx.logger.info("IntakeAgent started - MeTTa KG enabled")
    ctx.logger.info(f"Agent address: {intake_agent.address}")


@agent.on_message(model=ChatMessage)
async def handle_chat(ctx: Context, sender: str, msg: ChatMessage):
    """Handle chat messages from users"""
    ctx.logger.info(f"Received chat from {sender}: {msg.message}")
    
    # Determine artifact type
    message_text = msg.message.lower()
    if 'url' in message_text or message_text.startswith('http'):
        artifact_type = ArtifactType.URL
    elif 'solana' in message_text or 'transaction' in message_text:
        artifact_type = ArtifactType.SOLANA_TRANSACTION

    if artifact_type:
        artifact = Artifact(type=artifact_type, content=msg.message, user_id=msg.user_id)
        ticket = core.receive_artifact(artifact)
        analysis_request = core.package_for_analysis(ticket)

        ctx.logger.info(f"Created ticket {ticket.ticket_id} for analysis")

        if core.analyzer_address:
            try:
                await ctx.send(core.analyzer_address, analysis_request)
                response = ChatResponse(
                    response=f"✅ Received your {artifact_type} for analysis. Ticket ID: {ticket.ticket_id}\n🔍 Sending to AnalyzerAgent...",
                    requires_action=True,
                    action_type="analysis"
                )
            except Exception as e:
                ctx.logger.error(f"Failed to send to AnalyzerAgent: {e}")
                response = ChatResponse(
                    response=f"✅ Received your {artifact_type} for analysis. Ticket ID: {ticket.ticket_id}\n⚠️ AnalyzerAgent not available - queued",
                    requires_action=True,
                    action_type="analysis"
                )
        else:
            response = ChatResponse(
                response=f"✅ Received your {artifact_type} for analysis. Ticket ID: {ticket.ticket_id}\n⚠️ AnalyzerAgent not configured",
                requires_action=True,
                action_type="analysis"
            )
    else:
        response = ChatResponse(
            response="Hello! I can analyze URLs for phishing threats. Please provide a URL.",
            requires_action=False
        )

        await ctx.send(sender, response)
        return
    
    # Create artifact and analysis request
    artifact = Artifact(
        type=artifact_type,
        content=msg.message,
        user_id=msg.user_id
    )
    analysis_request = core.create_analysis_request(artifact, sender)
    
    ctx.logger.info(f"Created ticket {analysis_request.ticket_id} for analysis")
    
    if core.analyzer_address:
        try:
            await ctx.send(core.analyzer_address, req)
            return await ctx.send(sender, ChatResponse(
                response=f"✅ Received your {a_type}. Ticket: {ticket.ticket_id}\n🔍 Sent to AnalyzerAgent.",
                requires_action=True, action_type="analysis"
            ))
        except Exception as e:
            ctx.logger.error(f"send to analyzer failed: {e}")

@chat_protocol.on_message(model=SignedReport)
async def handle_analysis_result(ctx: Context, sender: str, msg: SignedReport):
    ctx.logger.info(f"Received analysis result: {msg.verdict}")
    
    # Get the original sender using ticket_id
    ticket_id = msg.ticket_id
    original_sender = core.ticket_senders.get(ticket_id) if ticket_id else None
    
    if original_sender:
        # Create comprehensive response for the user
        verdict_emoji = "🟢" if msg.verdict == "safe" else "🔴"
        severity_emoji = {
            "low": "🟡",
            "medium": "🟠", 
            "high": "🔴",
            "critical": "🚨"
        }.get(msg.severity.lower(), "⚪")
        
        response_text = f"""
{verdict_emoji} **Analysis Complete!**


@agent.on_message(model=SignedReport)
async def handle_report(ctx: Context, sender: str, msg: SignedReport):
    ctx.logger.info("Analysis Complete")
    ctx.logger.info(f"Severity: {msg.severity.upper()} | Verdict: {msg.verdict}")
    ctx.logger.debug(f"Evidence: {msg.evidence}")
    ctx.logger.info(f"Report: {msg.report_hash} @ {msg.timestamp}")


# HTTP endpoint for Agentverse chat
@intake_agent.on_rest_post("/chat", ChatMessage, ChatResponse)
async def chat_endpoint(ctx: Context, request: ChatMessage) -> ChatResponse:
    ctx.logger.info(f"HTTP chat request: {request.message}")
    
    message_text = request.message.lower()
    if 'url' in message_text or message_text.startswith('http'):
        artifact_type = ArtifactType.URL
    elif 'solana' in message_text or 'transaction' in message_text:
        artifact_type = ArtifactType.SOLANA_TRANSACTION
    else:
        return ChatResponse(
            response="Hello! I can analyze URLs and Solana transactions for phishing threats. What would you like me to check?",
            requires_action=False
        )
    
    # Create artifact and analysis request
    artifact = Artifact(
        type=artifact_type,
        content=request.message,
        user_id=request.user_id
    )
    analysis_request = core.create_analysis_request(artifact, "http_client")
    
    ctx.logger.info(f"Created ticket {analysis_request.ticket_id} for HTTP analysis")
    
    if core.analyzer_address:
        try:
            await ctx.send(core.analyzer_address, analysis_request)
            ctx.logger.info(f"Sent analysis request to AnalyzerAgent for ticket {analysis_request.ticket_id}")
            response_text = f"Received your {artifact_type} for analysis. Ticket ID: {analysis_request.ticket_id}\n\n🔍 Sending to AnalyzerAgent for processing..."
        except Exception as e:
            ctx.logger.error(f"Failed to send to AnalyzerAgent: {e}")
            response_text = f"Received your {artifact_type} for analysis. Ticket ID: {analysis_request.ticket_id}\n\nAnalyzerAgent not available - analysis queued"
    else:
        response_text = f"Received your {artifact_type} for analysis. Ticket ID: {analysis_request.ticket_id}\n\nAnalyzerAgent not configured"
    
    return ChatResponse(
        response=response_text,
        requires_action=True,
        action_type="analysis"
    )

if __name__ == "__main__":
    intake_agent.include(chat_protocol, publish_manifest=True)
    intake_agent.run()
