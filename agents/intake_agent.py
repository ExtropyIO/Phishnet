"""
IntakeAgent - uAgents Framework Implementation
Receives user artifacts and initiates analysis workflow
Uses proper uAgents communication patterns
"""

import os
import uuid
from datetime import datetime

from typing import Dict, Any
from uagents import Agent, Context, Model
from threat_detection.models.url_analyzer import URLAnalyzer

from shared.health import start_health_server

start_health_server()


# Import schemas
try:
    from shared.schemas.artifact_schema import (
        Artifact, ArtifactType, AnalysisTicket, AnalysisRequest, SignedReport,
        ChatMessage, ChatResponse
    )
except ImportError:
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from shared.schemas.artifact_schema import (
        Artifact, ArtifactType, AnalysisTicket, AnalysisRequest, SignedReport,
        ChatMessage, ChatResponse
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
        artifact = Artifact(
            type=artifact_type,
            content=msg.message,
            user_id=msg.user_id
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
                ctx.logger.info(f"Sent analysis request to AnalyzerAgent for ticket {ticket.ticket_id}")
                
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
    """Handle analysis results from AnalyzerAgent"""
    ctx.logger.info(f"Received analysis result: {msg.verdict}")
    
    # Present verdict to user (simplified for now)
    verdict_message = f"""
🔍 Analysis Complete!

Severity: {msg.severity.upper()}
Verdict: {msg.verdict}
Evidence: {msg.evidence}

Report Hash: {msg.report_hash}
Timestamp: {msg.timestamp}
    """
    
    # In a full implementation, you'd send this back to the original user
    ctx.logger.info(f"Analysis result: {verdict_message}")

if __name__ == "__main__":
    intake_agent.run()