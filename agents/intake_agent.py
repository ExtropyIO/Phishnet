"""
IntakeAgent - First point of contact for user artifacts
Role: Receives artifacts, packages data, presents initial verdicts
Team Member: Josh (Python agents and connecting them)
"""

import os
import uuid
from datetime import datetime
from typing import Dict, Any

from uagents import Agent, Context, Protocol, Model
# Option 1: Package import (preferred)
try:
    from shared.schemas.artifact_schema import (
        Artifact, ArtifactType, AnalysisTicket, ChatMessage, ChatResponse,
        AnalysisRequest, SignedReport, VerifiedVerdict, LogRequest, LogResponse
    )
except ImportError:
    # Option 2: Relative import fallback
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from shared.schemas.artifact_schema import (
        Artifact, ArtifactType, AnalysisTicket, ChatMessage, ChatResponse,
        AnalysisRequest, SignedReport, VerifiedVerdict, LogRequest, LogResponse
    )

# Core agent logic (framework-agnostic)
class IntakeAgentCore:
    def __init__(self):
        self.tickets: Dict[str, AnalysisTicket] = {}
        self.analyzer_address = None  # Will be set by uAgents adapter
    
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
    
    def present_verdict(self, signed_report: SignedReport) -> str:
        """Present verdict to user in human-readable format"""
        return f"""
🔍 Analysis Complete!

Threat Level: {signed_report.threat_score}/10
Verdict: {signed_report.verdict}
Evidence: {signed_report.evidence}

Report Hash: {signed_report.report_hash}
Timestamp: {signed_report.timestamp}

        """

# uAgents integration (always available)
try:
    from uagents import Agent, Context, Protocol, Model
    UAGENTS_AVAILABLE = True
except ImportError:
    UAGENTS_AVAILABLE = False

core = IntakeAgentCore()

intake_agent = Agent(
    name="IntakeAgent",
    seed="intake-agent-seed",
    port=8001,
    endpoint=["http://127.0.0.1:8001/submit"],
    mailbox=True
)

# Chat Protocol for user interaction
chat_protocol = Protocol(name="chat", version="0.1")

@chat_protocol.on_message(model=ChatMessage, replies=ChatResponse)
async def handle_chat(ctx: Context, sender: str, msg: ChatMessage):
    """Handle chat messages from users"""
    ctx.logger.info(f"Received chat from {sender}: {msg.message}")
    
    # Simple artifact detection
    if any(keyword in msg.message.lower() for keyword in ['url', 'email', 'transaction', 'check', 'analyze']):
        # Extract artifact type and content
        artifact_type = ArtifactType.TEXT
        if 'url' in msg.message.lower():
            artifact_type = ArtifactType.URL
        elif 'email' in msg.message.lower():
            artifact_type = ArtifactType.EMAIL
        elif 'transaction' in msg.message.lower():
            artifact_type = ArtifactType.TRANSACTION
        
        # Create artifact
        artifact = Artifact(
            type=artifact_type,
            content=msg.message,
            user_id=msg.user_id
        )
        
        # Process artifact
        ticket = core.receive_artifact(artifact)
        analysis_request = core.package_for_analysis(ticket)
        
        # Send to AnalyzerAgent (placeholder - will implement)
        ctx.logger.info(f"Created ticket {ticket.ticket_id} for analysis")
        
        response = ChatResponse(
            response=f"✅ Received your {artifact_type} for analysis. Ticket ID: {ticket.ticket_id}",
            requires_action=True,
            action_type="analysis"
        )
    else:
        response = ChatResponse(
            response="Hello! I can analyze URLs, emails, transactions, or text for phishing threats. What would you like me to check?",
            requires_action=False
        )
    
    await ctx.send(sender, response)

# Analysis Protocol for communication with other agents
analysis_protocol = Protocol(name="analysis", version="0.1")

@analysis_protocol.on_message(model=SignedReport, replies=ChatResponse)
async def handle_analysis_result(ctx: Context, sender: str, msg: SignedReport):
    """Handle analysis results from AnalyzerAgent"""
    ctx.logger.info(f"Received analysis result: {msg.verdict}")
    
    # Present verdict to user
    verdict_message = core.present_verdict(msg)
    
    response = ChatResponse(
        response=verdict_message,
        requires_action=True,
        action_type="verification"
    )
    
    await ctx.send(sender, response)

intake_agent.include(chat_protocol)
intake_agent.include(analysis_protocol)

@intake_agent.on_event("startup")
async def startup(ctx: Context):
    ctx.logger.info("IntakeAgent started - ready to receive artifacts")
    ctx.logger.info(f"Agent address: {intake_agent.address}")

if __name__ == "__main__":
    if not UAGENTS_AVAILABLE:
        print("❌ uAgents not installed. Install with: pip install uagents")
        sys.exit(1)
    
    intake_agent.run()