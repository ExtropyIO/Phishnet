"""
IntakeAgent - uAgents Framework Implementation
Receives user artifacts and initiates analysis workflow
Integrated with MeTTa Knowledge Graph for URL submissions
"""

import os
import uuid
from datetime import datetime
from typing import Dict, Any
from uagents import Agent, Context, Model

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

# Import MeTTa KG client
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from metta_kg_client import MeTTaKGClient

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
        self.kg_client = MeTTaKGClient()

    def receive_artifact(self, artifact: Artifact) -> AnalysisTicket:
        ticket_id = str(uuid.uuid4())
        ticket = AnalysisTicket(
            ticket_id=ticket_id,
            artifact=artifact,
            timestamp=datetime.now().isoformat(),
            status="received"
        )
        self.tickets[ticket_id] = ticket

        # Add submission to KG
        self.kg_client.add_fact(
            fact_type="url_submission" if artifact.type == ArtifactType.URL else "transaction_submission",
            fact_value=artifact.content,
            metadata={"user_id": artifact.user_id}
        )
        return ticket

    def package_for_analysis(self, ticket: AnalysisTicket) -> AnalysisRequest:
        return AnalysisRequest(
            ticket_id=ticket.ticket_id,
            artifact=ticket.artifact,
            nonce="",
            session_id=""
        )

core = IntakeAgentCore()

@intake_agent.on_event("startup")
async def startup(ctx: Context):
    ctx.logger.info("IntakeAgent started - MeTTa KG enabled")
    ctx.logger.info(f"Agent address: {intake_agent.address}")

@intake_agent.on_message(model=ChatMessage)
async def handle_chat(ctx: Context, sender: str, msg: ChatMessage):
    message_text = msg.message.lower()
    artifact_type = None
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

@intake_agent.on_message(model=SignedReport)
async def handle_analysis_result(ctx: Context, sender: str, msg: SignedReport):
    ctx.logger.info(f"Received analysis result: {msg.verdict}")
    verdict_message = f"""
  Analysis Complete!
Severity: {msg.severity.upper()}
Verdict: {msg.verdict}
Evidence: {msg.evidence}
Report Hash: {msg.report_hash}
Timestamp: {msg.timestamp}
"""
    ctx.logger.info(f"Analysis result: {verdict_message}")

if __name__ == "__main__":
    intake_agent.run()
