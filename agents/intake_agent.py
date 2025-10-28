"""
IntakeAgent - receives artifacts and initiates analysis workflow.
Publishes a public endpoint via shared bootstrap and exposes /intake/health on :8080.
"""

import os
import uuid
from datetime import datetime
from typing import Dict

from uagents import Agent, Context

# shared bootstrap (public endpoint + manifest + :8080 proxy/health)
from shared.agent_bootstrap import build_agent, start_sidecars, run_agent

# Schemas
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

# Construct agent with public endpoint advertised in manifest
agent: Agent = build_agent("IntakeAgent")

# Start the :8080 health/proxy (uses SERVICE_BASE, PORT, UAGENTS_PORT envs)
start_sidecars()


# -------------------------
# Core agent logic
# -------------------------
class IntakeAgentCore:
    def __init__(self):
        self.tickets: Dict[str, AnalysisTicket] = {}
        self.analyzer_address = os.getenv("ANALYZER_ADDRESS")

    def receive_artifact(self, artifact: Artifact) -> AnalysisTicket:
        ticket_id = str(uuid.uuid4())
        ticket = AnalysisTicket(
            ticket_id=ticket_id,
            artifact=artifact,
            timestamp=datetime.now().isoformat(),
            status="received",
        )
        self.tickets[ticket_id] = ticket
        return ticket

    def to_request(self, ticket: AnalysisTicket) -> AnalysisRequest:
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
    ctx.logger.info("IntakeAgent started - ready to receive artifacts")
    ctx.logger.info(f"Address: {agent.address}")
    pb = os.getenv("PUBLIC_BASE_URL")
    ctx.logger.info(f"Public endpoint: {pb.rstrip('/')+'/submit' if pb else '(unset)'}")
    if core.analyzer_address:
        ctx.logger.info(f"AnalyzerAgent: {core.analyzer_address}")
    else:
        ctx.logger.warning("ANALYZER_ADDRESS not set - analysis will be queued")


@agent.on_message(model=ChatMessage)
async def handle_chat(ctx: Context, sender: str, msg: ChatMessage):
    text = (msg.message or "").strip()
    lower = text.lower()

    # simple intent → artifact type
    if lower.startswith("http") or " url" in lower:
        a_type = ArtifactType.URL
    elif "solana" in lower or "transaction" in lower:
        a_type = ArtifactType.SOLANA_TRANSACTION
    else:
        return await ctx.send(sender, ChatResponse(
            response="I can analyse URLs and Solana transactions for phishing. Send me a link or a transaction.",
            requires_action=False
        ))

    artifact = Artifact(type=a_type, content=text, user_id=msg.user_id)
    ticket = core.receive_artifact(artifact)
    req = core.to_request(ticket)

    if core.analyzer_address:
        try:
            await ctx.send(core.analyzer_address, req)
            return await ctx.send(sender, ChatResponse(
                response=f"✅ Received your {a_type}. Ticket: {ticket.ticket_id}\n🔍 Sent to AnalyzerAgent.",
                requires_action=True, action_type="analysis"
            ))
        except Exception as e:
            ctx.logger.error(f"send to analyzer failed: {e}")

    await ctx.send(sender, ChatResponse(
        response=f"✅ Received your {a_type}. Ticket: {ticket.ticket_id}\n⚠️ Analyzer unavailable; queued.",
        requires_action=True, action_type="analysis"
    ))


@agent.on_message(model=SignedReport)
async def handle_report(ctx: Context, sender: str, msg: SignedReport):
    ctx.logger.info("Analysis Complete")
    ctx.logger.info(f"Severity: {msg.severity.upper()} | Verdict: {msg.verdict}")
    ctx.logger.debug(f"Evidence: {msg.evidence}")
    ctx.logger.info(f"Report: {msg.report_hash} @ {msg.timestamp}")


# Entrypoint (runs uAgents on :8001)
if __name__ == "__main__":
    run_agent(agent)
