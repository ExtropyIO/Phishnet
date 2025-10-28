"""
AnalyzerAgent - performs deterministic analysis (stub here) and returns a SignedReport.
Publishes public endpoint via shared bootstrap and exposes /analyzer/health on :8080.
"""

import os
import hashlib
from datetime import datetime

from uagents import Agent, Context

from shared.agent_bootstrap import build_agent, start_sidecars, run_agent

try:
    from shared.schemas.artifact_schema import (
        AnalysisRequest, SignedReport, ChatMessage, ChatResponse
    )
except ImportError:
    import sys, pathlib
    sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
    from shared.schemas.artifact_schema import (
        AnalysisRequest, SignedReport, ChatMessage, ChatResponse
    )

agent: Agent = build_agent("AnalyzerAgent")
start_sidecars()


def _score(artifact_content: str) -> float:
    """Very naive, deterministic stub scoring (replace with real pipeline)."""
    lower = (artifact_content or "").lower()
    s = 0.0
    if "http" in lower: s += 0.2
    if "login" in lower or "wallet" in lower: s += 0.4
    if "bonus" in lower or "airdrop" in lower: s += 0.4
    return min(1.0, s)

def _verdict(score: float) -> str:
    if score >= 0.8: return "malicious"
    if score >= 0.5: return "suspicious"
    return "benign"


@agent.on_event("startup")
async def startup(ctx: Context):
    ctx.logger.info("AnalyzerAgent ready")
    pb = os.getenv("PUBLIC_BASE_URL")
    ctx.logger.info(f"Public endpoint: {pb.rstrip('/')+'/submit' if pb else '(unset)'}")


@agent.on_message(model=AnalysisRequest)
async def handle_analysis(ctx: Context, sender: str, msg: AnalysisRequest):
    content = msg.artifact.content
    score = _score(content)
    verdict = _verdict(score)

    evidence = {
        "signals": {
            "has_http": "http" in content.lower(),
            "has_login_or_wallet": any(k in content.lower() for k in ["login", "wallet"]),
            "has_incentive_bait": any(k in content.lower() for k in ["bonus", "airdrop"]),
        },
        "score": score,
    }

    raw = f"{msg.ticket_id}|{content}|{score}|{verdict}|{datetime.utcnow().isoformat()}"
    report_hash = hashlib.sha256(raw.encode()).hexdigest()

    report = SignedReport(
        ticket_id=msg.ticket_id,
        severity="high" if verdict == "malicious" else ("medium" if verdict == "suspicious" else "low"),
        verdict=verdict,
        evidence=evidence,
        report_hash=report_hash,
        timestamp=datetime.utcnow().isoformat(),
        signature="stub-signature",  # replace with enclave signing
    )

    await ctx.send(sender, report)


# Optional chat endpoint for quick testing
@agent.on_message(model=ChatMessage)
async def handle_chat(ctx: Context, sender: str, msg: ChatMessage):
    await ctx.send(sender, ChatResponse(
        response="Analyzer is running. Send an AnalysisRequest to analyse artifacts.",
        requires_action=False
    ))


if __name__ == "__main__":
    run_agent(agent)
