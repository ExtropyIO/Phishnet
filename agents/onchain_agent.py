"""
OnchainAgent - posts immutable logs or actions on-chain (stub).
Publishes public endpoint via shared bootstrap and exposes /onchain/health on :8080.
"""

import os
from uagents import Agent, Context

from shared.agent_bootstrap import build_agent, start_sidecars, run_agent

try:
    from shared.schemas.artifact_schema import SignedReport, ChatMessage, ChatResponse
except ImportError:
    import sys, pathlib
    sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
    from shared.schemas.artifact_schema import SignedReport, ChatMessage, ChatResponse

agent: Agent = build_agent("OnchainAgent")
start_sidecars()


@agent.on_event("startup")
async def startup(ctx: Context):
    ctx.logger.info("OnchainAgent ready")
    pb = os.getenv("PUBLIC_BASE_URL")
    ctx.logger.info(f"Public endpoint: {pb.rstrip('/')+'/submit' if pb else '(unset)'}")


@agent.on_message(model=SignedReport)
async def handle_report(ctx: Context, sender: str, msg: SignedReport):
    # TODO: push a minimal hash/log on-chain (Solana/EVM) via tee/onchain
    ctx.logger.info(f"(stub) would write report {msg.report_hash} with verdict {msg.verdict} to chain")


@agent.on_message(model=ChatMessage)
async def hello(ctx: Context, sender: str, msg: ChatMessage):
    await ctx.send(sender, ChatResponse(
        response="Onchain agent is running. Send a SignedReport to persist proof on-chain.",
        requires_action=False
    ))


if __name__ == "__main__":
    run_agent(agent)
