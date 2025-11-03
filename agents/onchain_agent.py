import os
from uagents import Agent, Context

from schema import SignedReport, ChatMessage, ChatResponse

agent = Agent(
         name="OnchainAgent",
         seed="onchain-agent-seed"
     )

@agent.on_event("startup")
async def startup(ctx: Context):
    ctx.logger.info("OnchainAgent ready")


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
    agent.run()