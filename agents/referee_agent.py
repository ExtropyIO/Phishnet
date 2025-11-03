import os
from uagents import Agent, Context

from schema import SignedReport, ChatMessage, ChatResponse

agent = Agent(
         name="RefereeAgent",
         seed="referee-agent-seed",
     )

def _verify_stub(report: SignedReport) -> bool:
    # TODO: call enclave/attestation in tee/ later
    return bool(report.signature)

@agent.on_event("startup")
async def startup(ctx: Context):
    ctx.logger.info("RefereeAgent ready")

@agent.on_message(model=SignedReport)
async def verify_report(ctx: Context, sender: str, msg: SignedReport):
    ok = _verify_stub(msg)
    ctx.logger.info(f"Verification: {'valid' if ok else 'invalid'} for ticket {msg.ticket_id}")

    # For demo, reply back to sender (could be IntakeAgent) with a short verdict message
    await ctx.send(sender, ChatResponse(
        response=f"Referee verification for {msg.ticket_id}: {'VALID' if ok else 'INVALID'} signature; verdict={msg.verdict}",
        requires_action=False
    ))

@agent.on_message(model=ChatMessage)
async def hello(ctx: Context, sender: str, msg: ChatMessage):
    await ctx.send(sender, ChatResponse(
        response="Referee is running. Send a SignedReport to verify.",
        requires_action=False
    ))

if __name__ == "__main__":
    agent.run()