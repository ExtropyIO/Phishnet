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
    ctx.logger.info(f"Referee received SignedReport from {sender} for ticket {msg.ticket_id}")

    ok = _verify_stub(msg)
    verification_status = 'VALID' if ok else 'INVALID'
    ctx.logger.info(f"Verification: {verification_status} for ticket {msg.ticket_id}")

    verified_evidence = msg.evidence.copy() if isinstance(msg.evidence, dict) else {}
    verified_evidence['referee_verification'] = {
        'status': verification_status,
        'verified_by': 'referee_agent',
        'signature_valid': ok
    }
    
    verified_report = SignedReport(
        report_hash=msg.report_hash,
        attestation=f"{msg.attestation}_verified",
        signature=msg.signature,
        verdict=msg.verdict,
        severity=msg.severity,
        evidence=verified_evidence,
        timestamp=msg.timestamp,
        ticket_id=msg.ticket_id,
        chat_sender=msg.chat_sender
    )
    
    ctx.logger.info(f"Sending verified SignedReport back to {sender}")
    await ctx.send(sender, verified_report)
    ctx.logger.info(f"Verified report sent to {sender}")

@agent.on_message(model=ChatMessage)
async def hello(ctx: Context, sender: str, msg: ChatMessage):
    await ctx.send(sender, ChatResponse(
        response="Referee is running. Send a SignedReport to verify.",
        requires_action=False
    ))

if __name__ == "__main__":
    agent.run()