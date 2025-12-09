import os
import uuid
from datetime import datetime
from typing import Optional
from uagents import Agent, Context, Model
from uagents_core.contrib.protocols.chat import (
    ChatMessage as CPChatMessage,
    TextContent as CPTextContent,
    StartSessionContent as CPStartSessionContent,
    chat_protocol_spec,
)
from uagents import Protocol

GATEWAY_PORT = int(os.getenv("GATEWAY_AGENT_PORT", "8007"))
GATEWAY_ENDPOINT = os.getenv(
    "GATEWAY_AGENT_ENDPOINT",
    f"http://127.0.0.1:{GATEWAY_PORT}/submit"
)
INTAKE_AGENT_ADDRESS = os.getenv(
    "INTAKE_AGENT_ADDRESS",
    "agent1qtvyywwfn79saexjcd0hvp347ymdutp37xjhd6qcnuu0lruvypta69ctw45"
)

gateway_agent = Agent(
    name="HttpGateway",
    seed="gateway-agent-seed",
    port=GATEWAY_PORT,
    endpoint=GATEWAY_ENDPOINT,
)

class SubmitRequest(Model):
    content: str
    user_id: Optional[str] = None

class SubmitResponse(Model):
    success: bool
    message: str
    item_id: Optional[str] = None

chat_proto = Protocol(spec=chat_protocol_spec)

async def send_to_intake(ctx: Context, content: str, user_id: Optional[str] = None):

    try:
        msg_id = uuid.uuid4()
        chat_message = CPChatMessage(
            timestamp=datetime.utcnow(),
            msg_id=msg_id,
            content=[
                CPStartSessionContent(type="start-session"),
                CPTextContent(type="text", text=content)
            ]
        )
        
        await ctx.send(INTAKE_AGENT_ADDRESS, chat_message)
        
        preview = content[:50] + "..." if len(content) > 50 else content
        ctx.logger.info(f"Sent content to IntakeAgent: {preview} (user_id: {user_id})")
        return True
    except Exception as e:
        ctx.logger.error(f"Failed to send to IntakeAgent: {e}")
        return False

@gateway_agent.on_rest_post("/submit", SubmitRequest, SubmitResponse)
async def handle_submit(ctx: Context, req: SubmitRequest) -> SubmitResponse:
    # Generate item ID for tracking
    item_id = str(uuid.uuid4())
    
    success = await send_to_intake(ctx, req.content, req.user_id)
    
    if success:
        preview = req.content[:50] + "..." if len(req.content) > 50 else req.content
        ctx.logger.info(f"Processed submission {item_id}: {preview} (user_id: {req.user_id})")
        return SubmitResponse(
            success=True,
            message="Successfully submitted for analysis",
            item_id=item_id
        )
    else:
        ctx.logger.error(f"Failed to process submission {item_id}")
        return SubmitResponse(
            success=False,
            message="Failed to send to IntakeAgent",
            item_id=item_id
        )

@gateway_agent.on_event("startup")
async def startup(ctx: Context):
    ctx.logger.info("HttpGateway agent started")
    ctx.logger.info(f"Agent address: {gateway_agent.address}")
    ctx.logger.info(f"HTTP endpoint: {GATEWAY_ENDPOINT}")
    ctx.logger.info(f"IntakeAgent address: {INTAKE_AGENT_ADDRESS}")

@gateway_agent.on_message(model=CPChatMessage)
async def handle_chat_message(ctx: Context, sender: str, msg: CPChatMessage):
    ctx.logger.info(f"Received chat message from {sender}")

gateway_agent.include(chat_proto, publish_manifest=True)

if __name__ == "__main__":
    
    gateway_agent.run()