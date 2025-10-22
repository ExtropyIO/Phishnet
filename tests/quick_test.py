#!/usr/bin/env python3
"""
Quick test to verify uAgents communication
"""

import os
import asyncio
import sys
from uagents import Agent, Context, Model

# Import schemas
try:
    from shared.schemas.artifact_schema import ChatMessage, ChatResponse
except ImportError:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from shared.schemas.artifact_schema import ChatMessage, ChatResponse

# Create test client
test_client = Agent(
    name="QuickTestClient", 
    seed="quick-test-seed",
    port=8005
)

@test_client.on_event("startup")
async def startup(ctx: Context):
    """Send test message on startup"""
    intake_address = "agent1qwcf3u33m8at9txc6ksyj5vshts6xn0nftvsx25xnnxjvjrqsz9q296pfn0"  # From logs
    
    ctx.logger.info(f"Sending test message to IntakeAgent: {intake_address}")
    
    # Send test message
    test_message = ChatMessage(
        message="check url https://example-phish.test",
        user_id="test-user"
    )
    
    await ctx.send(intake_address, test_message)

@test_client.on_message(model=ChatResponse)
async def handle_response(ctx: Context, sender: str, msg: ChatResponse):
    """Handle response from IntakeAgent"""
    ctx.logger.info(f"Received response from {sender}:")
    ctx.logger.info(f"   Response: {msg.response}")
    ctx.logger.info(f"   Requires action: {msg.requires_action}")
    if msg.action_type:
        ctx.logger.info(f"   Action type: {msg.action_type}")

if __name__ == "__main__":
    print("Quick uAgents Communication Test")
    test_client.run()
