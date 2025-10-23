"""
Test URL Analysis Pipeline
Tests the complete flow: User → IntakeAgent → AnalyzerAgent → URL Analyzer → Response
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
    name="URLTestClient", 
    seed="url-test-seed",
    port=8006
)

@test_client.on_event("startup")
async def startup(ctx: Context):
    """Send test URLs on startup"""
    intake_address = "agent1qwcf3u33m8at9txc6ksyj5vshts6xn0nftvsx25xnnxjvjrqsz9q296pfn0"  # From logs
    
    # Test URLs with different threat levels
    test_urls = [
        "https://paypal.com.example.xyz/login?private_key=123",  # High risk
        "https://google.com",  # Safe
        "http://suspicious-site.pw/connect-wallet",  # Medium risk
        "https://legitimate-bank.com/secure-login"  # Safe
    ]
    
    for i, url in enumerate(test_urls):
        ctx.logger.info(f"Testing URL {i+1}: {url}")
        
        test_message = ChatMessage(
            message=f"check url {url}",
            user_id="test-user"
        )
        
        await ctx.send(intake_address, test_message)
        await asyncio.sleep(2)  # Wait between requests

@test_client.on_message(model=ChatResponse)
async def handle_response(ctx: Context, sender: str, msg: ChatResponse):
    """Handle response from IntakeAgent"""
    ctx.logger.info(f"📥 Received analysis result:")
    ctx.logger.info(f"   Response: {msg.response}")
    ctx.logger.info(f"   Requires action: {msg.requires_action}")
    if msg.action_type:
        ctx.logger.info(f"   Action type: {msg.action_type}")

if __name__ == "__main__":
    print("🧪 URL Analysis Pipeline Test")
    print("=" * 50)
    print("Testing complete flow with local threat detection...")
    print("=" * 50)
    test_client.run()
