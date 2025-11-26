import os
import uuid
import json
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional
from uagents import Agent, Context
from uagents_core.contrib.protocols.chat import (
    ChatMessage as CPChatMessage,
    TextContent as CPTextContent,
    StartSessionContent as CPStartSessionContent,
    chat_protocol_spec,
)
from uagents import Protocol

try:
    import aiohttp
    HTTP_AVAILABLE = True
except ImportError:
    HTTP_AVAILABLE = False

GATEWAY_PORT = int(os.getenv("GATEWAY_AGENT_PORT", "8007"))
POLL_INTERVAL = int(os.getenv("GATEWAY_POLL_INTERVAL", "10"))
INTAKE_AGENT_ADDRESS = os.getenv(
    "INTAKE_AGENT_ADDRESS",
    "agent1qwcf3u33m8at9txc6ksyj5vshts6xn0nftvsx25xnnxjvjrqsz9q296pfn0"
)

QUEUE_URL = os.getenv("GATEWAY_QUEUE_URL", None)
QUEUE_FILE = os.getenv("GATEWAY_QUEUE_FILE", None)

gateway_agent = Agent(
    name="HttpGateway",
    seed="gateway-agent-seed",
    port=GATEWAY_PORT,
)

chat_proto = Protocol(spec=chat_protocol_spec)

async def poll_http_queue(queue_url: str) -> List[Dict[str, Any]]:
    """Poll HTTP endpoint for pending URLs"""
    if not HTTP_AVAILABLE:
        raise RuntimeError("aiohttp not available - cannot poll HTTP queue")
    
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            async with session.get(queue_url) as response:
                if response.status == 200:
                    data = await response.json()
                    # Expected format: {"pending": [{"id": "...", "url": "...", "user_id": "..."}, ...]}
                    if isinstance(data, dict) and 'pending' in data:
                        return data['pending']
                    elif isinstance(data, list):
                        return data
                    else:
                        return []
                else:
                    return []
        except Exception as e:
            print(f"Error polling HTTP queue: {e}")
            return []

async def poll_file_queue(queue_file: str) -> List[Dict[str, Any]]:
    """Poll local file for pending URLs"""
    if not os.path.exists(queue_file):
        return []
    
    try:
        with open(queue_file, 'r') as f:
            data = json.load(f)
            # Expected format: {"pending": [{"id": "...", "url": "...", "user_id": "..."}, ...]}
            if isinstance(data, dict) and 'pending' in data:
                return data['pending']
            elif isinstance(data, list):
                return data
            else:
                return []
    except Exception as e:
        print(f"Error reading queue file: {e}")
        return []

async def send_to_intake(ctx: Context, content: str, user_id: Optional[str] = None):
    """Send content to IntakeAgent using Chat protocol
    
    IntakeAgent will auto-detect whether content is a URL or Solana transaction.
    
    Args:
        content: The content to send (URL string or Solana transaction JSON string)
        user_id: Optional user ID
    """
    try:
        # Create Chat protocol message with the content
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
        
        # Log the content (IntakeAgent will handle detection)
        preview = content[:50] + "..." if len(content) > 50 else content
        ctx.logger.info(f"Sent content to IntakeAgent: {preview} (user_id: {user_id})")
        return True
    except Exception as e:
        ctx.logger.error(f"Failed to send to IntakeAgent: {e}")
        return False

async def poll_and_process(ctx: Context):
    """Poll external store and process pending items (URLs or Solana transactions)"""
    ctx.logger.info("Polling external store for pending items...")
    
    pending_items = []
    
    # Poll from configured source
    if QUEUE_URL:
        pending_items = await poll_http_queue(QUEUE_URL)
    elif QUEUE_FILE:
        pending_items = await poll_file_queue(QUEUE_FILE)
    else:
        ctx.logger.warning("No queue source configured (GATEWAY_QUEUE_URL or GATEWAY_QUEUE_FILE)")
        return
    
    if not pending_items:
        ctx.logger.debug("No pending items found")
        return
    
    ctx.logger.info(f"Found {len(pending_items)} pending item(s)")
    
    # Process each pending item
    processed_count = 0
    for item in pending_items:
        # Extract item data
        item_id = item.get('id') or item.get('item_id') or str(uuid.uuid4())
        user_id = item.get('user_id')
        
        # Extract content from item (supports various field names for backward compatibility)
        # IntakeAgent will handle all content type detection
        content = item.get('url') or item.get('content') or item.get('transaction')
        
        # If content is a dict, convert to JSON string
        if isinstance(content, dict):
            try:
                content = json.dumps(content)
            except Exception as e:
                ctx.logger.warning(f"Item {item_id}: Failed to serialize content: {e}")
                continue
        
        if not content:
            ctx.logger.warning(f"Item {item_id} has no content field, skipping")
            continue
        
        # Send to IntakeAgent (it will handle detection)
        success = await send_to_intake(ctx, content, user_id)
        
        if success:
            processed_count += 1
            preview = content[:50] + "..." if len(content) > 50 else content
            ctx.logger.info(f"Processed item {item_id}: {preview}")
        else:
            ctx.logger.error(f"Failed to process item {item_id}")
    
    if processed_count > 0:
        ctx.logger.info(f"Processed {processed_count} item(s)")

@gateway_agent.on_event("startup")
async def startup(ctx: Context):
    """Agent startup handler"""
    ctx.logger.info("HttpGateway agent started")
    ctx.logger.info(f"Agent address: {gateway_agent.address}")
    ctx.logger.info(f"IntakeAgent address: {INTAKE_AGENT_ADDRESS}")
    ctx.logger.info(f"Poll interval: {POLL_INTERVAL} seconds")
    
    # Display queue configuration
    if QUEUE_URL:
        ctx.logger.info(f"Queue source: HTTP endpoint - {QUEUE_URL}")
    elif QUEUE_FILE:
        ctx.logger.info(f"Queue source: Local file - {QUEUE_FILE}")
    else:
        ctx.logger.warning("⚠️  No queue source configured!")
        ctx.logger.warning("Set GATEWAY_QUEUE_URL (HTTP endpoint) or GATEWAY_QUEUE_FILE (local file)")
    
    # Start polling task
    ctx.logger.info("Starting polling task...")
    asyncio.create_task(polling_loop(ctx))

async def polling_loop(ctx: Context):
    while True:
        try:
            await poll_and_process(ctx)
        except Exception as e:
            ctx.logger.error(f"Error in polling loop: {e}")
        
        # Wait before next poll
        await asyncio.sleep(POLL_INTERVAL)

@gateway_agent.on_message(model=CPChatMessage)
async def handle_chat_message(ctx: Context, sender: str, msg: CPChatMessage):
    """Handle chat protocol messages (for testing/debugging)"""
    ctx.logger.info(f"Received chat message from {sender}")
    # Gateway doesn't respond to chat messages, it only forwards to IntakeAgent

gateway_agent.include(chat_proto, publish_manifest=True)

if __name__ == "__main__":
    if QUEUE_URL:
        print(f"Queue Source: HTTP - {QUEUE_URL}")
    elif QUEUE_FILE:
        print(f"Queue Source: File - {QUEUE_FILE}")
    else:
        print("⚠️  No queue source configured!")
    print()
    
    gateway_agent.run()

