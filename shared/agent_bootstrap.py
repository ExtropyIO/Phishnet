# shared/agent_bootstrap.py
import os
from uagents import Agent
from uagents import Protocol
from uagents_core.contrib.protocols.chat import chat_protocol_spec
from .http_proxy import start_health_proxy

def build_agent(name: str) -> Agent:
    """
    Construct an Agent with a public endpoint taken from PUBLIC_BASE_URL.
    Expects env:
      - PUBLIC_BASE_URL (e.g. http://<ALB>/intake)  -> endpoint will be <...>/submit
      - AGENT_SEED (optional)
      - UAGENTS_PORT (defaults 8001)
    """
    public_base = os.environ.get("PUBLIC_BASE_URL")
    if not public_base:
        raise RuntimeError("PUBLIC_BASE_URL must be set (e.g. http://<ALB-DNS>/<service>)")

    endpoint = f"{public_base.rstrip('/')}/submit"
    agent = Agent(
        name=name,
        seed=os.environ.get("AGENT_SEED", f"{name}-seed"),
        endpoint=[endpoint],
    )

    # Include Chat protocol so Agentverse/ASI:One can chat to your agent
    chat_proto = Protocol(spec=chat_protocol_spec)
    agent.include(chat_proto, publish_manifest=True)

    return agent

def start_sidecars():
    """
    Start the health+proxy sidecar on PORT (default 8080).
    Reads SERVICE_BASE (/intake, /analyzer) and UAGENTS_PORT via http_proxy.
    """
    port = int(os.environ.get("PORT", "8080"))
    start_health_proxy(port=port)

def run_agent(agent: Agent):
    """
    Run the agent on UAGENTS_PORT (default 8001).
    """
    port = int(os.environ.get("UAGENTS_PORT", "8001"))
    agent.run(port=port)
