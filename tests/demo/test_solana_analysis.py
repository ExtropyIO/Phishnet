import asyncio
from datetime import datetime
from pydantic import BaseModel
from uagents import Agent
from shared.schemas.artifact_schema import Artifact, ArtifactType, AnalysisRequest

# -------------------------------
# Dummy Solana transaction model
# -------------------------------
class SolanaTransaction(BaseModel):
    from_address: str
    to_address: str
    amount: float
    signature: str
    validator: str = None

# -------------------------------
# Async demo
# -------------------------------
async def main():
    # Connect to local AnalyzerAgent
    agent = Agent(
        name="DemoClient",
        seed="demo-client-seed",
        port=9000
    )

    await agent.connect("http://127.0.0.1:8002/submit")
    print("[Demo] Connected to AnalyzerAgent")

    # Example malicious transaction (matches solana_rules.json)
    tx = SolanaTransaction(
        from_address="5Jfb3n8eW4JyQrKJktMNBFXnC1zx2YHjRSkzRrTT5QHh",  # malicious wallet
        to_address="GrXoxqM2a6QFKSBdZ9RLWJCBVTFvuuH8eCjjsLbjhpiR",   # malicious wallet
        amount=10.5,
        signature="demo_signature_12345",
        validator="4SKy65C9373k9WZnq2ViR7nq8eCu32TkLhoXq45MYQm6"   # malicious validator
    )

    artifact = Artifact(
        type=ArtifactType.SOLANA_TRANSACTION,
        content="Solana demo transaction",
        solana_tx=tx
    )

    request = AnalysisRequest(
        ticket_id="demo_tx_001",
        artifact=artifact
    )

    print("[Demo] Sending transaction for analysis...")
    response = await agent.send("AnalyzerAgent", request)
    
    print("\n===== Analysis Report =====")
    print(f"Verdict: {response.verdict}")
    print(f"Severity: {response.severity}")
    print("Alerts:")
    for alert in response.evidence.get("alerts", []):
        print(f" - {alert['id']}: {alert['description']} ({alert['severity']})")
    print("===========================")

    await agent.disconnect()

# -------------------------------
# Run demo
# -------------------------------
if __name__ == "__main__":
    asyncio.run(main())
