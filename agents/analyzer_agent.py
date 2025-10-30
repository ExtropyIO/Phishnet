"""
AnalyzerAgent - uAgents Framework Implementation
Calls Go service for TEE analysis and returns signed reports
Uses proper uAgents communication patterns
"""

import os
import uuid
import aiohttp
import sys
import json
from datetime import datetime
from typing import Dict, Any
from uagents import Agent, Context, Model

# Add threat detection to path
threat_detection_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'threat_detection')
sys.path.append(os.path.join(threat_detection_path, 'models'))

# Import URL analyzer (now uses absolute paths internally)
from url_analyzer import URLAnalyzer
from solana_analyzer import SolanaAnalyzer

# Import schemas
try:
    from shared.schemas.artifact_schema import (
        Artifact, ArtifactType, AnalysisRequest, SignedReport, SolanaTransaction
    )
except ImportError:
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from shared.schemas.artifact_schema import (
        Artifact, ArtifactType, AnalysisRequest, SignedReport, SolanaTransaction
    )

# Create agent
analyzer_agent = Agent(
    name="AnalyzerAgent",
    seed="analyzer-agent-seed",
    port=8002,
    endpoint=["http://127.0.0.1:8002/submit"]
)

# Threat detection analysis logic
class AnalyzerAgentCore:
    def __init__(self):
        self.go_service_url = os.getenv("GO_ANALYZER_URL", "http://localhost:8080")
        self.timeout = 30  # seconds
        # Initialize analyzer instances
        self.url_analyzer = URLAnalyzer()
        self.solana_analyzer = SolanaAnalyzer()
    
    async def analyze_request(self, req: AnalysisRequest) -> SignedReport:
        """Route analysis request based on artifact type"""
        artifact = req.artifact

        if artifact.type == ArtifactType.URL:
            return self._analyze_url(artifact.content, req.ticket_id)
        if artifact.type == ArtifactType.SOLANA_TRANSACTION:
            return self._analyze_solana(artifact, req.ticket_id)

        raise ValueError(f"Unsupported artifact type: {artifact.type}")

    def _analyze_url(self, content: str, ticket_id: str) -> SignedReport:
        import re

        url_match = re.search(r'https?://[^\s]+', content)
        if url_match:
            url_to_analyze = url_match.group(0)
        else:
            url_to_analyze = content

        analysis_result = self.url_analyzer.analyze_url(url_to_analyze)

        return SignedReport(
            report_hash=f"analysis_{uuid.uuid4().hex[:16]}",
            attestation="url_analyzer",
            signature=f"analyzer_sig_{uuid.uuid4().hex[:8]}",
            verdict=analysis_result.get("verdict", "UNKNOWN"),
            severity=analysis_result.get("severity", "low"),
            evidence=analysis_result,
            timestamp=datetime.now().isoformat(),
            ticket_id=ticket_id
        )

    def _analyze_solana(self, artifact: Artifact, ticket_id: str) -> SignedReport:
        tx_model = artifact.solana_tx

        if tx_model is None:
            try:
                tx_payload = json.loads(artifact.content)
            except json.JSONDecodeError as exc:
                raise ValueError("Solana transaction content must be valid JSON") from exc

            try:
                tx_model = SolanaTransaction(**tx_payload)
            except Exception as exc:
                raise ValueError("Invalid Solana transaction payload") from exc

        analysis_result = self.solana_analyzer.analyze_transaction(tx_model)

        return SignedReport(
            report_hash=f"analysis_{uuid.uuid4().hex[:16]}",
            attestation="solana_analyzer",
            signature=f"analyzer_sig_{uuid.uuid4().hex[:8]}",
            verdict=analysis_result.get("verdict", "UNKNOWN"),
            severity=analysis_result.get("severity", "low"),
            evidence=analysis_result,
            timestamp=datetime.now().isoformat(),
            ticket_id=ticket_id
        )

core = AnalyzerAgentCore()

@analyzer_agent.on_event("startup")
async def startup(ctx: Context):
    """Agent startup handler"""
    ctx.logger.info("AnalyzerAgent started - pass-through to URL analyzer")
    ctx.logger.info(f"Agent address: {analyzer_agent.address}")

@analyzer_agent.on_message(model=AnalysisRequest)
async def handle_analysis_request(ctx: Context, sender: str, msg: AnalysisRequest):
    """Handle analysis requests from IntakeAgent"""
    ctx.logger.info(f"Received analysis request for ticket {msg.ticket_id}")
    ctx.logger.info(f"Routing artifact type {msg.artifact.type} for analysis")

    try:
        signed_report = await core.analyze_request(msg)
    except Exception as exc:
        ctx.logger.error(f"Analysis failed for ticket {msg.ticket_id}: {exc}")
        error_report = SignedReport(
            report_hash=f"analysis_error_{uuid.uuid4().hex[:16]}",
            attestation="analyzer_error",
            signature=f"analyzer_sig_{uuid.uuid4().hex[:8]}",
            verdict="ERROR",
            severity="critical",
            evidence={"error": str(exc)},
            timestamp=datetime.now().isoformat(),
            ticket_id=msg.ticket_id
        )
        await ctx.send(sender, error_report)
        return
    
    ctx.logger.info(f"Analysis result verdict: {signed_report.verdict}")
    ctx.logger.info(f"Attestation source: {signed_report.attestation}")
    
    # Send result back to IntakeAgent
    await ctx.send(sender, signed_report)

if __name__ == "__main__":
    analyzer_agent.run()