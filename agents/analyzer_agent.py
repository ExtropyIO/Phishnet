import os
import uuid
import sys
from typing import Dict, Any
from uagents import Agent, Context, Protocol, Model
from uagents.protocols.query import QueryProtocol

# Add threat detection to path
threat_detection_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'threat_detection')
sys.path.append(os.path.join(threat_detection_path, 'models'))

# Import analyzers
# Import URL analyzer (now uses absolute paths internally)
from datetime import datetime
from shared.health import start_health_server
from url_analyzer import URLAnalyzer
from solana_analyzer import SolanaAnalyzer

# Import MeTTa KG client
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from metta_kg_client import MeTTaKGClient

start_health_server()
# Import schemas
try:
    from shared.schemas.artifact_schema import (
        Artifact, ArtifactType, AnalysisRequest, SignedReport
    )
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from shared.schemas.artifact_schema import (
        Artifact, ArtifactType, AnalysisRequest, SignedReport
    )

analysis_protocol = Protocol(name="AnalysisProtocol", version="1.0.0")

query_protocol = QueryProtocol()

analyzer_agent = Agent(
    name="AnalyzerAgent",
    seed="analyzer-agent-seed",
    port=8002,
    protocols=[query_protocol],
    mailbox=True,
    endpoint="http://TeeAge-Alb16-asYi7vJYnLGj-755747286.eu-west-1.elb.amazonaws.com/analyzer/"
)

# Core agent logic
class AnalyzerAgentCore:
    def __init__(self):
        self.url_analyzer = URLAnalyzer()
        self.solana_analyzer = SolanaAnalyzer()
        self.kg_client = MeTTaKGClient()
         # Future:
        self.tee_service_url = os.getenv("TEE_SERVICE_URL", "http://localhost:8080")
        self.timeout = 30

    async def analyze_request(self, req: AnalysisRequest) -> SignedReport:
        """Analyze a URL or Solana artifact and store result in MeTTa KG"""
        try:
            artifact = req.artifact
            result = {}
            
            if artifact.type == ArtifactType.URL:
                import re
                url_match = re.search(r'https?://[^\s]+', artifact.content)
                url_to_analyze = url_match.group(0) if url_match else artifact.content
                result = self.url_analyzer.analyze_url(url_to_analyze)
                fact_type = "url_analysis"
                fact_value = url_to_analyze

            elif artifact.type == ArtifactType.SOLANA_TRANSACTION:
                if not artifact.solana_tx:
                    raise Exception("Missing Solana transaction data")
                result = self.solana_analyzer.analyze_transaction(artifact.solana_tx)
                fact_type = "solana_tx_analysis"
                fact_value = artifact.solana_tx.dict()

            else:
                raise Exception(f"Unsupported artifact type: {artifact.type}")

            # Add to KG
            self.kg_client.add_fact(
                fact_type=fact_type,
                fact_value=fact_value,
                metadata={
                    "severity": result.get("severity"),
                    "verdict": result.get("verdict"),
                    "alerts": result.get("alerts")
                }
            )

            # Return signed report
            return SignedReport(
                report_hash=f"analysis_{uuid.uuid4().hex[:16]}",
                attestation="analyzer_agent",
                signature=f"analyzer_sig_{uuid.uuid4().hex[:8]}",
                verdict=result.get("verdict", "UNKNOWN"),
                severity=result.get("severity", "low"),
                evidence=result,
                timestamp=datetime.now().isoformat(),
                ticket_id=req.ticket_id
            )

        except Exception as e:
            raise Exception(f"Analysis failed: {str(e)}")
    
    # async def analyze_request_tee(self, req: AnalysisRequest) -> SignedReport:
    #     """Future: Analyze request via TEE service over HTTP"""
    #     # TODO: Implement TEE communication
    #     # async with aiohttp.ClientSession() as session:
    #     #     async with session.post(f"{self.tee_service_url}/analyze", json=req.dict()) as response:
    #     #         tee_result = await response.json()
    #     #         return SignedReport(**tee_result)
    #     pass

core = AnalyzerAgentCore()

@analyzer_agent.on_event("startup")
async def startup(ctx: Context):
    ctx.logger.info("AnalyzerAgent started - MeTTa KG enabled")
    ctx.logger.info(f"Agent address: {analyzer_agent.address}")

@analysis_protocol.on_message(AnalysisRequest, replies=SignedReport)
async def handle_analysis_request(ctx: Context, sender: str, msg: AnalysisRequest):
    ctx.logger.info(f"Received analysis request for ticket {msg.ticket_id}")
    ctx.logger.info(f"Passing {msg.artifact.type} to Analyzer")

    signed_report = await core.analyze_request(msg)
    
    ctx.logger.info(f"Analysis result: {signed_report.verdict}")
    ctx.logger.info(f"Attestation: {signed_report.attestation}")
    
    await ctx.send(sender, signed_report)

# HTTP endpoint for direct analysis requests
@analyzer_agent.on_rest_post("/analyze", AnalysisRequest, SignedReport)
async def analyze_endpoint(ctx: Context, request: AnalysisRequest) -> SignedReport:
    ctx.logger.info(f"HTTP analysis request for ticket {request.ticket_id}")
    
    signed_report = await core.analyze_request(request)
    
    ctx.logger.info(f"HTTP analysis result: {signed_report.verdict}")
    return signed_report

@analyzer_agent.on_rest_get("/health")
async def health_endpoint(ctx: Context) -> str:
    return "ok"

if __name__ == "__main__":
    analyzer_agent.include(analysis_protocol, publish_manifest=True)
    analyzer_agent.run()
