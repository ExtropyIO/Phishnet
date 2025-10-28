import os
import uuid
import aiohttp
import sys
from datetime import datetime
from typing import Dict, Any
from uagents import Agent, Context, Protocol, Model
from uagents.protocols.query import QueryProtocol

# Add threat detection to path
threat_detection_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'threat_detection')
sys.path.append(os.path.join(threat_detection_path, 'models'))

from url_analyzer import URLAnalyzer

try:
    from shared.schemas.artifact_schema import (
        Artifact, ArtifactType, AnalysisRequest, SignedReport
    )
except ImportError:
    import sys
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
    mailbox=True
)

class AnalyzerAgentCore:
    def __init__(self):
        # Current: Direct URL analyzer
        self.url_analyzer = URLAnalyzer()
        
        # Future:
        self.tee_service_url = os.getenv("TEE_SERVICE_URL", "http://localhost:8080")
        self.timeout = 30
    
    async def analyze_request(self, req: AnalysisRequest) -> SignedReport:
        """Analyze request - currently uses URL analyzer, future will use TEE"""
        try:
            analysis_result = self.url_analyzer.analyze_url(req.artifact.content)
            
            # Create SignedReport from URL analyzer result
            return SignedReport(
                report_hash=f"analysis_{uuid.uuid4().hex[:16]}",
                attestation="url_analyzer",
                signature=f"analyzer_sig_{uuid.uuid4().hex[:8]}",
                verdict=analysis_result.get("verdict", "UNKNOWN"),
                severity=analysis_result.get("severity", "low"),
                evidence=analysis_result,
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
    ctx.logger.info("AnalyzerAgent started - pass-through to URL analyzer")
    ctx.logger.info(f"Agent address: {analyzer_agent.address}")

@analysis_protocol.on_message(AnalysisRequest, replies=SignedReport)
async def handle_analysis_request(ctx: Context, sender: str, msg: AnalysisRequest):
    """Handle analysis requests from IntakeAgent"""
    ctx.logger.info(f"Received analysis request for ticket {msg.ticket_id}")
    
    # Pass to URL analyzer
    ctx.logger.info(f"Passing {msg.artifact.type} to URLAnalyzer")
    signed_report = await core.analyze_request(msg)
    
    ctx.logger.info(f"URL analyzer result: {signed_report.verdict}")
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