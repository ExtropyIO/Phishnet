"""
AnalyzerAgent - uAgents Framework Implementation
Calls Go service for TEE analysis and returns signed reports
Uses proper uAgents communication patterns
"""

import os
import uuid
import aiohttp
from datetime import datetime
from typing import Dict, Any
from uagents import Agent, Context, Model

# Import schemas
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

# Create agent
analyzer_agent = Agent(
    name="AnalyzerAgent",
    seed="analyzer-agent-seed",
    port=8002,
    endpoint=["http://127.0.0.1:8002/submit"]
)

# Go service communication logic
class AnalyzerAgentCore:
    def __init__(self):
        self.go_service_url = os.getenv("GO_ANALYZER_URL", "http://localhost:8080")
        self.timeout = 30  # seconds
    
    async def call_go_service(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Call Go service /analyze endpoint"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.go_service_url}/analyze",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        error_text = await response.text()
                        return {
                            "error": f"Go service error: {response.status}",
                            "details": error_text
                        }
        except aiohttp.ClientError as e:
            return {
                "error": f"Failed to connect to Go service: {str(e)}",
                "fallback": True
            }
        except Exception as e:
            return {
                "error": f"Unexpected error: {str(e)}",
                "fallback": True
            }
    
    async def analyze_request(self, req: AnalysisRequest) -> SignedReport:
        """Call Go service to analyze request with full context"""
        # Prepare payload with session context for Go service
        payload = {
            "ticket_id": req.ticket_id,
            "nonce": req.nonce,
            "session_id": req.session_id,
            "artifact": {
                "type": req.artifact.type.value,
                "content": req.artifact.content,
                "metadata": req.artifact.metadata or {}
            }
        }
        
        # Call Go service
        go_result = await self.call_go_service(payload)
        
        # Process Go service response
        if "error" in go_result:
            # Go service returned an error
            return SignedReport(
                report_hash=f"error_{uuid.uuid4().hex[:16]}",
                attestation="go_service_error",
                signature="",
                threat_score=0.0,
                verdict=f"ERROR: {go_result['error']}",
                evidence=go_result,
                timestamp=datetime.now().isoformat()
            )
        
        # Extract results from Go service response
        threat_score = go_result.get("threat_score", 0.0)
        verdict = go_result.get("verdict", "UNKNOWN")
        evidence = go_result.get("evidence", {})
        report_hash = go_result.get("report_hash", f"go_{uuid.uuid4().hex[:16]}")
        attestation = go_result.get("attestation", "go_service")
        signature = go_result.get("signature", "")
        
        return SignedReport(
            report_hash=report_hash,
            attestation=attestation,
            signature=signature,
            threat_score=threat_score,
            verdict=verdict,
            evidence=evidence,
            timestamp=datetime.now().isoformat()
        )

core = AnalyzerAgentCore()

@analyzer_agent.on_event("startup")
async def startup(ctx: Context):
    """Agent startup handler"""
    ctx.logger.info("AnalyzerAgent started - ready to call Go service for analysis")
    ctx.logger.info(f"Agent address: {analyzer_agent.address}")
    ctx.logger.info(f"Go service URL: {core.go_service_url}")

@analyzer_agent.on_message(model=AnalysisRequest)
async def handle_analysis_request(ctx: Context, sender: str, msg: AnalysisRequest):
    """Handle analysis requests from IntakeAgent"""
    ctx.logger.info(f"Received analysis request for ticket {msg.ticket_id}")
    
    # Call Go service for analysis
    ctx.logger.info(f"Calling Go service for analysis of {msg.artifact.type}")
    signed_report = await core.analyze_request(msg)
    
    ctx.logger.info(f"Analysis complete: {signed_report.verdict} (Score: {signed_report.threat_score})")
    ctx.logger.info(f"Attestation: {signed_report.attestation}")
    
    # Send result back to IntakeAgent
    await ctx.send(sender, signed_report)

if __name__ == "__main__":
    analyzer_agent.run()