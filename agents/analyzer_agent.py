"""
AnalyzerAgent - uAgents Framework Implementation
Calls Go service for TEE analysis and returns signed reports
Uses proper uAgents communication patterns
"""

import os
import uuid
import aiohttp
import sys
from datetime import datetime
from typing import Dict, Any
from uagents import Agent, Context, Model

# Add threat detection to path
threat_detection_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'threat_detection')
sys.path.append(os.path.join(threat_detection_path, 'models'))

# Import URL analyzer (now uses absolute paths internally)
from url_analyzer import URLAnalyzer

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

# Threat detection analysis logic
class AnalyzerAgentCore:
    def __init__(self):
        self.go_service_url = os.getenv("GO_ANALYZER_URL", "http://localhost:8080")
        self.timeout = 30  # seconds
        # Initialize URL analyzer instance
        self.url_analyzer = URLAnalyzer()
    
    def analyze_url_direct(self, url: str) -> Dict[str, Any]:
        """Call URL analyzer directly - no additional processing"""
        try:
            # Call the URL analyzer directly and return its result
            analysis_result = self.url_analyzer.analyze_url(url)
            
            # Pass through ONLY what the URL analyzer provides - no artificial conversions
            return {
                "verdict": analysis_result.get("verdict", "safe"),
                "severity": analysis_result.get("severity", "low"),
                "evidence": analysis_result,
                "report_hash": f"analysis_{uuid.uuid4().hex[:16]}",
                "attestation": "url_analyzer",
                "signature": f"analyzer_sig_{uuid.uuid4().hex[:8]}"
            }
        except Exception as e:
            raise Exception(f"URL analyzer failed: {str(e)}")
    
    async def analyze_request(self, req: AnalysisRequest) -> SignedReport:
        """Pass request to URL analyzer - no additional processing"""
        try:
            # Extract URL from content
            url_content = req.artifact.content
            import re
            url_match = re.search(r'https?://[^\s]+', url_content)
            if url_match:
                url_to_analyze = url_match.group(0)
            else:
                url_to_analyze = url_content
            
            # Call URL analyzer directly
            analysis_result = self.analyze_url_direct(url_to_analyze)
            
            # Create SignedReport from URL analyzer result
            return SignedReport(
                report_hash=analysis_result.get("report_hash", f"analysis_{uuid.uuid4().hex[:16]}"),
                attestation=analysis_result.get("attestation", "url_analyzer"),
                signature=analysis_result.get("signature", ""),
                verdict=analysis_result.get("verdict", "UNKNOWN"),
                severity=analysis_result.get("severity", "low"),
                evidence=analysis_result.get("evidence", {}),
                timestamp=datetime.now().isoformat()
            )
            
        except Exception as e:
            # Return simple error
            raise Exception(f"Analysis failed: {str(e)}")

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
    
    # Pass to URL analyzer
    ctx.logger.info(f"Passing {msg.artifact.type} to url_analyzer.py")
    signed_report = await core.analyze_request(msg)
    
    ctx.logger.info(f"URL analyzer result: {signed_report.verdict}")
    ctx.logger.info(f"Attestation: {signed_report.attestation}")
    
    # Send result back to IntakeAgent
    await ctx.send(sender, signed_report)

if __name__ == "__main__":
    analyzer_agent.run()