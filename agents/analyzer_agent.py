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
from threat_detection.models.url_analyzer import URLAnalyzer
from datetime import datetime
from shared.health import start_health_server

start_health_server()
from shared.health import start_health_server

start_health_server()
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
    
    async def analyze_request(self, req: AnalysisRequest) -> SignedReport:
        """Pass request directly to URL analyzer"""
        try:
            # Extract URL from content
            url_content = req.artifact.content
            import re
            url_match = re.search(r'https?://[^\s]+', url_content)
            if url_match:
                url_to_analyze = url_match.group(0)
            else:
                url_to_analyze = url_content
            
            # Call URL analyzer directly - no intermediate function needed
            analysis_result = self.url_analyzer.analyze_url(url_to_analyze)
            
            # Create SignedReport directly from URL analyzer result
            return SignedReport(
                report_hash=f"analysis_{uuid.uuid4().hex[:16]}",
                attestation="url_analyzer",
                signature=f"analyzer_sig_{uuid.uuid4().hex[:8]}",
                verdict=analysis_result.get("verdict", "UNKNOWN"),
                severity=analysis_result.get("severity", "low"),
                evidence=analysis_result,
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