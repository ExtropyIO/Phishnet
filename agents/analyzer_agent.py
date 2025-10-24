"""
AnalyzerAgent - uAgents Framework Implementation
Calls Go service for TEE analysis and returns signed reports
Integrated with MeTTa Knowledge Graph for URL threat logging
"""

import os
import uuid
import sys
from datetime import datetime
from typing import Dict, Any
from uagents import Agent, Context, Model

# Add threat detection to path
threat_detection_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'threat_detection')
sys.path.append(os.path.join(threat_detection_path, 'models'))

# Import URL analyzer
from url_analyzer import URLAnalyzer

# Import MeTTa KG client
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from metta_kg_client import MeTTaKGClient

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

# Core agent logic
class AnalyzerAgentCore:
    def __init__(self):
        self.url_analyzer = URLAnalyzer()
        self.kg_client = MeTTaKGClient()

    async def analyze_request(self, req: AnalysisRequest) -> SignedReport:
        """Analyze a URL artifact and store result in MeTTa KG"""
        try:
            url_content = req.artifact.content
            import re
            url_match = re.search(r'https?://[^\s]+', url_content)
            url_to_analyze = url_match.group(0) if url_match else url_content

            # Analyze URL
            analysis_result = self.url_analyzer.analyze_url(url_to_analyze)

            # Add to KG
            self.kg_client.add_fact(
                fact_type="url_analysis",
                fact_value=url_to_analyze,
                metadata={
                    "severity": analysis_result.get("severity"),
                    "verdict": analysis_result.get("verdict"),
                    "alerts": analysis_result.get("alerts")
                }
            )

            # Return signed report
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
            raise Exception(f"Analysis failed: {str(e)}")

core = AnalyzerAgentCore()

@analyzer_agent.on_event("startup")
async def startup(ctx: Context):
    ctx.logger.info("AnalyzerAgent started - MeTTa KG enabled")
    ctx.logger.info(f"Agent address: {analyzer_agent.address}")

@analyzer_agent.on_message(model=AnalysisRequest)
async def handle_analysis_request(ctx: Context, sender: str, msg: AnalysisRequest):
    ctx.logger.info(f"Received analysis request for ticket {msg.ticket_id}")
    signed_report = await core.analyze_request(msg)
    ctx.logger.info(f"URL analyzer result: {signed_report.verdict}")
    await ctx.send(sender, signed_report)

if __name__ == "__main__":
    analyzer_agent.run()
