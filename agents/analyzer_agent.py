import uuid
import json
import os
import sys
from datetime import datetime
from uagents import Agent, Context, Model

from url_analyzer import URLAnalyzer
from solana_analyzer import SolanaAnalyzer

if 'url_analyzer' in sys.modules:
    url_mod = sys.modules['url_analyzer']
    url_file_path = os.path.abspath(os.path.join(os.getcwd(), 'url_analyzer.py'))
    url_mod.__dict__['__file__'] = url_file_path
    setattr(url_mod, '__file__', url_file_path)

if 'solana_analyzer' in sys.modules:
    solana_mod = sys.modules['solana_analyzer']
    solana_file_path = os.path.abspath(os.path.join(os.getcwd(), 'solana_analyzer.py'))
    solana_mod.__dict__['__file__'] = solana_file_path
    setattr(solana_mod, '__file__', solana_file_path)

from schema import (
        Artifact, ArtifactType, AnalysisRequest, SignedReport, SolanaTransaction
)

# Create agent
analyzer_agent = Agent(
    name="AnalyzerAgent",
    seed="analyzer-agent-seed",
)

url_analyzer = None
solana_analyzer = None
_analyzer_error = None

def get_url_analyzer():
    global url_analyzer, _analyzer_error
    if url_analyzer is None and _analyzer_error is None:
        try:
            url_analyzer = URLAnalyzer(rules_path=None)
        except (NameError, FileNotFoundError) as e:
            _analyzer_error = f"URLAnalyzer init failed: {e}. Check rules.json location."
            raise RuntimeError(_analyzer_error)
        except Exception as e:
            _analyzer_error = str(e)
            raise RuntimeError(f"Failed to initialize URLAnalyzer: {e}")
    if _analyzer_error:
        raise RuntimeError(f"URLAnalyzer initialization error: {_analyzer_error}")
    return url_analyzer

def get_solana_analyzer():
    global solana_analyzer, _analyzer_error
    if solana_analyzer is None and _analyzer_error is None:
        try:
            solana_analyzer = SolanaAnalyzer(rules_path=None)
        except (NameError, FileNotFoundError) as e:
            _analyzer_error = f"SolanaAnalyzer init failed: {e}. Check solana_rules.json location."
            raise RuntimeError(_analyzer_error)
        except Exception as e:
            _analyzer_error = str(e)
            raise RuntimeError(f"Failed to initialize SolanaAnalyzer: {e}")
    if _analyzer_error:
        raise RuntimeError(f"SolanaAnalyzer initialization error: {_analyzer_error}")
    return solana_analyzer

# Threat detection analysis logic
class AnalyzerAgentCore:
    
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

        analysis_result = get_url_analyzer().analyze_url(url_to_analyze)

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

        analysis_result = get_solana_analyzer().analyze_transaction(tx_model)

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
    # Don't initialize analyzers at startup - initialize on first use to avoid __file__ issues
    ctx.logger.info("AnalyzerAgent started - analyzers will initialize on first request")
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