"""
Artifact Schema - Data structures for agent communication
Defines Pydantic models for all agent interactions
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from enum import Enum

class ArtifactType(str, Enum):
    URL = "url"
    SOLANA_TRANSACTION = "solana_transaction"

class SolanaTransaction(BaseModel):
    """Solana transaction details for analysis"""
    signature: str
    from_address: str
    to_address: str
    amount: float
    token: str = "SOL"  # Default to SOL, can be SPL tokens
    timestamp: Optional[str] = None
    block_height: Optional[int] = None

class URLDetails(BaseModel):
    """URL details for analysis"""
    url: str
    domain: str
    protocol: str = "https"
    path: Optional[str] = None
    query_params: Optional[Dict[str, str]] = None

class Artifact(BaseModel):
    """User-submitted artifact for analysis"""
    type: ArtifactType
    content: str
    metadata: Optional[Dict[str, Any]] = None
    user_id: Optional[str] = None
    
    # Specific data for each type
    solana_tx: Optional[SolanaTransaction] = None
    url_details: Optional[URLDetails] = None

class AnalysisTicket(BaseModel):
    """Ticket created when artifact is received"""
    ticket_id: str
    artifact: Artifact
    timestamp: str
    status: str = "pending"

class NonceRequest(BaseModel):
    """Request for nonce from HostAPI"""
    ticket_id: str
    artifact_hash: str

class NonceResponse(BaseModel):
    """Response with nonce for secure analysis"""
    nonce: str
    session_id: str
    expires_at: str

class AnalysisRequest(BaseModel):
    """Request to analyze artifact in TEE"""
    ticket_id: str
    artifact: Artifact
    nonce: str
    session_id: str
    chat_sender: Optional[str] = None  # Original chat protocol sender

class SignedReport(BaseModel):
    """Signed report from TEE analysis"""
    report_hash: str
    attestation: str
    signature: str
    verdict: str
    severity: str  # Use severity from URL analyzer instead of artificial threat_score
    evidence: Dict[str, Any]
    timestamp: str
    ticket_id: Optional[str] = None  # Track back to original request
    chat_sender: Optional[str] = None  # Original chat protocol sender for responses

class VerifyRequest(BaseModel):
    """Request to verify TEE attestation"""
    signed_report: SignedReport
    public_key: str

class VerifiedVerdict(BaseModel):
    """Verified verdict after attestation check"""
    is_verified: bool
    verdict: str
    confidence: float
    report_hash: str
    verification_timestamp: str

class LogRequest(BaseModel):
    """Request to log report hash on blockchain"""
    report_hash: str
    user_consent: bool = False

class LogResponse(BaseModel):
    """Response with blockchain transaction details"""
    tx_signature: str
    explorer_url: str
    block_height: Optional[int] = None
    confirmed: bool = False

class ChatMessage(BaseModel):
    """Chat protocol message for user interaction"""
    message: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None

class ChatResponse(BaseModel):
    """Response to chat message"""
    response: str
    requires_action: bool = False
    action_type: Optional[str] = None

# HTTP Request/Response Models for REST API
class AnalyzeRequestModel(BaseModel):
    """HTTP request model for artifact analysis"""
    content: str
    type: str = "URL"
    user_id: str = "unknown"

class AnalyzeResponseModel(BaseModel):
    """HTTP response model for analysis requests"""
    ticket_id: str
    status: str
    message: str
    verdict: str = ""
    severity: str = ""
    report_hash: str = ""
    timestamp: str = ""
    evidence: str = ""
    attestation: str = ""
    signature: str = ""

class StatusResponseModel(BaseModel):
    """HTTP response model for status checks"""
    ticket_id: str
    status: str
    verdict: str = ""
    severity: str = ""
    report_hash: str = ""
    timestamp: str = ""
    evidence: str = ""
    attestation: str = ""
    signature: str = ""

class HealthResponseModel(BaseModel):
    """HTTP response model for health checks"""
    status: str
    agent: str