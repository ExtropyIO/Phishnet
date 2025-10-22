"""
Artifact Schema - Data structures for agent communication
Defines Pydantic models for all agent interactions
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from enum import Enum

class ArtifactType(str, Enum):
    URL = "url"
    EMAIL = "email"
    TRANSACTION = "transaction"
    TEXT = "text"

class Artifact(BaseModel):
    """User-submitted artifact for analysis"""
    type: ArtifactType
    content: str
    metadata: Optional[Dict[str, Any]] = None
    user_id: Optional[str] = None

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

class SignedReport(BaseModel):
    """Signed report from TEE analysis"""
    report_hash: str
    attestation: str
    signature: str
    threat_score: float
    verdict: str
    evidence: Dict[str, Any]
    timestamp: str

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