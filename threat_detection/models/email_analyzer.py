import json
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parseaddr
import base64

EMBEDDED_EMAIL_RULES_JSON = r"""[
  {
    "id": "spf_fail",
    "description": "Email failed SPF authentication check",
    "severity": "high",
    "category": "authentication"
  },
  {
    "id": "dkim_fail",
    "description": "Email failed DKIM signature verification",
    "severity": "high",
    "category": "authentication"
  },
  {
    "id": "dmarc_fail",
    "description": "Email failed DMARC policy check",
    "severity": "high",
    "category": "authentication"
  },
  {
    "id": "suspicious_attachment",
    "description": "Email contains suspicious file attachment",
    "severity": "high",
    "category": "malware"
  },
  {
    "id": "multiple_attachments",
    "description": "Email contains multiple attachments",
    "severity": "medium",
    "category": "suspicious"
  },
  {
    "id": "executable_attachment",
    "description": "Email contains executable file attachment",
    "severity": "critical",
    "category": "malware"
  },
  {
    "id": "spoofed_sender",
    "description": "Sender address may be spoofed",
    "severity": "critical",
    "category": "spoofing"
  },
  {
    "id": "mismatched_reply_to",
    "description": "Reply-To address differs from sender",
    "severity": "high",
    "category": "spoofing"
  },
  {
    "id": "suspicious_header",
    "description": "Email headers show suspicious patterns",
    "severity": "medium",
    "category": "suspicious"
  },
  {
    "id": "phishing_subject",
    "description": "Subject line contains phishing keywords",
    "severity": "high",
    "category": "phishing"
  }
]"""


@dataclass
class EmailHeaders:
    """Email header information"""
    from_address: str = ""
    from_name: str = ""
    reply_to: str = ""
    return_path: str = ""
    to_addresses: List[str] = field(default_factory=list)
    cc_addresses: List[str] = field(default_factory=list)
    subject: str = ""
    date: str = ""
    message_id: str = ""
    received_headers: List[str] = field(default_factory=list)
    spf_result: str = ""
    dkim_result: str = ""
    dmarc_result: str = ""
    x_mailer: str = ""


@dataclass
class Attachment:
    """Email attachment information"""
    filename: str
    size: int
    content_type: str
    is_suspicious: bool = False
    risk_level: str = "low"


class EmailAnalyzer:
    """
    email analyzer for detecting phishing attempts through
    header analysis, authentication checks, and content inspection.
    """
    
    def __init__(self, rules_path: Optional[str] = None):
        """
        Initialize email analyzer with detection rules.
        
        Args:
            rules_path: Optional path to external rules JSON file
        """
        self.rules = self._load_rules(rules_path)
        self._initialize_detection_patterns()
    
    def _load_rules(self, rules_path: Optional[str]) -> List[Dict]:
        """Load email analysis rules"""
        if rules_path:
            try:
                with open(rules_path, "r") as f:
                    return json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                pass
        return json.loads(EMBEDDED_EMAIL_RULES_JSON)
    
    def _initialize_detection_patterns(self):
        """Initialize detection patterns and data"""
        # Dangerous file extensions
        self.dangerous_extensions = {
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', 
            '.js', '.jar', '.msi', '.app', '.deb', '.rpm', '.dmg',
            '.pkg', '.ps1', '.psm1', '.reg', '.hta', '.cpl', '.msc',
            '.gadget', '.application', '.msp', '.inf', '.vb', '.ws'
        }
        
        # Suspicious but not always dangerous
        self.suspicious_extensions = {
            '.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.img',
            '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm',
            '.pdf', '.rtf', '.ace', '.arj'
        }
        
        # Legitimate mail servers (partial list)
        self.trusted_mailers = {
            'gmail', 'outlook', 'yahoo', 'protonmail', 'icloud',
            'amazon', 'microsoft', 'google'
        }
        
        # Phishing subject patterns
        self.phishing_subject_patterns = [
            r'\b(urgent|immediate|action required|verify|suspended|locked)\b',
            r'\b(click here|act now|respond now|confirm|update)\b',
            r'\b(prize|winner|congratulations|claim|reward)\b',
            r'\b(refund|payment|invoice|receipt|billing)\b',
            r'\bRe:\s*$',  # Empty Re: (fake reply)
            r'\bFwd:\s*$',  # Empty Fwd: (fake forward)
        ]
        
        # Domain reputation (simplified)
        self.suspicious_domains = {
            '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.work',
            '.click', '.link', '.download', '.stream', '.accountant'
        }
    
    def parse_headers(self, headers: Dict[str, str]) -> EmailHeaders:
        """Parse raw email headers into structured format"""
        email_headers = EmailHeaders()
        
        # Parse From address
        from_header = headers.get('From', '')
        email_headers.from_name, email_headers.from_address = parseaddr(from_header)
        
        # Parse Reply-To
        reply_to = headers.get('Reply-To', '')
        if reply_to:
            _, email_headers.reply_to = parseaddr(reply_to)
        
        # Return-Path
        email_headers.return_path = headers.get('Return-Path', '').strip('<>')
        
        # Recipients
        to_header = headers.get('To', '')
        email_headers.to_addresses = [addr.strip() for addr in to_header.split(',')]
        
        cc_header = headers.get('Cc', '')
        if cc_header:
            email_headers.cc_addresses = [addr.strip() for addr in cc_header.split(',')]
        
        # Subject
        email_headers.subject = headers.get('Subject', '')
        
        # Date and Message-ID
        email_headers.date = headers.get('Date', '')
        email_headers.message_id = headers.get('Message-ID', '')
        
        # Authentication results
        auth_results = headers.get('Authentication-Results', '')
        email_headers.spf_result = self._extract_auth_result(auth_results, 'spf')
        email_headers.dkim_result = self._extract_auth_result(auth_results, 'dkim')
        email_headers.dmarc_result = self._extract_auth_result(auth_results, 'dmarc')
        
        # X-Mailer
        email_headers.x_mailer = headers.get('X-Mailer', '')
        
        # Received headers (for path analysis)
        received = headers.get('Received', '')
        if isinstance(received, list):
            email_headers.received_headers = received
        elif received:
            email_headers.received_headers = [received]
        
        return email_headers
    
    def _extract_auth_result(self, auth_results: str, auth_type: str) -> str:
        """Extract authentication result from Authentication-Results header"""
        pattern = rf'{auth_type}=(\w+)'
        match = re.search(pattern, auth_results, re.IGNORECASE)
        return match.group(1).lower() if match else 'none'
    
    def check_authentication(self, headers: EmailHeaders) -> List[Dict]:
        """Check email authentication mechanisms"""
        alerts = []
        
        # SPF check
        if headers.spf_result in ['fail', 'softfail', 'permerror']:
            alerts.append({
                "id": "spf_fail",
                "description": f"SPF check failed: {headers.spf_result}",
                "severity": "high",
                "category": "authentication"
            })
        elif headers.spf_result == 'none':
            alerts.append({
                "id": "spf_missing",
                "description": "No SPF record found",
                "severity": "medium",
                "category": "authentication"
            })
        
        # DKIM check
        if headers.dkim_result in ['fail', 'permerror']:
            alerts.append({
                "id": "dkim_fail",
                "description": f"DKIM verification failed: {headers.dkim_result}",
                "severity": "high",
                "category": "authentication"
            })
        elif headers.dkim_result == 'none':
            alerts.append({
                "id": "dkim_missing",
                "description": "No DKIM signature found",
                "severity": "medium",
                "category": "authentication"
            })
        
        # DMARC check
        if headers.dmarc_result in ['fail']:
            alerts.append({
                "id": "dmarc_fail",
                "description": f"DMARC policy check failed",
                "severity": "high",
                "category": "authentication"
            })
        
        return alerts
    
    def check_sender_spoofing(self, headers: EmailHeaders) -> List[Dict]:
        """Detect potential sender spoofing"""
        alerts = []
        
        # Check Reply-To mismatch
        if headers.reply_to and headers.reply_to != headers.from_address:
            # Extract domains
            from_domain = headers.from_address.split('@')[-1] if '@' in headers.from_address else ''
            reply_domain = headers.reply_to.split('@')[-1] if '@' in headers.reply_to else ''
            
            if from_domain != reply_domain:
                alerts.append({
                    "id": "mismatched_reply_to",
                    "description": f"Reply-To domain ({reply_domain}) differs from sender domain ({from_domain})",
                    "severity": "high",
                    "category": "spoofing"
                })
        
        # Check Return-Path mismatch
        if headers.return_path and headers.return_path != headers.from_address:
            from_domain = headers.from_address.split('@')[-1] if '@' in headers.from_address else ''
            return_domain = headers.return_path.split('@')[-1] if '@' in headers.return_path else ''
            
            if from_domain != return_domain:
                alerts.append({
                    "id": "mismatched_return_path",
                    "description": f"Return-Path domain differs from sender domain",
                    "severity": "medium",
                    "category": "spoofing"
                })
        
        # Check for display name tricks
        if headers.from_name and headers.from_address:
            # Check if display name contains email-like string different from actual address
            email_in_name = re.findall(r'[\w\.-]+@[\w\.-]+', headers.from_name)
            if email_in_name and email_in_name[0].lower() != headers.from_address.lower():
                alerts.append({
                    "id": "display_name_spoofing",
                    "description": "Display name contains different email address",
                    "severity": "high",
                    "category": "spoofing"
                })
        
        # Check for suspicious domain
        sender_domain = headers.from_address.split('@')[-1].lower() if '@' in headers.from_address else ''
        if any(sender_domain.endswith(tld) for tld in self.suspicious_domains):
            alerts.append({
                "id": "suspicious_sender_domain",
                "description": f"Sender uses suspicious domain: {sender_domain}",
                "severity": "medium",
                "category": "suspicious"
            })
        
        return alerts
    
    def analyze_subject(self, subject: str) -> List[Dict]:
        """Analyze subject line for phishing indicators"""
        alerts = []
        subject_lower = subject.lower()
        
        for pattern in self.phishing_subject_patterns:
            if re.search(pattern, subject_lower):
                alerts.append({
                    "id": "phishing_subject",
                    "description": f"Subject contains phishing pattern: {pattern}",
                    "severity": "high",
                    "category": "phishing"
                })
        
        # Check for excessive urgency markers
        urgency_markers = subject.count('!') + subject.count('URGENT') + subject.count('IMMEDIATE')
        if urgency_markers > 2:
            alerts.append({
                "id": "urgent_subject",
                "description": "Subject contains excessive urgency markers",
                "severity": "medium",
                "category": "social_engineering"
            })
        
        return alerts
    
    def analyze_attachments(self, attachments: List[Attachment]) -> List[Dict]:
        """Analyze email attachments for threats"""
        alerts = []
        
        if not attachments:
            return alerts
        
        dangerous_count = 0
        suspicious_count = 0
        
        for attachment in attachments:
            filename_lower = attachment.filename.lower()
            
            # Check for dangerous extensions
            if any(filename_lower.endswith(ext) for ext in self.dangerous_extensions):
                dangerous_count += 1
                attachment.is_suspicious = True
                attachment.risk_level = "critical"
                alerts.append({
                    "id": f"dangerous_attachment_{attachment.filename}",
                    "description": f"Dangerous attachment detected: {attachment.filename}",
                    "severity": "critical",
                    "category": "malware",
                    "filename": attachment.filename
                })
            
            # Check for suspicious extensions
            elif any(filename_lower.endswith(ext) for ext in self.suspicious_extensions):
                suspicious_count += 1
                attachment.is_suspicious = True
                attachment.risk_level = "medium"
                alerts.append({
                    "id": f"suspicious_attachment_{attachment.filename}",
                    "description": f"Suspicious attachment detected: {attachment.filename}",
                    "severity": "medium",
                    "category": "suspicious",
                    "filename": attachment.filename
                })
            
            # Check for double extensions
            if filename_lower.count('.') > 1:
                parts = filename_lower.split('.')
                if len(parts) >= 3 and parts[-2] in ['exe', 'bat', 'cmd']:
                    alerts.append({
                        "id": f"double_extension_{attachment.filename}",
                        "description": f"Double extension detected (obfuscation technique): {attachment.filename}",
                        "severity": "high",
                        "category": "malware",
                        "filename": attachment.filename
                    })
        
        # Alert on multiple attachments
        if len(attachments) > 3:
            alerts.append({
                "id": "multiple_attachments",
                "description": f"Email contains {len(attachments)} attachments",
                "severity": "medium",
                "category": "suspicious"
            })
        
        return alerts
    
    def calculate_verdict(self, alerts: List[Dict]) -> Dict[str, Any]:
        """Calculate verdict with risk scoring"""
        severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        severity_weights = {"low": 1, "medium": 3, "high": 7, "critical": 10}
        
        max_sev = 0
        total_score = 0
        category_counts = {}
        
        for alert in alerts:
            severity = alert.get("severity", "low").lower()
            category = alert.get("category", "general")
            
            sev_level = severity_levels.get(severity, 1)
            if sev_level > max_sev:
                max_sev = sev_level
            
            total_score += severity_weights.get(severity, 1)
            category_counts[category] = category_counts.get(category, 0) + 1
        
        severity_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
        final_severity = severity_map.get(max_sev, "low")
        
        # Calculate risk score
        max_possible = len(alerts) * 10 if alerts else 10
        risk_score = min(100, (total_score / max_possible * 100) if max_possible > 0 else 0)
        
        verdict = "safe" if max_sev <= 1 else "unsafe"
        
        return {
            "verdict": verdict,
            "severity": final_severity,
            "risk_score": round(risk_score, 2),
            "alert_count": len(alerts),
            "category_breakdown": category_counts
        }
    
    def analyze_email(self, 
                     headers: Dict[str, str],
                     body: str = "",
                     attachments: Optional[List[Attachment]] = None) -> Dict[str, Any]:
        """
        Perform comprehensive email analysis.
        
        Args:
            headers: Raw email headers dictionary
            body: Email body text
            attachments: List of attachment objects
            
        Returns:
            Dict containing complete analysis results
        """
        # Parse headers
        parsed_headers = self.parse_headers(headers)
        
        # Run all checks
        auth_alerts = self.check_authentication(parsed_headers)
        spoofing_alerts = self.check_sender_spoofing(parsed_headers)
        subject_alerts = self.analyze_subject(parsed_headers.subject)
        attachment_alerts = self.analyze_attachments(attachments or [])
        
        # Combine all alerts
        all_alerts = auth_alerts + spoofing_alerts + subject_alerts + attachment_alerts
        
        # Calculate verdict
        result = self.calculate_verdict(all_alerts)
        
        # Build response
        return {
            "email_metadata": {
                "from": f"{parsed_headers.from_name} <{parsed_headers.from_address}>",
                "reply_to": parsed_headers.reply_to,
                "subject": parsed_headers.subject,
                "date": parsed_headers.date,
                "authentication": {
                    "spf": parsed_headers.spf_result,
                    "dkim": parsed_headers.dkim_result,
                    "dmarc": parsed_headers.dmarc_result
                },
                "attachment_count": len(attachments) if attachments else 0
            },
            "alerts": all_alerts,
            "verdict": result["verdict"],
            "severity": result["severity"],
            "risk_score": result["risk_score"],
            "category_breakdown": result["category_breakdown"],
            "recommendations": self._generate_recommendations(result["verdict"], all_alerts, attachments),
            "analyzed_at": datetime.utcnow().isoformat(),
            "analyzer_version": "2.0.0"
        }
    
    def _generate_recommendations(self, verdict: str, alerts: List[Dict], 
                                 attachments: Optional[List[Attachment]]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if verdict == "unsafe":
            recommendations.append("⚠️ This email shows signs of phishing - DO NOT interact")
            
            categories = {alert.get("category") for alert in alerts}
            
            if "authentication" in categories:
                recommendations.append(" Email failed authentication checks - sender may be spoofed")
                recommendations.append("Do not trust the sender address")
            
            if "spoofing" in categories:
                recommendations.append(" Sender spoofing detected - verify sender independently")
                recommendations.append("Contact the supposed sender through known channels")
            
            if "malware" in categories or (attachments and any(a.is_suspicious for a in attachments)):
                recommendations.append("🚫 DO NOT open any attachments")
                recommendations.append("Dangerous files detected - report to security team immediately")
            
            if "phishing" in categories:
                recommendations.append(" Phishing attempt detected")
                recommendations.append("Do not click any links or provide credentials")
            
            recommendations.append("Report this email to your security/IT team")
            recommendations.append("Delete or quarantine this email")
        else:
            recommendations.append("✅ Email appears safe based on current analysis")
            recommendations.append("Always verify unexpected requests independently")
            
            if attachments:
                recommendations.append("Scan attachments with antivirus before opening")
        
        return recommendations


# Example usage
if __name__ == "__main__":
    analyzer = EmailAnalyzer()
    
    # Test phishing email
    test_headers = {
        'From': 'PayPal Security <noreply@paypal-verify.tk>',
        'Reply-To': 'support@malicious-site.xyz',
        'To': 'victim@example.com',
        'Subject': 'URGENT! Account Suspended - Verify Now!',
        'Date': 'Mon, 27 Jan 2025 10:00:00 +0000',
        'Message-ID': '<fake123@paypal-verify.tk>',
        'Authentication-Results': 'spf=fail dkim=none dmarc=fail',
        'Return-Path': '<bounce@different-domain.com>'
    }
    
    test_attachments = [
        Attachment(filename="invoice.pdf.exe", size=2048000, content_type="application/octet-stream")
    ]
    
    result = analyzer.analyze_email(test_headers, attachments=test_attachments)
    print(json.dumps(result, indent=2))
