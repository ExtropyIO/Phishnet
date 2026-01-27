import json
import re
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
from collections import Counter

EMBEDDED_TEXT_RULES_JSON = r"""[
  {
    "id": "urgency_immediate",
    "pattern": "\\b(urgent|immediately|right now|act now|expires today|last chance)\\b",
    "description": "Creates false urgency to pressure quick action",
    "severity": "high",
    "category": "social_engineering"
  },
  {
    "id": "account_threat",
    "pattern": "\\b(account (will be |has been )?(suspended|closed|terminated|locked)|suspended account|account suspension)\\b",
    "description": "Threatens account closure to induce panic",
    "severity": "high",
    "category": "social_engineering"
  },
  {
    "id": "verify_credentials",
    "pattern": "\\b(verify (your |the )?(account|identity|information|credentials)|confirm (your |the )?identity)\\b",
    "description": "Requests credential verification - common phishing tactic",
    "severity": "high",
    "category": "credential_theft"
  },
  {
    "id": "click_link",
    "pattern": "\\b(click (here|this link|the link|below)|follow (this |the )?link)\\b",
    "description": "Direct call-to-action for clicking links",
    "severity": "medium",
    "category": "social_engineering"
  },
  {
    "id": "prize_winning",
    "pattern": "\\b(you('ve| have) won|congratulations|claim (your )?(prize|reward|gift)|you('re| are) a winner)\\b",
    "description": "Prize/reward lure commonly used in scams",
    "severity": "medium",
    "category": "scam"
  },
  {
    "id": "password_request",
    "pattern": "\\b(enter (your )?password|provide (your )?password|confirm (your )?password|reset password|update (your )?password)\\b",
    "description": "Direct password requests - legitimate services never do this",
    "severity": "critical",
    "category": "credential_theft"
  },
  {
    "id": "payment_issue",
    "pattern": "\\b(payment (failed|declined|problem)|billing (issue|problem)|update payment|payment method|credit card (expired|declined))\\b",
    "description": "Payment issue claims to harvest financial data",
    "severity": "high",
    "category": "financial_theft"
  },
  {
    "id": "security_alert",
    "pattern": "\\b(security alert|suspicious activity|unauthorized access|unusual activity|login attempt)\\b",
    "description": "Fake security alerts to create fear",
    "severity": "high",
    "category": "social_engineering"
  },
  {
    "id": "personal_info_request",
    "pattern": "\\b(social security|ssn|tax id|date of birth|mother's maiden|bank account number)\\b",
    "description": "Requests for sensitive personal information",
    "severity": "critical",
    "category": "identity_theft"
  },
  {
    "id": "crypto_wallet",
    "pattern": "\\b(wallet address|private key|seed phrase|recovery phrase|mnemonic|12-word phrase|24-word phrase)\\b",
    "description": "Requests for cryptocurrency wallet credentials",
    "severity": "critical",
    "category": "crypto_theft"
  },
  {
    "id": "authority_impersonation",
    "pattern": "\\b(irs|fbi|police|government|tax authority|department of|official notice)\\b",
    "description": "Impersonates authority figures to intimidate",
    "severity": "high",
    "category": "impersonation"
  },
  {
    "id": "refund_claim",
    "pattern": "\\b(refund (available|pending|owed)|tax refund|claim (your )?refund|owed money)\\b",
    "description": "Refund claims to lure clicks and data entry",
    "severity": "medium",
    "category": "scam"
  },
  {
    "id": "download_attachment",
    "pattern": "\\b(download (the )?attachment|open (the )?attachment|view (the )?document|see attached)\\b",
    "description": "Prompts to download potentially malicious attachments",
    "severity": "high",
    "category": "malware"
  },
  {
    "id": "limited_time",
    "pattern": "\\b(limited time|offer expires|act (now|quickly|fast)|don't miss|only \\d+ (hours|days|minutes))\\b",
    "description": "Time pressure tactics to reduce critical thinking",
    "severity": "medium",
    "category": "social_engineering"
  },
  {
    "id": "free_offer",
    "pattern": "\\b(free (money|cash|gift card|iphone|ipad)|get (paid|free)|earn money (fast|quickly))\\b",
    "description": "Too-good-to-be-true free offers",
    "severity": "medium",
    "category": "scam"
  },
  {
    "id": "ceo_fraud",
    "pattern": "\\b(wire transfer|urgent payment|confidential|need you to|discreet|sensitive matter)\\b",
    "description": "CEO fraud / business email compromise patterns",
    "severity": "high",
    "category": "bec"
  },
  {
    "id": "package_delivery",
    "pattern": "\\b(package delivery|delivery failed|parcel|tracking number|shipment|courier)\\b",
    "description": "Fake delivery notifications",
    "severity": "medium",
    "category": "scam"
  },
  {
    "id": "invoice_payment",
    "pattern": "\\b(outstanding invoice|payment (due|overdue)|pay invoice|invoice attached)\\b",
    "description": "Fake invoice scams",
    "severity": "medium",
    "category": "financial_theft"
  }
]"""


@dataclass
class TextFeatures:
    """Features extracted from text analysis"""
    word_count: int
    sentence_count: int
    avg_word_length: float
    uppercase_ratio: float
    exclamation_count: int
    question_count: int
    url_count: int
    email_count: int
    phone_count: int
    currency_mentions: int
    number_count: int
    suspicious_domain_count: int


class TextAnalyzer:
    """
    text analyzer for detecting phishing attempts in messages,
    emails, and documents using NLP patterns and heuristics.
    """
    
    def __init__(self, rules_path: Optional[str] = None):
        """
        Initialize text analyzer with detection rules.
        
        Args:
            rules_path: Optional path to external rules JSON file
        """
        self.rules = self._load_rules(rules_path)
        self._initialize_patterns()
    
    def _load_rules(self, rules_path: Optional[str]) -> List[Dict]:
        """Load text analysis rules"""
        if rules_path:
            try:
                with open(rules_path, "r") as f:
                    return json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                pass
        return json.loads(EMBEDDED_TEXT_RULES_JSON)
    
    def _initialize_patterns(self):
        """Initialize regex patterns for detection"""
        # URL pattern
        self.url_pattern = re.compile(
            r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)'
        )
        
        # Email pattern
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        

        
        # Currency pattern
        self.currency_pattern = re.compile(
            r'(?:USD|\$|EUR|€|GBP|£)\s*[\d,]+(?:\.\d{2})?'
        )
        
        # Suspicious domains
        self.suspicious_tlds = {'.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq'}
        
        # Brand names commonly impersonated
        self.target_brands = {
            'paypal', 'amazon', 'netflix', 'apple', 'microsoft', 'google',
            'facebook', 'instagram', 'twitter', 'linkedin', 'ebay', 'wells fargo',
            'bank of america', 'chase', 'citibank', 'coinbase', 'binance'
        }
    
    def extract_features(self, text: str) -> TextFeatures:
        """Extract statistical features from text"""
        # Basic counts
        words = re.findall(r'\b\w+\b', text.lower())
        word_count = len(words)
        sentence_count = len(re.findall(r'[.!?]+', text))
        
        # Average word length
        avg_word_length = sum(len(w) for w in words) / word_count if word_count > 0 else 0
        
        # Uppercase ratio
        uppercase_chars = sum(1 for c in text if c.isupper())
        total_chars = sum(1 for c in text if c.isalpha())
        uppercase_ratio = uppercase_chars / total_chars if total_chars > 0 else 0
        
        # Punctuation counts
        exclamation_count = text.count('!')
        question_count = text.count('?')
        
        # Extract entities
        urls = self.url_pattern.findall(text)
        emails = self.email_pattern.findall(text)
        currencies = self.currency_pattern.findall(text)
        
        # Suspicious domain count
        suspicious_domain_count = sum(
            1 for url in urls 
            if any(tld in url.lower() for tld in self.suspicious_tlds)
        )
        
        # Number count
        numbers = re.findall(r'\b\d+\b', text)
        
        return TextFeatures(
            word_count=word_count,
            sentence_count=max(1, sentence_count),
            avg_word_length=round(avg_word_length, 2),
            uppercase_ratio=round(uppercase_ratio, 3),
            exclamation_count=exclamation_count,
            question_count=question_count,
            url_count=len(urls),
            email_count=len(emails),
            
            currency_mentions=len(currencies),
            number_count=len(numbers),
            suspicious_domain_count=suspicious_domain_count
        )
    
    def scan_patterns(self, text: str) -> List[Dict]:
        """Scan text for suspicious patterns based on rules"""
        alerts = []
        text_lower = text.lower()
        
        for rule in self.rules:
            matches = re.findall(rule["pattern"], text_lower, re.IGNORECASE)
            if matches:
                alerts.append({
                    "id": rule["id"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "matches": len(matches),
                    "matched_text": list(set(matches))[:3]  # Show first 3 unique matches
                })
        
        return alerts
    
    def analyze_linguistic_features(self, text: str, features: TextFeatures) -> List[Dict]:
        """Analyze linguistic features for phishing indicators"""
        alerts = []
        
        # Excessive exclamation marks
        if features.exclamation_count > 3:
            alerts.append({
                "id": "excessive_exclamations",
                "description": f"Excessive use of exclamation marks ({features.exclamation_count})",
                "severity": "medium",
                "category": "linguistic"
            })
        
        # High uppercase ratio (shouting)
        if features.uppercase_ratio > 0.3:
            alerts.append({
                "id": "excessive_uppercase",
                "description": f"Excessive uppercase text ({features.uppercase_ratio:.1%})",
                "severity": "medium",
                "category": "linguistic"
            })
        
        # Multiple URLs (link spam)
        if features.url_count > 3:
            alerts.append({
                "id": "multiple_urls",
                "description": f"Multiple URLs detected ({features.url_count})",
                "severity": "medium",
                "category": "suspicious"
            })
        
        # Suspicious domains
        if features.suspicious_domain_count > 0:
            alerts.append({
                "id": "suspicious_domains",
                "description": f"URLs with suspicious TLDs detected ({features.suspicious_domain_count})",
                "severity": "high",
                "category": "suspicious"
            })
        
        # Short message with URL (common phishing pattern)
        if features.word_count < 20 and features.url_count > 0:
            alerts.append({
                "id": "short_message_with_url",
                "description": "Very short message with URL - common phishing pattern",
                "severity": "high",
                "category": "suspicious"
            })
        
        return alerts
    
    def check_brand_impersonation(self, text: str) -> List[Dict]:
        """Detect potential brand impersonation"""
        alerts = []
        text_lower = text.lower()
        
        for brand in self.target_brands:
            if brand in text_lower:
                # Check if it looks like impersonation
                suspicious_contexts = [
                    'verify', 'suspend', 'urgent', 'click', 'login',
                    'password', 'account', 'confirm', 'update'
                ]
                
                # Check for suspicious context around brand name
                for context in suspicious_contexts:
                    if context in text_lower:
                        alerts.append({
                            "id": f"brand_impersonation_{brand.replace(' ', '_')}",
                            "description": f"Possible {brand.title()} impersonation with '{context}' context",
                            "severity": "high",
                            "category": "impersonation",
                            "brand": brand
                        })
                        break  # Only alert once per brand
        
        return alerts
    
    def analyze_sender_patterns(self, sender_email: Optional[str] = None, 
                                sender_name: Optional[str] = None) -> List[Dict]:
        """Analyze sender information for suspicious patterns"""
        alerts = []
        
        if sender_email:
            email_lower = sender_email.lower()
            
            # Check for lookalike domains
            for brand in self.target_brands:
                if brand.replace(' ', '') in email_lower:
                    # Check if it's not the legitimate domain
                    legitimate_domains = [f'{brand.replace(" ", "")}.com', f'{brand.replace(" ", "")}.net']
                    if not any(domain in email_lower for domain in legitimate_domains):
                        alerts.append({
                            "id": f"sender_impersonation_{brand.replace(' ', '_')}",
                            "description": f"Sender email may be impersonating {brand.title()}",
                            "severity": "high",
                            "category": "impersonation"
                        })
        
        if sender_name:
            name_lower = sender_name.lower()
            
            # Check for authority impersonation
            authority_keywords = ['admin', 'support', 'security', 'noreply', 'notification']
            for keyword in authority_keywords:
                if keyword in name_lower:
                    alerts.append({
                        "id": f"authority_sender_{keyword}",
                        "description": f"Sender name uses authority keyword: {keyword}",
                        "severity": "medium",
                        "category": "impersonation"
                    })
        
        return alerts
    
    def calculate_verdict(self, alerts: List[Dict]) -> Dict[str, Any]:
        """Calculate verdict with risk scoring"""
        severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        severity_weights = {"low": 1, "medium": 3, "high": 7, "critical": 10}
        
        max_sev = 0
        total_score = 0
        category_counts = Counter()
        
        for alert in alerts:
            severity = alert.get("severity", "low").lower()
            category = alert.get("category", "general")
            
            sev_level = severity_levels.get(severity, 1)
            if sev_level > max_sev:
                max_sev = sev_level
            
            total_score += severity_weights.get(severity, 1)
            category_counts[category] += 1
        
        severity_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
        final_severity = severity_map.get(max_sev, "low")
        
        # Calculate risk score (0-100)
        max_possible = len(alerts) * 10 if alerts else 10
        risk_score = min(100, (total_score / max_possible * 100) if max_possible > 0 else 0)
        
        verdict = "safe" if max_sev <= 1 else "unsafe"
        
        return {
            "verdict": verdict,
            "severity": final_severity,
            "risk_score": round(risk_score, 2),
            "alert_count": len(alerts),
            "category_breakdown": dict(category_counts)
        }
    
    def analyze_text(self, text: str, 
                    sender_email: Optional[str] = None,
                    sender_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive text analysis for phishing detection.
        
        Args:
            text: Text content to analyze
            sender_email: Optional sender email address
            sender_name: Optional sender name
            
        Returns:
            Dict containing complete analysis results
        """
        # Extract features
        features = self.extract_features(text)
        
        # Run all detection methods
        pattern_alerts = self.scan_patterns(text)
        linguistic_alerts = self.analyze_linguistic_features(text, features)
        brand_alerts = self.check_brand_impersonation(text)
        sender_alerts = self.analyze_sender_patterns(sender_email, sender_name)
        
        # Combine all alerts
        all_alerts = pattern_alerts + linguistic_alerts + brand_alerts + sender_alerts
        
        # Calculate verdict
        result = self.calculate_verdict(all_alerts)
        
        # Extract URLs and emails for reference
        urls = self.url_pattern.findall(text)
        emails = self.email_pattern.findall(text)
        
        return {
            "text": text[:200] + "..." if len(text) > 200 else text,
            "features": {
                "word_count": features.word_count,
                "sentence_count": features.sentence_count,
                "uppercase_ratio": features.uppercase_ratio,
                "url_count": features.url_count,
                "suspicious_domain_count": features.suspicious_domain_count
            },
            "extracted_entities": {
                "urls": urls[:5],  # First 5 URLs
                "emails": emails[:5]  # First 5 emails
            },
            "alerts": all_alerts,
            "verdict": result["verdict"],
            "severity": result["severity"],
            "risk_score": result["risk_score"],
            "category_breakdown": result["category_breakdown"],
            "recommendations": self._generate_recommendations(result["verdict"], all_alerts),
            "analyzed_at": datetime.utcnow().isoformat(),
            "analyzer_version": "2.0.0"
        }
    
    def _generate_recommendations(self, verdict: str, alerts: List[Dict]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if verdict == "unsafe":
            recommendations.append("⚠️ This message shows signs of phishing - be cautious")
            
            categories = {alert.get("category") for alert in alerts}
            
            if "credential_theft" in categories or "password" in str(alerts):
                recommendations.append("🔐 NEVER provide passwords through email or messages")
                recommendations.append("Legitimate companies never ask for passwords via email")
            
            if "financial_theft" in categories:
                recommendations.append("💳 Do not provide financial information")
                recommendations.append("Contact your bank directly using official channels")
            
            if "crypto_theft" in categories:
                recommendations.append("🔑 NEVER share wallet private keys or seed phrases")
                recommendations.append("These credentials should never be requested")
            
            if "impersonation" in categories:
                recommendations.append("⚡ Verify sender identity through official channels")
                recommendations.append("Look up official contact info independently")
            
            if "malware" in categories:
                recommendations.append("🚫 Do not download or open attachments")
                recommendations.append("Scan any files with antivirus before opening")
            
            recommendations.append("Report this message to your IT/security team")
        else:
            recommendations.append("✅ Message appears safe based on current analysis")
            recommendations.append("Always verify unexpected requests independently")
        
        return recommendations


# Example usage
if __name__ == "__main__":
    analyzer = TextAnalyzer()
    
    # Test phishing message
    phishing_text = """
    URGENT! Your PayPal account has been suspended due to suspicious activity.
    
    Click here immediately to verify your identity and restore access:
    http://paypal-verify.xyz/login
    
    If you don't act within 24 hours, your account will be permanently closed.
    Enter your password and social security number to confirm.
    """
    
    result = analyzer.analyze_text(
        phishing_text,
        sender_email="noreply@paypal-security.tk",
        sender_name="PayPal Security Team"
    )
    
    print(json.dumps(result, indent=2))
