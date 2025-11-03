import json
import re
from urllib.parse import urlparse, parse_qs
import idna

EMBEDDED_RULES_JSON = r"""[
  {
    "id": "kw_connect_wallet",
    "pattern": "\\bconnect[-_ ]?wallet\\b",
    "description": "Prompt to connect a crypto wallet — common Web3 phishing bait",
    "severity": "high"
  },
  {
    "id": "kw_connectwallet",
    "pattern": "\\bconnectwallet\\b",
    "description": "Variant of connect-wallet used to trick users",
    "severity": "high"
  },
  {
    "id": "kw_claim_airdrop",
    "pattern": "\\bclaim[-_ ]?airdrop\\b",
    "description": "Claim airdrop phrase used in token/NFT scams",
    "severity": "high"
  },
  {
    "id": "kw_claimairdrop",
    "pattern": "\\bclaimairdrop\\b",
    "description": "Compact claim-airdrop variant",
    "severity": "high"
  },
  {
    "id": "kw_free_nft",
    "pattern": "\\bfree[-_ ]?nft\\b",
    "description": "Free NFT lure used by scams",
    "severity": "high"
  },
  {
    "id": "kw_mint_now",
    "pattern": "\\bmin?t[-_ ]?now\\b",
    "description": "Impatient minting call to entice immediate action",
    "severity": "high"
  },
  {
    "id": "kw_whitelist_claim",
    "pattern": "\\bwhitelist[-_ ]?claim\\b",
    "description": "Whitelist claim invitations often used to lure users",
    "severity": "high"
  },
  {
    "id": "kw_presale_mint",
    "pattern": "\\bpresale[-_ ]?mint\\b",
    "description": "Presale / mint calls that try to get funds or wallet actions",
    "severity": "high"
  },
  {
    "id": "kw_verify_wallet",
    "pattern": "\\bverify[-_ ]?wallet\\b",
    "description": "Requests to verify wallet — used to phish keys or signatures",
    "severity": "high"
  },
  {
    "id": "kw_approve_token",
    "pattern": "\\bapprove[-_ ]?token\\b",
    "description": "Approve token operations prompt — often malicious",
    "severity": "high"
  },
  {
    "id": "kw_sign_transaction",
    "pattern": "\\bsign[-_ ]?transaction\\b",
    "description": "Requests to sign transactions (can drain wallets)",
    "severity": "high"
  },
  {
    "id": "kw_private_key",
    "pattern": "\\bprivate[-_ ]?key\\b",
    "description": "Explicit request for private key (never legitimate)",
    "severity": "high"
  },
  {
    "id": "kw_seed_phrase",
    "pattern": "\\b(seed[-_ ]?phrase|mnemonic)\\b",
    "description": "Requests for seed / mnemonic — immediate red flag",
    "severity": "high"
  },
  {
    "id": "kw_restore_wallet",
    "pattern": "\\brestore[-_ ]?wallet\\b",
    "description": "Restore wallet requests used to harvest credentials",
    "severity": "high"
  },
  {
    "id": "kw_unlock_wallet",
    "pattern": "\\bunlock[-_ ]?wallet\\b",
    "description": "Unlock wallet prompts used by malicious sites",
    "severity": "high"
  },
  {
    "id": "kw_wallet_verify",
    "pattern": "\\bwallet[-_ ]?verify\\b",
    "description": "Verify wallet phrasing to trick users into signing",
    "severity": "high"
  },
  {
    "id": "kw_claim_token",
    "pattern": "\\bclaim[-_ ]?token\\b",
    "description": "Claim-token patterns used for scams",
    "severity": "high"
  },
  {
    "id": "kw_get_free",
    "pattern": "\\bget[-_ ]?free\\b",
    "description": "Generic 'get free' lure often used in scams",
    "severity": "medium"
  },
  {
    "id": "kw_free_token",
    "pattern": "\\bfree[-_ ]?token\\b",
    "description": "Free token lure — suspicious in many contexts",
    "severity": "high"
  },
  {
    "id": "kw_airdrop_claim",
    "pattern": "\\bairdrop[-_ ]?claim\\b",
    "description": "Another airdrop-claim variant used by attackers",
    "severity": "high"
  },
  {
    "id": "kw_login",
    "pattern": "\\b(login|sign[-_ ]?in)\\b",
    "description": "Generic login/signin prompts used to phish credentials",
    "severity": "medium"
  },
  {
    "id": "kw_signin",
    "pattern": "\\bsign[-_ ]?in\\b",
    "description": "signin variant used in phishing login pages",
    "severity": "medium"
  },
  {
    "id": "kw_secure_login",
    "pattern": "\\bsecure[-_ ]?login\\b",
    "description": "'secure login' in URL often used in fake login pages",
    "severity": "medium"
  },
  {
    "id": "kw_reset_password",
    "pattern": "\\b(reset[-_ ]?password|password[-_ ]?reset)\\b",
    "description": "Password reset prompts in URL often used by attackers",
    "severity": "high"
  },
  {
    "id": "kw_password_reset",
    "pattern": "\\bpassword[-_ ]?reset\\b",
    "description": "Explicit password-reset wording — suspicious",
    "severity": "high"
  },
  {
    "id": "kw_verify_email",
    "pattern": "\\bverify[-_ ]?email\\b",
    "description": "Requests to verify email used in phishing flows",
    "severity": "medium"
  },
  {
    "id": "kw_confirm_email",
    "pattern": "\\bconfirm[-_ ]?email\\b",
    "description": "Confirm email phrasing used to validate stolen accounts",
    "severity": "medium"
  },
  {
    "id": "kw_update_account",
    "pattern": "\\bupdate[-_ ]?account\\b",
    "description": "Update-account often used in account takeover attempts",
    "severity": "medium"
  },
  {
    "id": "kw_account_verify",
    "pattern": "\\baccount[-_ ]?verify\\b",
    "description": "Account verification prompts used to deceive users",
    "severity": "medium"
  },
  {
    "id": "kw_security_alert",
    "pattern": "\\bsecurity[-_ ]?alert\\b",
    "description": "Security alert wording tries to scare and compel action",
    "severity": "medium"
  },
  {
    "id": "kw_account_suspended",
    "pattern": "\\baccount[-_ ]?suspended\\b",
    "description": "Account suspended language to induce panic and clicks",
    "severity": "medium"
  },
  {
    "id": "kw_billing",
    "pattern": "\\bbilling\\b",
    "description": "Billing-related pages used for payment credential theft",
    "severity": "medium"
  },
  {
    "id": "kw_invoice",
    "pattern": "\\binvoice\\b",
    "description": "Invoice keyword is common in payment phishing",
    "severity": "medium"
  },
  {
    "id": "kw_confirm_payment",
    "pattern": "\\bconfirm[-_ ]?payment\\b",
    "description": "Confirm payment wording used to trick into approval",
    "severity": "high"
  },
  {
    "id": "kw_payment_update",
    "pattern": "\\bpayment[-_ ]?update\\b",
    "description": "Payment update prompts used for credential harvesting",
    "severity": "medium"
  },
  {
    "id": "kw_download_invoice",
    "pattern": "\\bdownload[-_ ]?invoice\\b",
    "description": "Download invoice often used to push malicious downloads",
    "severity": "medium"
  },
  {
    "id": "kw_urgent",
    "pattern": "\\burgent\\b",
    "description": "Urgent language used to pressure user into action",
    "severity": "medium"
  },
  {
    "id": "kw_action_required",
    "pattern": "\\baction[-_ ]?required\\b",
    "description": "Action required phrasing to create urgency",
    "severity": "medium"
  },
  {
    "id": "kw_verify_now",
    "pattern": "\\bverify[-_ ]?now\\b",
    "description": "Immediate verification request — suspicious",
    "severity": "medium"
  },
  {
    "id": "kw_limited_time",
    "pattern": "\\blimited[-_ ]?time\\b",
    "description": "Limited time offers are common phishing ploys",
    "severity": "medium"
  },
  {
    "id": "kw_reward",
    "pattern": "\\breward\\b",
    "description": "Reward wording used to entice clicks",
    "severity": "medium"
  },
  {
    "id": "kw_bonus_offer",
    "pattern": "\\bbonus[-_ ]?offer\\b",
    "description": "Bonus offers that lure victims to malicious links",
    "severity": "medium"
  },
  {
    "id": "kw_click_here",
    "pattern": "\\bclick[-_ ]?here\\b",
    "description": "Generic click-here prompts found in many phishing URLs",
    "severity": "low"
  },
  {
    "id": "kw_customer_support",
    "pattern": "\\bcustomer[-_ ]?support\\b",
    "description": "Customer support-like URLs used by impersonators",
    "severity": "medium"
  },
  {
    "id": "kw_support_team",
    "pattern": "\\bsupport[-_ ]?team\\b",
    "description": "Support team wording to impersonate staff",
    "severity": "medium"
  },
  {
    "id": "kw_verify_identity",
    "pattern": "\\bverify[-_ ]?identity\\b",
    "description": "Identity verification requests often fraudulent",
    "severity": "medium"
  },
  {
    "id": "kw_secure_portal",
    "pattern": "\\bsecure[-_ ]?portal\\b",
    "description": "Secure portal wording to mimic legitimate services",
    "severity": "medium"
  },
  {
    "id": "kw_token_claim",
    "pattern": "\\btoken[-_ ]?claim\\b",
    "description": "Token claim prompts used in crypto scams",
    "severity": "high"
  },
  {
    "id": "kw_connect_wallet_now",
    "pattern": "\\bconnect[-_ ]?wallet[-_ ]?now\\b",
    "description": "Immediate connect-wallet prompts — urgent Web3 phishing bait",
    "severity": "high"
  },
  {
    "id": "kw_giveaway",
    "pattern": "\\bgiveaway\\b",
    "description": "Giveaway calls used to lure victims to malicious links",
    "severity": "medium"
  },
  {
    "id": "kw_login",
    "pattern": "\\blogin\\b",
    "description": "Generic login prompt often used in phishing URLs",
    "severity": "medium"
  },
  {
    "id": "kw_signin",
    "pattern": "\\bsign[-_ ]?in\\b",
    "description": "Sign-in variant used to phish credentials",
    "severity": "medium"
  },
  {
    "id": "kw_account",
    "pattern": "\\baccount\\b",
    "description": "Account references often used in phishing pages",
    "severity": "medium"
  },
  {
    "id": "kw_verify",
    "pattern": "\\bverify\\b",
    "description": "Verification prompts used to trick users",
    "severity": "high"
  },
  {
    "id": "kw_secure",
    "pattern": "\\bsecure\\b",
    "description": "Fake secure login references used by attackers",
    "severity": "medium"
  },
  {
    "id": "kw_update",
    "pattern": "\\bupdate\\b",
    "description": "Update references for phishing account takeover",
    "severity": "medium"
  },
  {
    "id": "kw_password",
    "pattern": "\\bpassword\\b",
    "description": "Password-related prompts used in phishing attempts",
    "severity": "high"
  },
  {
    "id": "kw_reset",
    "pattern": "\\breset\\b",
    "description": "Password reset term often used in phishing attacks",
    "severity": "high"
  },
  {
    "id": "kw_confirm",
    "pattern": "\\bconfirm\\b",
    "description": "Confirm prompts used to trick users",
    "severity": "medium"
  },
  {
    "id": "kw_billing",
    "pattern": "\\bbilling\\b",
    "description": "Billing pages used for payment credential theft",
    "severity": "high"
  },
  {
    "id": "kw_invoice",
    "pattern": "\\binvoice\\b",
    "description": "Invoice keyword used in fake payment/phishing pages",
    "severity": "medium"
  },
  {
    "id": "kw_bank",
    "pattern": "\\bbank\\b",
    "description": "Bank references in phishing attempts",
    "severity": "medium"
  },
  {
    "id": "kw_alert",
    "pattern": "\\balert\\b",
    "description": "Alert used to create urgency in phishing links",
    "severity": "medium"
  },
  {
    "id": "kw_notice",
    "pattern": "\\bnotice\\b",
    "description": "Notice phrasing often used to trick users",
    "severity": "low"
  },
  {
    "id": "kw_support",
    "pattern": "\\bsupport\\b",
    "description": "Support references used to impersonate legitimate services",
    "severity": "low"
  },
  {
    "id": "kw_urgent",
    "pattern": "\\burgent\\b",
    "description": "Urgency used to compel user to act immediately",
    "severity": "medium"
  },
  {
    "id": "kw_reward",
    "pattern": "\\breward\\b",
    "description": "Reward wording used to entice clicks",
    "severity": "low"
  },
  {
    "id": "kw_bonus",
    "pattern": "\\bbonus\\b",
    "description": "Bonus offers lure used by attackers",
    "severity": "low"
  },
  {
    "id": "kw_upgrade",
    "pattern": "\\bupgrade\\b",
    "description": "Upgrade prompts often used in phishing pages",
    "severity": "low"
  },
  {
    "id": "kw_gift",
    "pattern": "\\bgift\\b",
    "description": "Gift lure often used in scams",
    "severity": "low"
  },
  {
    "id": "kw_redeem",
    "pattern": "\\bredeem\\b",
    "description": "Redeem call used to lure clicks",
    "severity": "low"
  },
  {
    "id": "kw_temporary",
    "pattern": "\\btemporary\\b",
    "description": "Temporary access or account wording often used in phishing",
    "severity": "low"
  },
  {
    "id": "kw_notification",
    "pattern": "\\bnotification\\b",
    "description": "Notification used to create a false sense of urgency",
    "severity": "low"
  }
]"""

class URLAnalyzer:
    def __init__(self, rules_path=None):
        
        if rules_path:
            try:
                with open(rules_path, "r") as f:
                    self.rules = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                self.rules = json.loads(EMBEDDED_RULES_JSON)
        else:
            self.rules = json.loads(EMBEDDED_RULES_JSON)

        self.suspicious_tlds = ['xyz', 'top', 'info', 'club', 'pw', 'cn', 'ru']
        self.brand_domains = ['paypal', 'google', 'facebook', 'apple']

    def analyze_url_metadata(self, url):
        metadata = {}
        parsed = urlparse(url)

        # URL scheme
        metadata["scheme"] = parsed.scheme

        # Domain info
        domain = parsed.hostname or ""
        metadata["domain"] = domain
        metadata["is_ip"] = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) is not None

        # Suspicious TLD
        tld = domain.split('.')[-1].lower() if '.' in domain else ''
        metadata["suspicious_tld"] = tld in self.suspicious_tlds

        # Subdomain tricks
        sub_parts = domain.split('.')
        metadata["subdomain_tricks"] = len(sub_parts) > 2 and sub_parts[-2] in self.brand_domains

        # Punycode check
        try:
            decoded = idna.decode(domain)
            metadata["punycode"] = decoded != domain
        except idna.IDNAError:
            metadata["punycode"] = False

        # Path length
        metadata["path_length"] = len(parsed.path)

        # Query keywords
        query_params = parse_qs(parsed.query)
        metadata["query_keywords"] = [k for k in query_params if k.lower() in ["private_key", "seed_phrase", "mnemonic"]]

        return metadata

    def scan_keywords(self, url):
        alerts = []
        for rule in self.rules:
            if re.search(rule["pattern"], url, re.IGNORECASE):
                alerts.append({
                    "id": rule["id"],
                    "description": rule["description"],
                    "severity": rule["severity"]
                })
        return alerts

    def metadata_alerts(self, metadata):
        alerts = []

        if metadata["scheme"] == "http":
            alerts.append({"id": "http_scheme", "description": "Non-HTTPS URL", "severity": "medium"})
        if metadata["is_ip"]:
            alerts.append({"id": "ip_domain", "description": "URL uses an IP address instead of domain", "severity": "high"})
        if metadata["suspicious_tld"]:
            alerts.append({"id": "suspicious_tld", "description": f"Suspicious TLD detected: {metadata['domain'].split('.')[-1]}", "severity": "medium"})
        if metadata["subdomain_tricks"]:
            alerts.append({"id": "subdomain_trick", "description": "Suspicious subdomain pattern", "severity": "high"})
        if metadata["punycode"]:
            alerts.append({"id": "punycode_domain", "description": "Punycode / Unicode domain detected", "severity": "high"})
        if metadata["path_length"] > 100:
            alerts.append({"id": "long_path", "description": "Excessively long URL path", "severity": "low"})
        for q in metadata["query_keywords"]:
            alerts.append({"id": f"query_{q}", "description": f"Suspicious query parameter: {q}", "severity": "high"})

        return alerts

    def calculate_verdict(self, alerts):
        severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        max_sev = 0
        for alert in alerts:
            sev = severity_levels.get(alert["severity"].lower(), 1)
            if sev > max_sev:
                max_sev = sev

        severity_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
        final_severity = severity_map.get(max_sev, "low")

        verdict = "safe" if max_sev <= 1 else "unsafe"
        return {"verdict": verdict, "severity": final_severity}

    def analyze_url(self, url):
        metadata = self.analyze_url_metadata(url)
        keyword_alerts = self.scan_keywords(url)
        meta_alerts = self.metadata_alerts(metadata)

        all_alerts = keyword_alerts + meta_alerts
        result = self.calculate_verdict(all_alerts)

        return {
            "url": url,
            "metadata": metadata,
            "alerts": all_alerts,
            "verdict": result["verdict"],
            "severity": result["severity"]
        }