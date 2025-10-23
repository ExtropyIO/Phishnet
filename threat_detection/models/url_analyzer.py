import json
import re
from urllib.parse import urlparse, parse_qs
import idna

class URLAnalyzer:
    def __init__(self, rules_path="rules.json"):
        with open(rules_path, "r") as f:
            self.rules = json.load(f)

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

