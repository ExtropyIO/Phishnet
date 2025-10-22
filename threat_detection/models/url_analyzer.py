import json
import re
from urllib.parse import urlparse, parse_qs
import idna

# Load rules.json
with open("rules.json", "r") as f:
    rules = json.load(f)

# List of suspicious TLDs
SUSPICIOUS_TLDS = ['xyz', 'top', 'info', 'club', 'pw', 'cn', 'ru']

# Metadata analyzer
def analyze_url_metadata(url):
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
    metadata["suspicious_tld"] = tld in SUSPICIOUS_TLDS

    # Subdomain tricks (main domain appears as subdomain)
    sub_parts = domain.split('.')
    metadata["subdomain_tricks"] = len(sub_parts) > 2 and sub_parts[-2] in ['paypal', 'google', 'facebook', 'apple']

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

# Keyword scan
def scan_keywords(url):
    alerts = []
    for rule in rules:
        if re.search(rule["pattern"], url, re.IGNORECASE):
            alerts.append({
                "id": rule["id"],
                "description": rule["description"],
                "severity": rule["severity"]
            })
    return alerts

# Metadata checks as alerts
def metadata_alerts(metadata):
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

# Verdict calculation
def calculate_verdict(alerts):
    severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    max_sev = 0
    for alert in alerts:
        sev = severity_levels.get(alert["severity"].lower(), 1)
        if sev > max_sev:
            max_sev = sev

    # Map numeric to string severity
    severity_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
    final_severity = severity_map.get(max_sev, "low")

    verdict = "safe" if max_sev <= 1 else "unsafe"
    return {"verdict": verdict, "severity": final_severity}

# Full analysis function
def analyze_url(url):
    metadata = analyze_url_metadata(url)
    keyword_alerts = scan_keywords(url)
    meta_alerts = metadata_alerts(metadata)

    all_alerts = keyword_alerts + meta_alerts
    result = calculate_verdict(all_alerts)

    return {
        "url": url,
        "metadata": metadata,
        "alerts": all_alerts,
        "verdict": result["verdict"],
        "severity": result["severity"]
    }

# Example uage
if __name__ == "__main__":
    test_url = "http://paypal.com.example.xyz/login?private_key=123"
    report = analyze_url(test_url)
    print(json.dumps(report, indent=2))
