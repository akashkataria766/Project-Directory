import re
import urllib.parse
import ipaddress
import difflib
import requests

KNOWN_BRANDS = {
    "amazon", "apple", "facebook", "google", "instagram", "linkedin",
    "microsoft", "netflix", "paypal", " tiktok".strip(), "twitter",
}
LOOKALIKE_TRANSLATIONS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s"})

# Function to check Google Safe Browsing API
def check_google_safebrowsing(url, api_key):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

    payload = {
        "client": {"clientId": "web-security-analyzer", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    headers = {'Content-Type': 'application/json'}
    
    try:
        response = requests.post(api_url, json=payload, headers=headers, timeout=10)
    except requests.RequestException as error:
        return False, f"❌ API request failed: {error}"

    if response.status_code == 200:
        try:
            result = response.json()
        except ValueError:
            return False, "Google returned an invalid response."
        if "matches" in result:
            match = result["matches"][0]
            threat_type = match.get("threatType", "known threat").replace("_", " ").title()
            platform = match.get("platformType", "unknown platform").replace("_", " ").title()
            return True, f"Google detected {threat_type} for {platform}."
        else:
            return False, "✅ URL is safe according to Google Safe Browsing."
    if response.status_code in {400, 401, 403}:
        return False, "Google rejected the API key. Create a new key, enable Safe Browsing API, and restart the app."
    if response.status_code == 429:
        return False, "Google API quota has been exceeded. Check Google Cloud billing and quotas."
    else:
        return False, f"Google Safe Browsing is temporarily unavailable (HTTP {response.status_code})."

# Function to check for suspicious patterns
def is_suspicious_url(url):
    if not isinstance(url, str) or not url.strip():
        return True, "A URL is required."

    url = normalize_address(url)
    phishing_keywords = ["login", "verify", "update", "secure", "bank", "confirm", "account", "paypal", "ebay"]
    try:
        parsed_url = urllib.parse.urlparse(url)
        parsed_hostname = parsed_url.hostname
    except ValueError:
        return True, "URL contains an invalid hostname or port."

    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        return True, "URL must include a valid http or https domain."

    try:
        is_ip_address = isinstance(parsed_hostname, str) and isinstance(
            ipaddress.ip_address(parsed_hostname), ipaddress.IPv4Address
        )
    except ValueError:
        is_ip_address = False

    if is_ip_address:
        return True, "URL contains an IP address instead of a domain."

    for keyword in phishing_keywords:
        if keyword in parsed_url.netloc.lower() or keyword in parsed_url.path.lower():
            return True, f"Suspicious keyword '{keyword}' detected in URL."

    if parsed_url.netloc.count('.') > 2:
        return True, "URL has multiple subdomains, which is often a phishing tactic."

    return False, "✅ URL appears to be safe."


def find_brand_impersonation(hostname):
    """Detect common one-character brand lookalikes without flagging exact brands."""
    labels = [label.lower() for label in hostname.split(".") if label]
    for label in labels:
        translated = label.translate(LOOKALIKE_TRANSLATIONS)
        for brand in KNOWN_BRANDS:
            similarity = difflib.SequenceMatcher(None, label, brand).ratio()
            if label != brand and (translated == brand or (len(label) >= 5 and similarity >= 0.8)):
                return brand, label
    return None, None


def normalize_address(value):
    """Add a scheme when a user enters a bare domain or IPv4 address."""
    if not isinstance(value, str):
        return ""

    value = value.strip()
    if value and not re.match(r"^[a-z][a-z0-9+.-]*://", value, re.IGNORECASE):
        return f"https://{value}"
    return value


def analyze_url(value, api_key=None):
    """Return an explainable local and Safe Browsing assessment."""
    original_value = value.strip() if isinstance(value, str) else ""
    normalized_value = normalize_address(original_value)

    checks = []
    risk_points = 0
    local_suspicious, local_reason = is_suspicious_url(normalized_value)
    if local_suspicious:
        checks.append({"name": "Local pattern review", "status": "danger", "detail": local_reason})
        risk_points += 55
    else:
        checks.append({"name": "Local pattern review", "status": "safe", "detail": "No suspicious local patterns found."})

    try:
        parsed_url = urllib.parse.urlparse(normalized_value)
        parsed_hostname = parsed_url.hostname
        parsed_port = parsed_url.port
    except ValueError:
        parsed_url = urllib.parse.urlparse("https://invalid")
        parsed_hostname = None
        parsed_port = None
    has_valid_port = ":" not in parsed_url.netloc or parsed_port is not None
    is_valid = (
        parsed_url.scheme in {"http", "https"}
        and bool(parsed_url.netloc)
        and bool(parsed_hostname)
        and has_valid_port
    )
    if is_valid:
        checks.append({"name": "Address format", "status": "safe", "detail": "The address uses a valid HTTP or HTTPS format."})
    else:
        checks.append({"name": "Address format", "status": "danger", "detail": "Use a domain, URL, or IPv4 address."})

    if is_valid:
        hostname = parsed_hostname or ""
        impersonated_brand, lookalike_label = find_brand_impersonation(hostname)
        if impersonated_brand:
            checks.append({"name": "Brand impersonation", "status": "danger", "detail": f"The hostname '{lookalike_label}' closely resembles '{impersonated_brand}'. This can indicate a typosquatting or impersonation domain."})
            risk_points += 60
            local_suspicious = True
        else:
            checks.append({"name": "Brand impersonation", "status": "safe", "detail": "No close match to the monitored brand names was found."})
        if parsed_url.scheme != "https":
            checks.append({"name": "Transport security", "status": "warning", "detail": "The address uses HTTP, so data can be exposed in transit."})
            risk_points += 15
        else:
            checks.append({"name": "Transport security", "status": "safe", "detail": "The address uses encrypted HTTPS transport."})

        if parsed_url.username or parsed_url.password:
            checks.append({"name": "Credential protection", "status": "danger", "detail": "The URL contains embedded login credentials, which can leak through history or logs."})
            risk_points += 35
        else:
            checks.append({"name": "Credential protection", "status": "safe", "detail": "No embedded username or password was found."})

        if parsed_port and parsed_port not in {80, 443}:
            checks.append({"name": "Port review", "status": "warning", "detail": f"The address uses uncommon port {parsed_port}. Verify that it is expected."})
            risk_points += 10
        else:
            checks.append({"name": "Port review", "status": "safe", "detail": "The address uses a standard web port."})

        if "xn--" in hostname.lower():
            checks.append({"name": "Internationalized hostname", "status": "warning", "detail": "The hostname uses punycode; visually similar characters can hide impersonation."})
            risk_points += 20
        else:
            checks.append({"name": "Internationalized hostname", "status": "safe", "detail": "No punycode hostname was found."})

        if any(character in normalized_value for character in ["%00", "%0d", "%0a", "\\"]):
            checks.append({"name": "Encoded character review", "status": "warning", "detail": "Encoded control characters or backslashes can obscure the true destination."})
            risk_points += 20
        else:
            checks.append({"name": "Encoded character review", "status": "safe", "detail": "No suspicious encoded control characters were found."})

        if len(normalized_value) > 200:
            checks.append({"name": "URL complexity", "status": "warning", "detail": "This unusually long address is harder to inspect and may hide its destination."})
            risk_points += 10
        else:
            checks.append({"name": "URL complexity", "status": "safe", "detail": "The address length is within a normal range."})

    if local_suspicious or not is_valid:
        status_counts = {status: sum(check["status"] == status for check in checks) for status in ["safe", "warning", "danger"]}
        return {
            "input": original_value,
            "normalized": normalized_value,
            "overall": "danger",
            "headline": "Unsafe or suspicious address",
            "checks": checks,
            "status_counts": status_counts,
            "score": max(5, 100 - risk_points),
            "score_label": "High risk",
        }

    if not api_key:
        checks.append({"name": "Google Safe Browsing", "status": "warning", "detail": "Not checked because the API key is not configured."})
        status_counts = {"safe": sum(check["status"] == "safe" for check in checks), "warning": 1, "danger": 0}
        return {
            "input": original_value,
            "normalized": normalized_value,
            "overall": "warning",
            "headline": "Local review passed; external check unavailable",
            "checks": checks,
            "status_counts": status_counts,
            "score": max(35, 100 - risk_points - 20),
            "score_label": "Needs external verification",
        }

    google_suspicious, google_reason = check_google_safebrowsing(normalized_value, api_key)
    api_unavailable = google_reason.startswith(("Google rejected", "Google API quota", "Google Safe Browsing is temporarily", "❌ API request failed", "Google returned an invalid"))
    checks.append({
        "name": "Google Safe Browsing",
        "status": "danger" if google_suspicious else "warning" if api_unavailable else "safe",
        "detail": google_reason,
    })
    status_counts = {"safe": 0, "warning": 0, "danger": 0}
    for check in checks:
        status_counts[check["status"]] += 1

    return {
        "input": original_value,
        "normalized": normalized_value,
        "overall": "danger" if google_suspicious else "warning" if api_unavailable or risk_points >= 25 else "safe",
        "headline": "Threat detected" if google_suspicious else "Review needs attention" if api_unavailable or risk_points >= 25 else "No known threat detected",
        "checks": checks,
        "status_counts": status_counts,
        "score": 10 if google_suspicious else max(20, 100 - risk_points - (20 if api_unavailable else 0)),
        "score_label": "High risk" if google_suspicious else "Needs review" if api_unavailable or risk_points >= 25 else "Low risk",
    }
