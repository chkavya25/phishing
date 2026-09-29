import ipaddress
import re
import math
from urllib.parse import urlparse

SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure", "account", "update",
    "bank", "signin", "confirm", "password", "wallet", "payment",
    "free", "bonus", "claim", "security", "unlock"
}

def normalize_url(url):
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        return "http://" + url
    return url

def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        return 0

def extract_features(url):
    u = normalize_url(url)
    p = urlparse(u)
    host = p.netloc.split("@")[-1].split(":")[0].lower()
    path = p.path or ""
    query = p.query or ""
    full = u.lower()

    special_count = sum(full.count(c) for c in "@?=&%_-")
    suspicious_count = sum(1 for w in SUSPICIOUS_WORDS if w in full)
    subdomains = max(0, host.count(".") - 1)

    return {
        "url_length": len(full),
        "hostname_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "dot_count": full.count("."),
        "hyphen_count": full.count("-"),
        "slash_count": full.count("/"),
        "at_count": full.count("@"),
        "question_count": full.count("?"),
        "equal_count": full.count("="),
        "ampersand_count": full.count("&"),
        "percent_count": full.count("%"),
        "digit_count": sum(c.isdigit() for c in full),
        "special_count": special_count,
        "subdomain_count": subdomains,
        "has_ip": is_ip(host),
        "has_https": 1 if p.scheme.lower() == "https" else 0,
        "has_port": 1 if p.port else 0,
        "suspicious_word_count": suspicious_count,
        "entropy": round(_entropy(full), 4),
    }

def _entropy(s):
    if not s:
        return 0.0
    from collections import Counter
    counts = Counter(s)
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())
