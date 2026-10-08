"""
SafeScan Heuristic & Lexical Analyzer Agent.
Performs deterministic threat assessment through URL lexical feature extraction,
Shannon entropy calculation, suspicious TLD matching, and signature pattern matching.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Any
from urllib.parse import urlparse
from .config import SafeScanConfig, default_config
from .scraper import ScrapeResult


@dataclass
class HeuristicReport:
    url: str
    risk_score: float = 0.0  # 0.0 to 10.0
    preliminary_verdict: str = "benign"  # benign | suspicious | malicious
    reasons: List[str] = field(default_factory=list)
    lexical_features: Dict[str, Any] = field(default_factory=dict)
    matched_patterns: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "risk_score": round(self.risk_score, 2),
            "preliminary_verdict": self.preliminary_verdict,
            "reasons": self.reasons,
            "lexical_features": self.lexical_features,
            "matched_patterns": self.matched_patterns,
        }


class HeuristicAnalyzer:
    """
    Deterministic threat evaluation engine analyzing URL lexical characteristics
    and body content signatures.
    """

    def __init__(self, config: SafeScanConfig = default_config):
        self.config = config

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """
        Calculates character entropy to detect algorithmic/random domain generation (DGA).
        Legitimate domains like 'google.com' have low entropy (~2.5 - 3.2).
        Malicious randomized domains like 'xn--80ak6aa92e.ru' or 'xkj893nfc8.pw' have high entropy (>3.8).
        """
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text)
        entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
        return round(entropy, 3)

    def extract_lexical_features(self, url: str) -> Dict[str, Any]:
        """Extracts security features from the URL structure."""
        parsed = urlparse(url if url.startswith(("http://", "https://")) else f"http://{url}")
        netloc = parsed.netloc.lower()
        path = parsed.path.lower()

        # Remove port if present
        domain = netloc.split(":")[0]

        # IP address as domain indicator (e.g. http://192.168.1.1/login)
        ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
        has_ip = bool(re.match(ip_pattern, domain))

        # Punycode / IDN Homograph check (e.g. xn-- or double hyphen trick)
        has_punycode = "xn--" in domain or "--" in domain

        # High risk TLD check
        has_high_risk_tld = any(domain.endswith(tld) for tld in self.config.HIGH_RISK_TLDS)

        # Entropy of domain name
        domain_entropy = self.calculate_shannon_entropy(domain)

        return {
            "domain": domain,
            "url_length": len(url),
            "domain_length": len(domain),
            "num_dots": domain.count("."),
            "num_hyphens": domain.count("-"),
            "num_digits": sum(c.isdigit() for c in domain),
            "has_ip_host": has_ip,
            "has_punycode": has_punycode,
            "has_high_risk_tld": has_high_risk_tld,
            "domain_entropy": domain_entropy,
            "is_https": parsed.scheme == "https",
        }

    def analyze(self, scrape_result: ScrapeResult) -> HeuristicReport:
        """
        Evaluates lexical and text signatures to generate a preliminary risk assessment.
        """
        url = scrape_result.url
        lexical = self.extract_lexical_features(url)
        reasons: List[str] = []
        matched_patterns: List[Dict[str, Any]] = []
        raw_score = 0.0

        # 1. Scrape Status & Network Red Flags
        if scrape_result.status != "success":
            if scrape_result.status_code == 502 or "Domain resolution" in (scrape_result.error_message or ""):
                reasons.append("Domain resolution failed (NXDOMAIN / unroutable host)")
                raw_score += 4.0
            elif scrape_result.status_code == 495 or "SSL" in (scrape_result.error_message or ""):
                reasons.append("SSL/TLS certificate verification failure")
                raw_score += 3.0
            else:
                reasons.append(f"HTTP request failed: {scrape_result.error_message}")
                raw_score += 2.0

        # 2. Lexical URL Red Flags
        if lexical["has_ip_host"]:
            reasons.append("URL uses raw numerical IP address instead of domain name")
            raw_score += 3.5

        if lexical["has_punycode"]:
            reasons.append("Punycode / IDN homograph attack indicator detected ('xn--' or multiple hyphens)")
            raw_score += 3.0

        if lexical["has_high_risk_tld"]:
            reasons.append("Domain uses high-risk Top-Level Domain (TLD) heavily linked with cybercrime")
            raw_score += 2.5

        if lexical["num_hyphens"] >= 3:
            reasons.append(f"Excessive hyphenation in domain ({lexical['num_hyphens']} hyphens)")
            raw_score += 1.5

        if lexical["domain_entropy"] > 4.1:
            reasons.append(f"Unusually high domain character entropy ({lexical['domain_entropy']}), suggesting DGA/random generation")
            raw_score += 2.0

        if not lexical["is_https"]:
            reasons.append("Insecure plain HTTP protocol (lacks SSL encryption)")
            raw_score += 1.0

        # 3. Content Pattern Signatures
        content_lower = (scrape_result.text_content + " " + scrape_result.html).lower()
        for rule in self.config.HEURISTIC_PATTERNS:
            pattern = rule["regex"]
            if re.search(pattern, content_lower, re.IGNORECASE):
                weight = rule["weight"]
                rule_name = rule["name"]
                matched_patterns.append({
                    "signature": rule_name,
                    "weight": weight,
                })
                reasons.append(f"Content match: [{rule_name}]")
                raw_score += weight

        # Normalize risk score to 0 - 10 scale
        normalized_score = min(round(raw_score, 2), 10.0)

        # Assign verdict
        if normalized_score >= self.config.MALICIOUS_THRESHOLD:
            verdict = "malicious"
        elif normalized_score >= self.config.SUSPICIOUS_THRESHOLD:
            verdict = "suspicious"
        else:
            verdict = "benign"

        return HeuristicReport(
            url=url,
            risk_score=normalized_score,
            preliminary_verdict=verdict,
            reasons=reasons,
            lexical_features=lexical,
            matched_patterns=matched_patterns,
        )
