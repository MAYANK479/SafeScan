"""
SafeScan Behavioral & DOM Auditor Agent.
Performs in-depth DOM inspection, detecting credential harvesting form inputs,
obfuscated client-side JavaScript, data exfiltration beacons (Discord/Telegram webhooks),
and brand-domain impersonation mismatches across 50+ monitored brands.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Any
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from .config import SafeScanConfig, default_config
from .scraper import ScrapeResult


@dataclass
class BehavioralReport:
    url: str
    behavioral_score: float = 0.0  # 0.0 to 10.0
    brand_impersonations: List[Dict[str, Any]] = field(default_factory=list)
    sensitive_form_inputs: List[Dict[str, str]] = field(default_factory=list)
    obfuscated_js_indicators: List[str] = field(default_factory=list)
    exfiltration_endpoints: List[str] = field(default_factory=list)
    external_link_risk: Dict[str, Any] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "behavioral_score": round(self.behavioral_score, 2),
            "brand_impersonations": self.brand_impersonations,
            "sensitive_form_inputs": self.sensitive_form_inputs,
            "obfuscated_js_indicators": self.obfuscated_js_indicators,
            "exfiltration_endpoints": self.exfiltration_endpoints,
            "external_link_risk": self.external_link_risk,
            "reasons": self.reasons,
        }


class BehavioralAuditor:
    """
    Deep DOM auditor evaluating HTML elements, script tags, and brand consistency.
    """

    def __init__(self, config: SafeScanConfig = default_config):
        self.config = config

    def audit(self, scrape_result: ScrapeResult) -> BehavioralReport:
        html = scrape_result.html or ""
        url = scrape_result.url
        parsed = urlparse(url if url.startswith(("http://", "https://")) else f"http://{url}")
        current_domain = parsed.netloc.lower().split(":")[0]

        reasons: List[str] = []
        raw_score = 0.0

        soup = BeautifulSoup(html, "html.parser")

        # 1. Inspect Form Inputs for Sensitive Harvesting
        sensitive_inputs: List[Dict[str, str]] = []
        input_tags = soup.find_all(["input", "textarea"])
        sensitive_keywords = [
            "seed", "mnemonic", "private_key", "privatekey", "recovery",
            "passphrase", "ssn", "socialsecurity", "cvv", "cardnumber",
            "creditcard", "bankpin", "otp", "secret"
        ]

        for tag in input_tags:
            tag_name = tag.get("name", "").lower()
            tag_id = tag.get("id", "").lower()
            tag_placeholder = tag.get("placeholder", "").lower()
            tag_type = tag.get("type", "text").lower()

            combined_str = f"{tag_name} {tag_id} {tag_placeholder}"
            for kw in sensitive_keywords:
                if kw in combined_str:
                    sensitive_inputs.append({
                        "tag": tag.name,
                        "type": tag_type,
                        "matched_field": kw,
                        "name": tag_name or tag_id,
                    })
                    break

        if sensitive_inputs:
            reasons.append(f"Suspicious form fields harvesting sensitive secrets ({len(sensitive_inputs)} inputs found)")
            raw_score += 4.0

        # 2. Obfuscated JavaScript Inspection
        obfuscated_js: List[str] = []
        js_patterns = {
            "eval_execution": r"\beval\s*\(",
            "atob_base64_decoder": r"\batob\s*\(",
            "charcode_generator": r"String\.fromCharCode\s*\(",
            "unescape_decoder": r"\bunescape\s*\(",
            "packed_script": r"}\('[\w\d]+',[\d]+,[\d]+,'[\w\|]+'\.split\('\|'\)",
        }

        for rule_name, pat in js_patterns.items():
            if re.search(pat, html, re.IGNORECASE):
                obfuscated_js.append(rule_name)

        if obfuscated_js:
            reasons.append(f"Obfuscated JavaScript patterns detected: {', '.join(obfuscated_js)}")
            raw_score += 2.5

        # 3. Data Exfiltration Endpoint Detection
        exfil_endpoints: List[str] = []
        # Check Discord webhooks
        if re.search(r"discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+", html, re.IGNORECASE):
            exfil_endpoints.append("Discord Webhook C2 Exfiltration endpoint")
            reasons.append("Hardcoded Discord Webhook detected (common token/credential stealer C2)")
            raw_score += 4.5

        # Check Telegram Bot API exfiltration
        if re.search(r"api\.telegram\.org/bot\d+:[A-Za-z0-9_-]+/sendmessage", html, re.IGNORECASE):
            exfil_endpoints.append("Telegram Bot C2 Exfiltration endpoint")
            reasons.append("Hardcoded Telegram Bot token endpoint detected (common phishing exfiltration channel)")
            raw_score += 4.5

        # Check Beacon API
        if re.search(r"navigator\.sendBeacon\s*\(", html, re.IGNORECASE):
            exfil_endpoints.append("navigator.sendBeacon API call")

        # 4. Brand Impersonation Mismatch Analysis
        impersonations: List[Dict[str, Any]] = []
        title_text = (soup.title.string or "").lower() if soup.title else ""
        heading_text = " ".join([h.get_text() for h in soup.find_all(["h1", "h2"])]).lower()
        has_login_or_creds = bool(sensitive_inputs) or ("password" in html.lower()) or ("login" in html.lower()) or ("seed" in html.lower())

        for brand, legitimate_domains in self.config.MONITORED_BRANDS.items():
            # Brand is considered target of impersonation IF:
            # - Brand is in the title, OR
            # - Brand is in an H1/H2 header, OR
            # - Brand is mentioned AND page asks for login/credentials
            # (Ignores incidental social media footer links like 'Follow us on Twitter')
            brand_in_title = brand in title_text
            brand_in_header = brand in heading_text
            brand_prominent = brand_in_title or brand_in_header or (has_login_or_creds and brand in scrape_result.text_content.lower()[:1500])

            if brand_prominent:
                # Is current domain legitimate for this brand?
                is_legit = any(
                    current_domain == legit or current_domain.endswith("." + legit)
                    for legit in legitimate_domains
                )
                if not is_legit:
                    impersonation_info = {
                        "brand": brand.capitalize(),
                        "current_domain": current_domain,
                        "legitimate_domains": legitimate_domains,
                    }
                    impersonations.append(impersonation_info)
                    reasons.append(
                        f"Brand Impersonation: Page targets '{brand.capitalize()}' in title/headers/forms but domain '{current_domain}' is NOT authorized ({', '.join(legitimate_domains)})"
                    )
                    raw_score += 4.0

        # 5. Outbound External Link Analysis
        links = [a.get("href", "") for a in soup.find_all("a", href=True)]
        external_bad_tld_links = []
        for l in links:
            if l.startswith("http"):
                parsed_link = urlparse(l)
                link_netloc = parsed_link.netloc.lower()
                if any(link_netloc.endswith(tld) for tld in self.config.HIGH_RISK_TLDS):
                    external_bad_tld_links.append(l)

        link_risk_data = {
            "total_links": len(links),
            "bad_tld_links_count": len(external_bad_tld_links),
        }
        if len(external_bad_tld_links) >= 2:
            reasons.append(f"Multiple outbound hyperlinks ({len(external_bad_tld_links)}) point to known malicious/shady TLDs")
            raw_score += 2.0

        normalized_score = min(round(raw_score, 2), 10.0)

        return BehavioralReport(
            url=url,
            behavioral_score=normalized_score,
            brand_impersonations=impersonations,
            sensitive_form_inputs=sensitive_inputs,
            obfuscated_js_indicators=obfuscated_js,
            exfiltration_endpoints=exfil_endpoints,
            external_link_risk=link_risk_data,
            reasons=reasons,
        )
