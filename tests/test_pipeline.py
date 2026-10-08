"""
SafeScan Comprehensive Automated Test Suite.
Validates Heuristics, Shannon Entropy, Brand Impersonation, C2 Webhooks,
and End-to-End Pipeline Execution.
"""

import pytest
from safescan import (
    SafeScanPipeline,
    HeuristicAnalyzer,
    BehavioralAuditor,
    WebsiteScraper,
    SafeScanConfig,
)


@pytest.fixture
def pipeline():
    return SafeScanPipeline()


def test_shannon_entropy():
    # Low entropy for structured English domain
    low_entropy = HeuristicAnalyzer.calculate_shannon_entropy("google.com")
    # High entropy for randomized DGA domain
    high_entropy = HeuristicAnalyzer.calculate_shannon_entropy("xn--80ak6aa92e718bkc.ru")
    assert high_entropy > low_entropy
    assert low_entropy < 3.5


def test_lexical_feature_extraction():
    analyzer = HeuristicAnalyzer()
    features = analyzer.extract_lexical_features("http://192.168.1.100/login")
    assert features["has_ip_host"] is True
    assert features["is_https"] is False

    punycode_features = analyzer.extract_lexical_features("https://xn--apple-43a.com")
    assert punycode_features["has_punycode"] is True


def test_crypto_seed_phrase_detection(pipeline):
    fake_scam_html = """
    <html>
        <head><title>MetaMask Sync Wallet</title></head>
        <body>
            <h1>Restore Your Web3 Wallet</h1>
            <p>Please enter your 12-word secret recovery seed phrase to claim your free airdrop token reward.</p>
            <form action="/steal">
                <input type="text" name="seed_phrase" placeholder="Enter 12 or 24 mnemonic words" />
                <button type="submit">Verify & Claim Airdrop</button>
            </form>
        </body>
    </html>
    """
    report = pipeline.scan_simulation(
        url="http://metamvsk-airdrop-claim.pw/sync",
        html=fake_scam_html,
        page_title="MetaMask Sync Wallet",
    )
    assert report.verdict == "MALICIOUS"
    assert report.risk_score >= 6.5
    assert any("seed" in ind.lower() or "phrase" in ind.lower() for ind in report.key_indicators)
    assert any("brand" in ind.lower() or "metamask" in ind.lower() for ind in report.key_indicators)


def test_banking_brand_impersonation(pipeline):
    paypal_phish_html = """
    <html>
        <head><title>PayPal Account Verification</title></head>
        <body>
            <h1>Immediate Action Required</h1>
            <p>Your PayPal account has been suspended due to unusual activity detected.</p>
            <form action="/login">
                <input type="text" name="email" placeholder="PayPal Email" />
                <input type="password" name="password" placeholder="Password" />
                <input type="text" name="ssn" placeholder="Social Security Number" />
                <button type="submit">Confirm Credentials</button>
            </form>
        </body>
    </html>
    """
    report = pipeline.scan_simulation(
        url="http://paypal-security-update.pw/verify",
        html=paypal_phish_html,
        page_title="PayPal Account Verification",
    )
    assert report.verdict == "MALICIOUS"
    assert "PayPal" in report.threat_category or any("brand" in ind.lower() for ind in report.key_indicators)


def test_discord_webhook_c2_exfiltration(pipeline):
    stealer_html = """
    <html>
        <body>
            <h1>Claim Free Nitro</h1>
            <script>
                const webhook = "https://discord.com/api/webhooks/1234567890/AbCdEfGhIjKlMnOpQrStUvWxYz";
                eval(atob("YWxlcnQoJ2hhY2tlZCcpOw=="));
            </script>
        </body>
    </html>
    """
    report = pipeline.scan_simulation(
        url="http://free-nitro-generator.xyz",
        html=stealer_html,
        page_title="Discord Nitro Free",
    )
    assert report.verdict in ("MALICIOUS", "SUSPICIOUS")
    assert any("discord" in ind.lower() or "webhook" in ind.lower() for ind in report.key_indicators)


def test_benign_website(pipeline):
    benign_html = """
    <!DOCTYPE html>
    <html>
        <head><title>Python Software Foundation</title></head>
        <body>
            <h1>Welcome to Python.org</h1>
            <p>The mission of the Python Software Foundation is to promote, protect, and advance the Python programming language.</p>
            <a href="https://docs.python.org">Documentation</a>
            <a href="https://pypi.org">PyPI Packages</a>
        </body>
    </html>
    """
    report = pipeline.scan_simulation(
        url="https://python.org",
        html=benign_html,
        page_title="Python Software Foundation",
    )
    assert report.verdict == "SAFE"
    assert report.risk_score < 3.5
