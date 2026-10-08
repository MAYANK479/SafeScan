"""
SafeScan Configuration & Threat Intelligence Signatures.
Centralized repository of threat patterns, high-risk TLDs, monitored brand assets,
and risk scoring thresholds.
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Set


@dataclass
class SafeScanConfig:
    # Model Configuration
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", os.getenv("GOOGLE_API_KEY", ""))

    # Network Configuration
    REQUEST_TIMEOUT: int = int(os.getenv("SAFESCAN_TIMEOUT", "12"))
    MAX_CONTENT_CHARS: int = 15000  # Generous cutoff ensuring full DOM analysis
    USER_AGENT: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36 SafeScanBot/2.0"
    )

    # Risk Scoring Thresholds (0 - 10 scale)
    SUSPICIOUS_THRESHOLD: float = 3.5
    MALICIOUS_THRESHOLD: float = 6.5

    # High-Risk Top Level Domains (frequently exploited in bulletproof phishing campaigns)
    HIGH_RISK_TLDS: Set[str] = field(
        default_factory=lambda: {
            ".ru", ".cn", ".tk", ".pw", ".top", ".xyz", ".cc", ".buzz",
            ".club", ".work", ".click", ".gq", ".cf", ".ml", ".ga",
            ".icu", ".live", ".fit", ".rest", ".monster", ".sbs", ".cam"
        }
    )

    # Monitored Brands for Impersonation Detection (Domain Mismatch Hunter)
    MONITORED_BRANDS: Dict[str, List[str]] = field(
        default_factory=lambda: {
            # Web3 & Crypto
            "metamask": ["metamask.io"],
            "binance": ["binance.com", "binance.org", "binance.us"],
            "coinbase": ["coinbase.com"],
            "trustwallet": ["trustwallet.com"],
            "phantom": ["phantom.app"],
            "okx": ["okx.com"],
            "ledger": ["ledger.com"],
            "trezor": ["trezor.io"],
            "kraken": ["kraken.com"],
            "bybit": ["bybit.com"],
            "kucoin": ["kucoin.com"],
            "uniswap": ["uniswap.org"],
            "opensea": ["opensea.io"],
            "pancakeswap": ["pancakeswap.finance"],
            # Financial & Banking
            "paypal": ["paypal.com"],
            "chase": ["chase.com"],
            "bankofamerica": ["bankofamerica.com"],
            "wellsfargo": ["wellsfargo.com"],
            "citibank": ["citi.com", "citibank.com"],
            "stripe": ["stripe.com"],
            "revolut": ["revolut.com"],
            "cashapp": ["cash.app"],
            "venmo": ["venmo.com"],
            "wise": ["wise.com"],
            "americanexpress": ["americanexpress.com", "amex.com"],
            "capitalone": ["capitalone.com"],
            # Tech Giants & Cloud
            "google": ["google.com", "google.co", "accounts.google.com"],
            "microsoft": ["microsoft.com", "live.com", "office.com", "login.microsoftonline.com"],
            "apple": ["apple.com", "icloud.com", "appleid.apple.com"],
            "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com"],
            "netflix": ["netflix.com"],
            "meta": ["meta.com", "facebook.com", "instagram.com", "whatsapp.com"],
            "facebook": ["facebook.com", "fb.com"],
            "instagram": ["instagram.com"],
            "whatsapp": ["whatsapp.com", "web.whatsapp.com"],
            "twitter": ["twitter.com", "x.com"],
            "linkedin": ["linkedin.com"],
            "github": ["github.com"],
            "gitlab": ["gitlab.com"],
            "dropbox": ["dropbox.com"],
            "adobe": ["adobe.com"],
            "discord": ["discord.com", "discord.gg"],
            "telegram": ["telegram.org", "t.me"],
            "docusign": ["docusign.com", "docusign.net"],
            # Shipping & Government
            "usps": ["usps.com"],
            "fedex": ["fedex.com"],
            "dhl": ["dhl.com"],
            "ups": ["ups.com"],
            "irs": ["irs.gov"],
        }
    )

    # Bad Pattern Regex Signatures (18+ categories)
    HEURISTIC_PATTERNS: List[Dict[str, str]] = field(
        default_factory=lambda: [
            # Crypto Drainer & Seed Theft
            {"name": "seed_phrase_request", "regex": r"(?:enter|restore|backup|confirm|verify)\s+(?:your\s+)?(?:secret\s+)?(?:recovery\s+)?(?:seed\s+phrase|12[\s-]word|24[\s-]word|mnemonic)", "weight": 3.5},
            {"name": "private_key_harvest", "regex": r"(?:enter|paste|input|import)\s+(?:your\s+)?private\s+key", "weight": 3.5},
            {"name": "wallet_connection_lure", "regex": r"(?:connect|link)\s+(?:your\s+)?(?:web3\s+)?(?:crypto\s+)?(?:wallet|metamask|trust\s*wallet|phantom)\s+to\s+(?:claim|receive|verify)", "weight": 2.5},
            {"name": "crypto_airdrop_lure", "regex": r"(?:exclusive|free|instant|guaranteed)\s+(?:airdrop|token\s+claim|reward\s+pool)", "weight": 2.5},
            {"name": "crypto_doubler_scam", "regex": r"(?:double|multiply|2x)\s+(?:your\s+)?(?:money|crypto|btc|eth|sol)", "weight": 3.0},
            
            # Urgent Social Engineering & Account Lockout
            {"name": "account_suspended_urgency", "regex": r"(?:account\s+(?:suspended|restricted|compromised|locked)|unusual\s+activity\s+detected)", "weight": 2.0},
            {"name": "immediate_action_lure", "regex": r"(?:immediate\s+action\s+required|act\s+within\s+\d+\s+hours|avoid\s+permanent\s+suspension)", "weight": 2.0},
            {"name": "security_update_lure", "regex": r"(?:mandatory|critical)\s+security\s+(?:update|upgrade|verification)", "weight": 1.5},
            
            # Financial & Prize Scams
            {"name": "guaranteed_returns", "regex": r"(?:guaranteed\s+profit|100%\s+risk[\s-]free|get\s+rich\s+quick)", "weight": 2.5},
            {"name": "lottery_prize_lure", "regex": r"(?:you\s+(?:have\s+)?won|congratulations\s+winner|claim\s+your\s+\$\d+[\d,]*\s+(?:prize|gift\s+card))", "weight": 2.5},
            
            # Credential Phishing Keywords
            {"name": "credential_harvest_prompt", "regex": r"(?:confirm|verify)\s+(?:your\s+)?(?:password|pin|security\s+questions|ssn|social\s+security)", "weight": 2.5},
            {"name": "unusual_login_prompt", "regex": r"(?:session\s+expired|re[\s-]enter\s+credentials|login\s+to\s+keep\s+access)", "weight": 1.5},
        ]
    )


# Global default configuration instance
default_config = SafeScanConfig()
