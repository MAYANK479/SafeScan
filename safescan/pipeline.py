"""
SafeScan Master Pipeline Orchestrator.
Coordinates the end-to-end multi-agent pipeline:
Scraper Agent -> Heuristic Screener -> Behavioral Auditor -> LLM Reasoning Agent.
Generates comprehensive ThreatReport with visual terminal reporting and JSON export.
"""

import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

from .config import SafeScanConfig, default_config
from .scraper import WebsiteScraper, ScrapeResult
from .heuristics import HeuristicAnalyzer, HeuristicReport
from .behavioral import BehavioralAuditor, BehavioralReport
from .llm_agent import GeminiReasoningAgent, LLMAnalysisResult


@dataclass
class ThreatReport:
    url: str
    verdict: str  # "SAFE" | "SUSPICIOUS" | "MALICIOUS"
    risk_score: float  # 0.0 to 10.0
    confidence_score: float  # 0.0 to 1.0
    threat_category: str
    summary: str
    key_indicators: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    technical_telemetry: Dict[str, Any] = field(default_factory=dict)
    scan_duration_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "verdict": self.verdict,
            "risk_score": round(self.risk_score, 2),
            "confidence_score": round(self.confidence_score, 2),
            "threat_category": self.threat_category,
            "summary": self.summary,
            "key_indicators": self.key_indicators,
            "recommendations": self.recommendations,
            "technical_telemetry": self.technical_telemetry,
            "scan_duration_ms": self.scan_duration_ms,
            "timestamp": self.timestamp,
        }

    def print_terminal_card(self):
        """Prints a high-impact, formatted visual security card in terminal / notebook."""
        # ANSI Color codes
        RED = "\033[91m"
        YELLOW = "\033[93m"
        GREEN = "\033[92m"
        CYAN = "\033[96m"
        BOLD = "\033[1m"
        RESET = "\033[0m"

        if self.verdict == "MALICIOUS":
            color = RED
            badge = "🚨 MALICIOUS THREAT DETECTED"
        elif self.verdict == "SUSPICIOUS":
            color = YELLOW
            badge = "⚠️ SUSPICIOUS - PROCEED WITH CAUTION"
        else:
            color = GREEN
            badge = "🛡️ BENIGN - SITE APPEARS SAFE"

        # Build risk gauge bar
        gauge_blocks = int(self.risk_score)
        gauge_bar = "█" * gauge_blocks + "░" * (10 - gauge_blocks)

        border = "=" * 70
        print(f"\n{color}{BOLD}{border}{RESET}")
        print(f"{color}{BOLD}   SafeScan AI Threat Assessment: {badge}{RESET}")
        print(f"{color}{BOLD}{border}{RESET}")
        print(f"{BOLD}Target URL:{RESET}       {self.url}")
        print(f"{BOLD}Threat Category:{RESET}  {color}{self.threat_category}{RESET}")
        print(f"{BOLD}Risk Score:{RESET}       {color}{self.risk_score}/10  [{gauge_bar}]{RESET}")
        print(f"{BOLD}Confidence:{RESET}       {int(self.confidence_score * 100)}%")
        print(f"{BOLD}Scan Latency:{RESET}     {self.scan_duration_ms} ms")
        print(f"\n{CYAN}{BOLD}--- EXECUTIVE SUMMARY ---{RESET}")
        print(f"{self.summary}")

        if self.key_indicators:
            print(f"\n{CYAN}{BOLD}--- DETECTED THREAT INDICATORS ({len(self.key_indicators)}) ---{RESET}")
            for idx, reason in enumerate(self.key_indicators, 1):
                print(f" {idx}. {color}•{RESET} {reason}")

        if self.recommendations:
            print(f"\n{CYAN}{BOLD}--- ACTIONABLE RECOMMENDATIONS ---{RESET}")
            for idx, rec in enumerate(self.recommendations, 1):
                print(f" {idx}. 👉 {rec}")

        print(f"{color}{BOLD}{border}{RESET}\n")


class SafeScanPipeline:
    """
    Main Multi-Agent Threat Detection Pipeline.
    """

    def __init__(self, config: SafeScanConfig = default_config):
        self.config = config
        self.scraper = WebsiteScraper(config)
        self.heuristics = HeuristicAnalyzer(config)
        self.behavioral = BehavioralAuditor(config)
        self.llm_agent = GeminiReasoningAgent(config)

    def scan(self, url: str) -> ThreatReport:
        """
        Executes end-to-end multi-agent scan on target URL.
        """
        start_time = time.time()

        # Step 1: Scraper Agent
        scrape_result = self.scraper.scrape(url)

        # Step 2: Heuristic Screener Agent
        heuristic_report = self.heuristics.analyze(scrape_result)

        # Step 3: Deep Behavioral DOM Auditor
        behavioral_report = self.behavioral.audit(scrape_result)

        # Step 4: LLM Threat Reasoning Agent
        llm_result = self.llm_agent.analyze(scrape_result, heuristic_report, behavioral_report)

        # Compute overall risk score (weighted combination)
        composite_score = min(
            round(
                (heuristic_report.risk_score * 0.40)
                + (behavioral_report.behavioral_score * 0.40)
                + ((10.0 if llm_result.verdict == "MALICIOUS" else 5.0 if llm_result.verdict == "SUSPICIOUS" else 0.0) * 0.20),
                2,
            ),
            10.0,
        )

        # Consolidate indicators
        all_indicators = list(dict.fromkeys(heuristic_report.reasons + behavioral_report.reasons + llm_result.key_findings))

        # Map to display verdict
        if llm_result.verdict == "MALICIOUS" or composite_score >= self.config.MALICIOUS_THRESHOLD:
            final_verdict = "MALICIOUS"
        elif llm_result.verdict == "SUSPICIOUS" or composite_score >= self.config.SUSPICIOUS_THRESHOLD:
            final_verdict = "SUSPICIOUS"
        else:
            final_verdict = "SAFE"

        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        return ThreatReport(
            url=url,
            verdict=final_verdict,
            risk_score=composite_score,
            confidence_score=llm_result.confidence_score,
            threat_category=llm_result.threat_category,
            summary=llm_result.human_summary,
            key_indicators=all_indicators,
            recommendations=llm_result.actionable_recommendations,
            technical_telemetry={
                "scraper": scrape_result.to_dict(),
                "heuristics": heuristic_report.to_dict(),
                "behavioral": behavioral_report.to_dict(),
                "llm": llm_result.to_dict(),
            },
            scan_duration_ms=elapsed_ms,
        )

    def scan_simulation(self, url: str, html: str, page_title: str = "") -> ThreatReport:
        """
        Executes scan using provided HTML payload (for automated benchmarks and simulations).
        """
        start_time = time.time()
        mock_scrape = WebsiteScraper.create_mock_result(url=url, html=html, page_title=page_title)
        heuristic_report = self.heuristics.analyze(mock_scrape)
        behavioral_report = self.behavioral.audit(mock_scrape)
        llm_result = self.llm_agent.analyze(mock_scrape, heuristic_report, behavioral_report)

        composite_score = min(
            round(
                (heuristic_report.risk_score * 0.40)
                + (behavioral_report.behavioral_score * 0.40)
                + ((10.0 if llm_result.verdict == "MALICIOUS" else 5.0 if llm_result.verdict == "SUSPICIOUS" else 0.0) * 0.20),
                2,
            ),
            10.0,
        )

        all_indicators = list(dict.fromkeys(heuristic_report.reasons + behavioral_report.reasons + llm_result.key_findings))

        if llm_result.verdict == "MALICIOUS" or composite_score >= self.config.MALICIOUS_THRESHOLD:
            final_verdict = "MALICIOUS"
        elif llm_result.verdict == "SUSPICIOUS" or composite_score >= self.config.SUSPICIOUS_THRESHOLD:
            final_verdict = "SUSPICIOUS"
        else:
            final_verdict = "SAFE"

        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        return ThreatReport(
            url=url,
            verdict=final_verdict,
            risk_score=composite_score,
            confidence_score=llm_result.confidence_score,
            threat_category=llm_result.threat_category,
            summary=llm_result.human_summary,
            key_indicators=all_indicators,
            recommendations=llm_result.actionable_recommendations,
            technical_telemetry={
                "scraper": mock_scrape.to_dict(),
                "heuristics": heuristic_report.to_dict(),
                "behavioral": behavioral_report.to_dict(),
                "llm": llm_result.to_dict(),
            },
            scan_duration_ms=elapsed_ms,
        )
