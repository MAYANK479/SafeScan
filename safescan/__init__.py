"""
SafeScan: AI-Powered Malicious Website & Phishing Detection System
Autonomous multi-agent threat intelligence pipeline leveraging heuristic analysis,
behavioral DOM auditing, and Google Gemini LLM reasoning.
"""

__version__ = "2.0.0"
__author__ = "Mayank Pandey"

from .config import SafeScanConfig
from .scraper import WebsiteScraper, ScrapeResult
from .heuristics import HeuristicAnalyzer, HeuristicReport
from .behavioral import BehavioralAuditor, BehavioralReport
from .llm_agent import GeminiReasoningAgent, LLMAnalysisResult
from .pipeline import SafeScanPipeline, ThreatReport

__all__ = [
    "SafeScanConfig",
    "WebsiteScraper",
    "ScrapeResult",
    "HeuristicAnalyzer",
    "HeuristicReport",
    "BehavioralAuditor",
    "BehavioralReport",
    "GeminiReasoningAgent",
    "LLMAnalysisResult",
    "SafeScanPipeline",
    "ThreatReport",
]
