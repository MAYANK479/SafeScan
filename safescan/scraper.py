"""
SafeScan Web Scraper Agent.
Resilient web content extraction engine leveraging cloudscraper for anti-bot bypass,
DNS error handling, SSL exception handling, and DOM normalization.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
import requests
import cloudscraper
from bs4 import BeautifulSoup
from .config import SafeScanConfig, default_config


@dataclass
class ScrapeResult:
    url: str
    final_url: str = ""
    status: str = "success"  # "success" | "error"
    status_code: Optional[int] = 200
    html: str = ""
    text_content: str = ""
    page_title: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    response_time_ms: float = 0.0
    error_message: Optional[str] = None
    is_simulated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "status_code": self.status_code,
            "page_title": self.page_title,
            "content_length": len(self.html),
            "text_length": len(self.text_content),
            "response_time_ms": self.response_time_ms,
            "error": self.error_message,
            "is_simulated": self.is_simulated,
        }


class WebsiteScraper:
    """
    Intelligent web scraper designed for automated threat investigation.
    Extracts HTML and text while evading basic bot mitigation barriers.
    """

    def __init__(self, config: SafeScanConfig = default_config):
        self.config = config
        self.session = cloudscraper.create_scraper(
            browser={"browser": "chrome", "platform": "windows", "desktop": True}
        )

    def scrape(self, url: str) -> ScrapeResult:
        """
        Fetches web page content securely.
        Catches network and anti-bot anomalies.
        """
        # Ensure scheme
        target_url = url.strip()
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        start_time = time.time()
        try:
            headers = {"User-Agent": self.config.USER_AGENT}
            response = self.session.get(
                target_url,
                timeout=self.config.REQUEST_TIMEOUT,
                headers=headers,
                allow_redirects=True,
            )
            elapsed_ms = round((time.time() - start_time) * 1000, 2)

            raw_html = response.text or ""
            # Truncate raw html only if exceedingly massive to preserve DOM structures
            trimmed_html = raw_html[: self.config.MAX_CONTENT_CHARS]

            # Parse DOM with BeautifulSoup
            soup = BeautifulSoup(trimmed_html, "html.parser")
            
            # Remove scripts and styles for pure text analysis
            for element in soup(["script", "style", "noscript"]):
                element.extract()
            
            page_title = soup.title.string.strip() if (soup.title and soup.title.string) else ""
            clean_text = " ".join(soup.get_text(separator=" ").split())

            return ScrapeResult(
                url=url,
                final_url=response.url,
                status="success",
                status_code=response.status_code,
                html=trimmed_html,
                text_content=clean_text,
                page_title=page_title,
                headers=dict(response.headers),
                response_time_ms=elapsed_ms,
            )

        except cloudscraper.exceptions.CloudflareChallengeError as cf_err:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            return ScrapeResult(
                url=url,
                status="error",
                status_code=403,
                error_message=f"Cloudflare bot protection challenged request: {str(cf_err)[:120]}",
                response_time_ms=elapsed_ms,
            )
        except requests.exceptions.SSLError as ssl_err:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            return ScrapeResult(
                url=url,
                status="error",
                status_code=495,
                error_message=f"SSL certificate validation failed: {str(ssl_err)[:120]}",
                response_time_ms=elapsed_ms,
            )
        except requests.exceptions.ConnectionError:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            return ScrapeResult(
                url=url,
                status="error",
                status_code=502,
                error_message="Domain resolution or connection failed (host unreachable or NXDOMAIN).",
                response_time_ms=elapsed_ms,
            )
        except requests.exceptions.Timeout:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            return ScrapeResult(
                url=url,
                status="error",
                status_code=504,
                error_message=f"Connection timed out after {self.config.REQUEST_TIMEOUT}s.",
                response_time_ms=elapsed_ms,
            )
        except Exception as exc:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            return ScrapeResult(
                url=url,
                status="error",
                status_code=500,
                error_message=f"Scraper error: {str(exc)[:120]}",
                response_time_ms=elapsed_ms,
            )

    @classmethod
    def create_mock_result(
        cls, url: str, html: str, page_title: str = "", status_code: int = 200
    ) -> ScrapeResult:
        """Helper to create simulated scrape results for testing and offline demos."""
        soup = BeautifulSoup(html, "html.parser")
        for element in soup(["script", "style", "noscript"]):
            element.extract()
        clean_text = " ".join(soup.get_text(separator=" ").split())
        title = page_title or (soup.title.string.strip() if soup.title and soup.title.string else "Untitled")
        
        return ScrapeResult(
            url=url,
            final_url=url,
            status="success",
            status_code=status_code,
            html=html,
            text_content=clean_text,
            page_title=title,
            response_time_ms=12.5,
            is_simulated=True,
        )
