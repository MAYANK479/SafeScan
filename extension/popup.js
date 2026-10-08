/**
 * SafeScan AI Extension Popup Controller
 * Connects to active tab and queries SafeScan threat intelligence backend.
 */

document.addEventListener('DOMContentLoaded', async () => {
  const domainEl = document.getElementById('target-domain');
  const urlEl = document.getElementById('target-url');
  const rescanBtn = document.getElementById('rescan-btn');

  // Query active browser tab
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      inspectTabUrl(tab.url);
    } else {
      domainEl.textContent = "No Active Web Page";
    }
  } catch (e) {
    // Fallback if running outside full extension context (e.g. preview)
    inspectTabUrl(window.location.href);
  }

  rescanBtn.addEventListener('click', async () => {
    rescanBtn.innerHTML = `<span>⏳</span><span>Scanning...</span>`;
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url) {
        await inspectTabUrl(tab.url);
      }
    } finally {
      rescanBtn.innerHTML = `<span>🔄</span><span>Re-Scan Page</span>`;
    }
  });
});

async function inspectTabUrl(rawUrl) {
  const domainEl = document.getElementById('target-domain');
  const urlEl = document.getElementById('target-url');

  try {
    const parsed = new URL(rawUrl);
    domainEl.textContent = parsed.hostname || rawUrl;
    urlEl.textContent = rawUrl;
  } catch (e) {
    domainEl.textContent = rawUrl;
    urlEl.textContent = rawUrl;
  }

  // Attempt live scan against local SafeScan backend, fallback to cloud, then client heuristics
  const endpoints = [
    'http://127.0.0.1:8080/api/v1/scan',
    'https://safescan-lac.vercel.app/api/v1/scan'
  ];

  for (const ep of endpoints) {
    try {
      const response = await fetch(ep, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: rawUrl }),
        signal: AbortSignal.timeout(2800)
      });

      if (response.ok) {
        const report = await response.json();
        renderPopupVerdict(report);
        return;
      }
    } catch (err) {
      // Try next endpoint
    }
  }

  // Client-Side Fast Heuristic Fallback Engine
  const fallbackReport = clientHeuristicScan(rawUrl);
  renderPopupVerdict(fallbackReport);
}

function clientHeuristicScan(url) {
  let score = 0.5;
  let verdict = "SAFE";
  let category = "Legitimate Website";
  const reasons = [];

  const lower = url.toLowerCase();
  const badTlds = [".ru", ".cn", ".tk", ".pw", ".top", ".xyz", ".cc"];

  if (badTlds.some(t => lower.includes(t))) {
    score += 3.5;
    reasons.push("Suspicious Top-Level Domain (TLD) linked with phishing campaigns");
  }
  if (lower.includes("xn--") || lower.includes("--")) {
    score += 3.0;
    reasons.push("Punycode / Homograph domain spoofs detected");
  }
  if (lower.includes("metamvsk") || lower.includes("airdrop") || lower.includes("claim-wallet")) {
    score += 4.5;
    category = "Cryptocurrency Wallet Drainer";
    reasons.push("Crypto seed harvest or wallet drainer pattern");
  }
  if (lower.includes("paypal-security") || lower.includes("verify-account")) {
    score += 4.0;
    category = "Credential Phishing (Banking)";
    reasons.push("Banking impersonation credential lure");
  }

  if (score >= 6.0) verdict = "MALICIOUS";
  else if (score >= 3.0) verdict = "SUSPICIOUS";

  return {
    url: url,
    verdict: verdict,
    risk_score: Math.min(score, 10.0),
    threat_category: category,
    summary: verdict === "MALICIOUS" 
      ? "CRITICAL: Threat markers identified. Exercise extreme caution and do not input passwords or seed phrases."
      : "Website passed primary lexical security screening.",
    key_indicators: reasons
  };
}

function renderPopupVerdict(report) {
  const card = document.getElementById('verdict-card');
  const badge = document.getElementById('verdict-badge');
  const cat = document.getElementById('verdict-category');
  const scoreNum = document.getElementById('risk-score-num');
  const sum = document.getElementById('verdict-summary');
  const list = document.getElementById('indicators-list');

  const v = (report.verdict || "SAFE").toUpperCase();
  const state = v === 'MALICIOUS' ? 'malicious' : v === 'SUSPICIOUS' ? 'suspicious' : 'safe';

  card.className = 'verdict-box ' + state;
  badge.className = 'v-badge ' + state;
  badge.textContent = v === 'MALICIOUS' ? '🚨 MALICIOUS' : v === 'SUSPICIOUS' ? '⚠️ SUSPICIOUS' : '🛡️ SAFE';

  cat.textContent = report.threat_category || 'Assessment';
  scoreNum.textContent = (report.risk_score || 0.5).toFixed(1);
  sum.textContent = report.summary || 'Safety analysis complete.';

  list.innerHTML = '';
  const indicators = report.key_indicators || [];
  if (indicators.length === 0) {
    list.innerHTML = `
      <li class="indicator-item safe"><span>✓</span><span>No malicious indicators or threat patterns</span></li>
      <li class="indicator-item safe"><span>✓</span><span>Domain structure matches safe conventions</span></li>
    `;
  } else {
    indicators.forEach(item => {
      const li = document.createElement('li');
      li.className = 'indicator-item danger';
      li.innerHTML = `<span>⚠️</span><span>${item}</span>`;
      list.appendChild(li);
    });
  }
}
