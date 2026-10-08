/**
 * SafeScan AI In-Page Content Script
 * Analyzes active DOM for phishing cues and displays a high-visibility security banner if malicious.
 */

(function() {
  const currentUrl = window.location.href.toLowerCase();
  
  // Fast in-page signature inspection
  const badPatterns = [
    /seed phrase/i,
    /recovery phrase/i,
    /mnemonic/i,
    /private key/i,
    /connect your wallet to claim/i,
    /urgent action required.*suspended/i
  ];

  const bodyText = (document.body ? document.body.innerText : "") + " " + document.title;
  let matches = [];

  for (const pat of badPatterns) {
    if (pat.test(bodyText)) {
      matches.push(pat.source);
    }
  }

  const isBadTld = [".pw", ".ru", ".top", ".xyz"].some(t => currentUrl.includes(t));
  const isSuspicious = matches.length > 0 && (isBadTld || currentUrl.includes("claim") || currentUrl.includes("airdrop"));

  if (isSuspicious) {
    injectSafeScanBanner(matches);
  }

  function injectSafeScanBanner(threats) {
    if (document.getElementById('safescan-inpage-banner')) return;

    const banner = document.createElement('div');
    banner.id = 'safescan-inpage-banner';
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 2147483647;
      background: linear-gradient(90deg, #b91c1c, #dc2626);
      color: #ffffff;
      padding: 12px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: 0 4px 20px rgba(0,0,0,0.5);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 14px;
      font-weight: 600;
    `;

    banner.innerHTML = `
      <div style="display: flex; align-items: center; gap: 10px;">
        <span style="font-size: 20px;">🚨</span>
        <span>
          <strong>SafeScan AI Threat Warning:</strong> This website was flagged as a potential phishing or crypto scam attack! Do not input recovery seed phrases or passwords.
        </span>
      </div>
      <div style="display: flex; align-items: center; gap: 10px;">
        <a href="https://safescan-lac.vercel.app" target="_blank" style="background: rgba(0,0,0,0.3); color: #fff; padding: 6px 12px; border-radius: 6px; text-decoration: none; font-size: 12px;">Inspect Details</a>
        <button id="safescan-dismiss-btn" style="background: transparent; border: none; color: #fff; font-size: 18px; cursor: pointer; padding: 0 5px;">✕</button>
      </div>
    `;

    document.documentElement.prepend(banner);

    document.getElementById('safescan-dismiss-btn').addEventListener('click', () => {
      banner.remove();
    });
  }
})();
