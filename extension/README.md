# 🛡️ SafeScan AI — Browser Extension (Chrome, Edge, Brave, Arc)

The **SafeScan AI Browser Extension** provides real-time, in-browser protection against malicious websites, cryptocurrency wallet drainers, and zero-day phishing attacks on **both macOS and Windows**.

---

## 🚀 How to Install in 30 Seconds (Mac & Windows)

### Google Chrome / Brave / Arc
1. Open your browser and navigate to:
   ```text
   chrome://extensions
   ```
2. Enable **"Developer mode"** (toggle in the top-right corner).
3. Click the **"Load unpacked"** button in the top-left corner.
4. Select the `extension/` folder in this project:
   ```text
   /Users/mayankpandey/Downloads/Projects/untitled folder/extension
   ```
5. SafeScan AI is now installed! Pin it to your browser toolbar.

### Microsoft Edge
1. Navigate to:
   ```text
   edge://extensions
   ```
2. Turn on the **"Developer mode"** toggle in the left sidebar.
3. Click **"Load unpacked"** and select the `extension/` directory.

---

## 🎯 How It Works

1. **Toolbar Quick-Inspection**: Click the SafeScan shield icon in your browser toolbar to instantly view:
   - Live **Threat Verdict** (`SAFE`, `SUSPICIOUS`, `MALICIOUS`).
   - Risk score gauge (`0.0 to 10.0`).
   - Threat category (e.g., *Cryptocurrency Wallet Drainer*, *Credential Harvester*).
   - Detected indicators (Punycode spoofs, suspicious TLDs, seed harvesting prompts).
2. **In-Page Interception Banner**: If you navigate to a high-risk phishing or wallet drainer site, SafeScan injects an immediate high-visibility crimson security banner warning you not to enter credentials or seed phrases.
3. **Dual Engine Synchronization**:
   - When the local SafeScan backend is active (`http://localhost:8080`), the extension communicates directly with the Python multi-agent pipeline.
   - When offline, it executes client-side heuristic screening, ensuring non-stop protection.
