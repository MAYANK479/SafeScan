/**
 * SafeScan AI Extension Service Worker (Manifest V3)
 * Monitors tab navigation and updates toolbar icon badges.
 */

chrome.runtime.onInstalled.addListener(() => {
  console.log("SafeScan AI Extension installed and active.");
  chrome.action.setBadgeBackgroundColor({ color: "#10b981" });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    const url = tab.url.toLowerCase();
    
    // Quick heuristic alert check
    if (url.includes(".pw") || url.includes("metamvsk") || url.includes("airdrop-claim")) {
      chrome.action.setBadgeText({ tabId, text: "!" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" });
    } else {
      chrome.action.setBadgeText({ tabId, text: "" });
    }
  }
});
