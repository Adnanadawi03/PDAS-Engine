const API_BASE = "http://127.0.0.1:8000";

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return; // نتأكد انه تبويب رئيسي
  const url = details.url;

  fetch(`${API_BASE}/scan/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  })
    .then((r) => r.json())
    .then((data) => {
      if (data.verdict === "block") {
        chrome.tabs.update(details.tabId, {
          url: chrome.runtime.getURL("blocked.html") + "?url=" + encodeURIComponent(url)
        });
      }
    })
    .catch((err) => console.error("[PDAS][ERR]", err));
}, { url: [{ schemes: ["http", "https"] }] });

chrome.downloads.onCreated.addListener((item) => {
  fetch(`${API_BASE}/scan/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: item.url })
  })
    .then((r) => r.json())
    .then((data) => {
      if (data.verdict === "block") {
        chrome.downloads.cancel(item.id);
        chrome.notifications.create({
          type: "basic",
          iconUrl: "icon.png",
          title: "PDAS Web Guard",
          message: "تم حظر تنزيل مشبوه!"
        });
      }
    });
});
