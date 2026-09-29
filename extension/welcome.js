// Welcome page: ask for notification permission first (the browser only allows this after a click).
const $ = s => document.querySelector(s);
const PERM = { permissions: ["notifications"] };

function showState(granted, denied = false) {
  $("#allowBtn").hidden = granted;
  $("#testBtn").hidden = !granted;
  $("#permMsg").innerHTML = granted
    ? "✅ <b>Notifications are on.</b> You'll be warned on screen about insecure or risky pages."
    : denied ? "Notifications stay off. You can switch them on later in the SAYNO popup." : "";
  $("#permCard").classList.toggle("perm", !granted);
}

chrome.permissions.contains(PERM, granted => showState(granted));

$("#allowBtn").onclick = () => {
  // Must be called directly in the click handler (a user gesture).
  chrome.permissions.request(PERM, granted => {
    chrome.storage.local.set({ notifyInsecure: granted });
    showState(granted, !granted);
  });
};

$("#testBtn").onclick = () => chrome.runtime.sendMessage({ type: "testNotification" }, ok => {
  if (!ok) $("#permMsg").textContent = "Couldn't show a notification. Check that notifications for your browser are allowed in Windows Settings → System → Notifications.";
});
