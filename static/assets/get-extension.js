// The Chrome Web Store address of SAYNO. Paste it between the quotes once Google approves the listing,
// for example "https://chromewebstore.google.com/detail/sayno-card-guard/abcdefghijklmnopabcdefghijklmnop".
// While it is empty the page says the listing is under review and offers the manual install instead.
const STORE_URL = "";

(() => {
  const store = document.getElementById("store-cta");
  const manual = document.querySelectorAll("[data-manual]");
  const status = document.getElementById("store-status");
  if (STORE_URL) {
    store.href = STORE_URL;
    store.target = "_blank";
    store.rel = "noopener";
    store.textContent = "Add to Chrome";
    store.removeAttribute("aria-disabled");
    manual.forEach(el => { el.hidden = true; });
    status.textContent = "Free. Works in Chrome and Edge.";
  } else {
    store.setAttribute("aria-disabled", "true");
    store.addEventListener("click", e => e.preventDefault());
    store.textContent = "Chrome Web Store: under review";
    status.textContent = "Our Chrome Web Store listing is waiting for Google's approval. Until then, use the manual install below.";
  }
})();
