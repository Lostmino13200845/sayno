// A small, honest search: it looks through the page names and keywords below. Nothing is sent anywhere.
(() => {
  const base = window.SY.base;
  const PAGES = [
    ["How SAYNO works", "/how-it-works/", "how works steps check understand act layer", true],
    ["Card Guard", "/card-guard/", "card guard block warning cvv pin sensitive", true],
    ["Privacy", "/privacy/", "privacy data stored upload permissions policy collect", true],
    ["Message Check", "/message-check/", "message sms text email scam paste check", true],
    ["Website Check", "/website-check/", "website link url address phishing check", true],
    ["FAQ", "/help/", "faq help questions safe high risk blocked store", true],
    ["Security", "/security/", "security detection threat lists reporting open source", false],
    ["Protect yourself", "/protect/", "protect checklist password breach passkey 2fa", false],
    ["Get the extension", "/get-extension/", "install extension download chrome edge add browser", false],
    ["Take the 60-second tour", "/tutorial/", "tour tutorial practice demo learn", false],
    ["Report a scam", "/report-scam/", "report scam phishing fraud block list send template email text call", true],
    ["Report a problem", "/report/", "report problem bug contact feedback", false],
    ["About SAYNO", "/about/", "about stormhacks team problem approach", false],
    ["Accessibility", "/accessibility/", "accessibility keyboard screen reader contrast", false],
    ["Terms", "/terms/", "terms legal conditions", false],
  ];
  const list = document.getElementById("results"), none = document.getElementById("none"), q = document.getElementById("q"), head = document.getElementById("pop-h");
  const esc = s => s.replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  function render() {
    const term = q.value.trim().toLowerCase();
    const hits = term ? PAGES.filter(p => (p[0] + " " + p[2]).toLowerCase().includes(term)) : PAGES.filter(p => p[3]);
    head.textContent = term ? (hits.length ? "Results" : "No results") : "Popular searches";
    none.hidden = !(term && !hits.length);
    list.innerHTML = hits.map((p, i) => `<li><a class="result-row" href="${base}${p[1]}"${i ? "" : ""}>${esc(p[0])} <span aria-hidden="true">&rarr;</span></a></li>`).join("");
  }
  q.addEventListener("input", render);
  document.getElementById("search-form").addEventListener("submit", e => { e.preventDefault(); const first = list.querySelector("a"); if (first && q.value.trim()) location.href = first.href; });
  const initial = new URLSearchParams(location.search).get("q"); if (initial) q.value = initial;
  render();
})();
