// Scam Shield – Card Guard (content script)
// Detects pages that ask for card details and decides, locally, whether that is dangerous.
// Card numbers typed by the user NEVER leave the page: only a yes/no signal is used.
(() => {
  const host = location.hostname;
  let settings = { enabled: true, newcomerMode: true, myBanks: [] };
  let verdict = null;          // server verdict for this URL
  let dismissed = false;       // user chose "continue anyway" on this page
  let shown = null;            // "block" | "toast" | null

  const FIELD_RX = {
    number: /(card.?(no|num)|cc.?(no|num)|credit.?card|debit.?card|cardnumber|pan\b|numero.?de.?carte)/i,
    cvv:    /(cvv|cvc|csc|cid\b|security.?code|card.?code|verification.?(value|code))/i,
    expiry: /(expir|exp.?(date|month|year|mm|yy)|valid.?(thru|until)|mm.?\/?.?yy)/i,
    pin:    /(\bpin\b|pin.?(code|number)|atm.?pin|debit.?pin|card.?pin)/i,
    sin:    /(\bsin\b|social.?insurance|ssn\b|social.?security)/i,
  };
  const AUTOCOMPLETE = { "cc-number": "number", "cc-csc": "cvv", "cc-exp": "expiry", "cc-exp-month": "expiry", "cc-exp-year": "expiry" };

  function describe(el) {
    const label = el.id ? document.querySelector(`label[for="${CSS.escape(el.id)}"]`)?.textContent : "";
    return [el.name, el.id, el.placeholder, el.getAttribute("aria-label"), el.closest("label")?.textContent, label]
      .filter(Boolean).join(" ");
  }

  function findFields() {
    const found = {};
    for (const el of document.querySelectorAll("input, select")) {
      if (el.type === "hidden" || el.offsetParent === null) continue;
      const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
      if (AUTOCOMPLETE[ac]) { found[AUTOCOMPLETE[ac]] = true; continue; }
      const d = describe(el);
      for (const [kind, rx] of Object.entries(FIELD_RX)) if (rx.test(d)) found[kind] = true;
    }
    return found;
  }

  const allBankDomains = () => Object.values(SS_BANKS).flatMap(b => b.domains);
  function trustedHost() {
    const mine = settings.myBanks.flatMap(k => SS_BANKS[k]?.domains || []);
    return ssHostMatches(host, [...mine, ...allBankDomains(), ...SS_PAYMENT_PROCESSORS]);
  }

  function luhn(num) {
    const d = num.replace(/\D/g, "");
    if (d.length < 13 || d.length > 19) return false;
    let sum = 0;
    for (let i = 0; i < d.length; i++) {
      let n = +d[d.length - 1 - i];
      if (i % 2) { n *= 2; if (n > 9) n -= 9; }
      sum += n;
    }
    return sum % 10 === 0;
  }

  // ---- decide how risky this page is
  function evaluate(typedCard = false) {
    if (!settings.enabled || dismissed || trustedHost()) return;
    const f = findFields();
    const asksCard = f.number || f.cvv || f.pin || typedCard;
    if (!asksCard) return;

    const text = (document.title + " " + (document.body?.innerText || "")).slice(0, 20000);
    const posesAsBank = SS_BANK_WORDS.test(text);
    const pressure = SS_PRESSURE_WORDS.test(text);
    const serverRisk = verdict && ["medium", "high", "critical"].includes(verdict.level);
    const reasons = [];

    if (f.pin) reasons.push("It asks for your card <b>PIN</b>. No bank or shop ever asks for your PIN on a website.");
    if (f.sin) reasons.push("It asks for your <b>Social Insurance Number</b> together with card details.");
    if (posesAsBank && pressure) reasons.push("It uses <b>bank-style pressure</b> (\"suspended\", \"verify your card\", \"pending e-Transfer\") but this is <b>not your bank's website</b>.");
    if (serverRisk) reasons.push(`Scam Shield rates this site <b>${verdict.level.toUpperCase()}</b> (${verdict.score}/100).`);
    const local = ["127.0.0.1", "localhost"].includes(host);
    if (location.protocol === "http:" && !local) reasons.push("The connection is <b>not encrypted</b> (http://). Card details could be stolen in transit.");
    if (f.number && f.cvv && f.expiry && posesAsBank && !pressure && settings.newcomerMode)
      reasons.push("It collects your full card number, expiry and CVV while talking about banking, on a site that is not a bank.");

    if (reasons.length) {
      block(reasons);
      chrome.runtime.sendMessage({ type: "cardGuard", reason: "Page asks for card details: " +
        reasons.map(r => r.replace(/<[^>]+>/g, "")).join(" ") });
    } else if (settings.newcomerMode && typedCard && !shown) {
      toast("You're entering a card number on <b>" + host + "</b>. Make sure you opened this site yourself, not from a message or e-mail link.");
    }
  }

  // ---- UI (closed shadow DOM so the page can't restyle or hide it).
  // Styles come from ui/tokens.css + ui/components.css + ui/overlay.css (the design system).
  const STYLES = ["ui/tokens.css", "ui/components.css", "ui/overlay.css"];
  let cssText = null;
  async function loadCss() {
    if (cssText !== null) return cssText;
    const parts = await Promise.all(STYLES.map(p => fetch(chrome.runtime.getURL(p)).then(r => r.text()).catch(() => "")));
    // Tokens are declared on :root; inside a shadow root the equivalent is :host.
    return (cssText = parts.join("\n").replace(/:root/g, ":host"));
  }
  function mount() {
    const hostEl = document.createElement("scam-shield-ui");
    hostEl.style.cssText = "all:initial;position:fixed;inset:0;z-index:2147483647;pointer-events:none";
    const root = hostEl.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    const c = document.createElement("div");
    c.hidden = true;  // shown once styles are in, so there is no unstyled flash
    root.append(style, c);
    loadCss().then(css => { style.textContent = css; c.hidden = false; });
    document.documentElement.appendChild(hostEl);
    return c;
  }
  let container = null;
  const ui = () => (container ||= mount());
  const esc = s => String(s).replace(/[&<>"]/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[ch]));

  function block(reasons) {
    if (shown === "block") return;
    shown = "block";
    document.activeElement?.blur?.();
    ui().innerHTML = `<div class="ov-veil" role="alertdialog" aria-labelledby="ov-title"><div class="ov-box">
      <h1 id="ov-title">🛡️ Stop: this page wants your card details</h1>
      <p>Scam Shield blocked this page on <b>${esc(host)}</b> because:</p>
      <ul>${reasons.map(r => `<li>${r}</li>`).join("")}</ul>
      <p class="ov-tip"><b>Your bank will never</b> ask for your full card number, CVV, PIN or one-time code by message or on a page you reached from a link. If you're unsure, call the number on the back of your card.</p>
      <div class="ov-actions"><button class="ss-btn ss-btn--danger" id="leave">Get me out of here</button>
      <button class="ss-btn ss-btn--link" id="stay">I understand the risk, continue</button></div></div></div>`;
    ui().querySelector("#leave").onclick = () => { history.length > 1 ? history.back() : location.replace("about:blank"); };
    ui().querySelector("#stay").onclick = () => { dismissed = true; shown = null; ui().innerHTML = ""; };
    setTimeout(() => ui().querySelector("#leave")?.focus(), 50);
  }

  function toast(html) {
    shown = "toast";
    ui().innerHTML = `<div class="ov-toast" role="status">🛡️ ${html}<div style="margin-top:8px"><button class="ss-btn ss-btn--ghost ss-btn--s" id="ok">Got it</button></div></div>`;
    ui().querySelector("#ok").onclick = () => { ui().innerHTML = ""; };
  }

  function showScan({ result, error }) {
    const body = error ? `<p>${esc(error)}</p>` : `
      <span class="ss-level ss-level--${result.level}">${result.level} · ${result.score}/100</span>
      <ul class="ss-findings">${[...result.text.findings, ...result.urls.flatMap(u => u.findings), ...result.emails.flatMap(e => e.findings)]
        .filter(f => f.weight).slice(0, 6).map(f => `<li class="${f.severity === "danger" ? "is-danger" : ""}">${esc(f.message)}</li>`).join("")
        || '<li class="is-ok">No warning signs found.</li>'}</ul>
      <p class="ss-muted">${esc(result.advice[0] || "")}</p>
      ${result.reported ? `<p><b>🚩 ${result.reported} dangerous link(s) reported automatically.</b></p>` : ""}`;
    ui().innerHTML = `<div class="ov-panel" role="dialog" aria-label="Scam Shield result"><div class="ov-panel-head"><b>🛡️ Scam Shield</b>
      <button class="ov-close" id="x" aria-label="Close">×</button></div>${body}</div>`;
    ui().querySelector("#x").onclick = () => { ui().innerHTML = ""; };
  }

  // ---- wiring
  chrome.runtime.onMessage.addListener(msg => {
    if (msg.type === "verdict") { verdict = msg.result; evaluate(); }
    if (msg.type === "scanResult") showScan(msg);
  });

  // Focus on a password / card field on an unencrypted (http) page -> on-screen notification.
  const isLocal = ["127.0.0.1", "localhost"].includes(host);
  document.addEventListener("focusin", e => {
    const el = e.target;
    if (location.protocol !== "http:" || isLocal || !settings.enabled || !(el instanceof HTMLInputElement)) return;
    const d = describe(el), ac = (el.getAttribute("autocomplete") || "").toLowerCase();
    const what = el.type === "password" ? "password"
      : ac.startsWith("cc-") || FIELD_RX.number.test(d) || FIELD_RX.cvv.test(d) ? "card details"
      : FIELD_RX.pin.test(d) ? "PIN" : FIELD_RX.sin.test(d) ? "Social Insurance Number" : null;
    if (what) chrome.runtime.sendMessage({ type: "insecureField", what });
  }, true);

  document.addEventListener("input", e => {
    const v = e.target?.value;
    if (typeof v === "string" && /\d/.test(v) && luhn(v)) evaluate(true);
  }, true);

  let timer = null;
  new MutationObserver(() => { clearTimeout(timer); timer = setTimeout(() => evaluate(), 600); })
    .observe(document.documentElement, { childList: true, subtree: true });

  chrome.storage.local.get(settings, s => {
    settings = s;
    chrome.runtime.sendMessage({ type: "getVerdict" }, v => { verdict = v || verdict; evaluate(); });
  });
})();
