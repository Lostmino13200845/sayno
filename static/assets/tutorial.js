// SAYNO website: live threat count + the interactive tutorial ("practice browser").
// Every step: instructions on the left, a pulsing ring on the thing to click on the right.
(() => {
  // "" on a server, "/sayno" on GitHub Pages: the folder that holds assets/, v1/ and the pages.
  const BASE = new URL("..", document.currentScript.src).pathname.replace(/\/$/, "");
  const $ = s => document.querySelector(s);
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  const RBC_TEXT = "RBC: Your new debit card is not yet activated and has been temporarily locked. Activate your card within 24 hours at https://rbc-card-activation.help/secure to avoid suspension.";
  const RBC_URL = "https://rbc-card-activation.help/secure";

  // Offline fallbacks (same shape as /api/scan) so the tutorial also works as a static page.
  const CANNED = {
    [RBC_TEXT]: { score: 92, level: "critical", reported: 0,
      text: { findings: [
        { weight: 12, severity: "warn", message: "Creates urgency / time pressure" },
        { weight: 12, severity: "warn", message: "Threatens account closure, arrest or legal action" },
        { weight: 12, severity: "warn", message: "Targets new accounts ('welcome', 'activate your new account/card')" },
        { weight: 15, severity: "danger", message: "Pressure combined with a request for data or money (classic scam pattern)" }] },
      urls: [{ url: RBC_URL, score: 38, level: "medium", findings: [
        { weight: 10, severity: "warn", message: "Top-level domain '.help' is heavily abused by scammers" },
        { weight: 24, severity: "danger", message: "Mentions 'rbc' but is not an official rbc domain" }] }],
      emails: [], advice: ["Do NOT click any link, open attachments, reply, or call numbers in this message."] },
    [RBC_URL]: { score: 38, level: "medium", reported: 0, text: { findings: [] }, emails: [], advice: [],
      urls: [{ url: RBC_URL, score: 38, level: "medium", findings: [
        { weight: 10, severity: "warn", message: "Top-level domain '.help' is heavily abused by scammers" },
        { weight: 24, severity: "danger", message: "Mentions 'rbc' but is not an official rbc domain" }] }] },
  };
  const SAFE = { score: 0, level: "safe", text: { findings: [] }, urls: [], emails: [], advice: [], reported: 0 };

  async function scan(text) {
    try {  // the real scoring rules, run right here in the page (no network, nothing stored or reported)
      const { analyzeText } = await import(BASE + "/assets/engine.js");
      return await analyzeText(text);
    } catch { return CANNED[text] || SAFE; }
  }

  // ---- live threat count
  fetch(BASE + "/v1/meta.json").then(r => r.json()).then(s => {
    const n = s.entries;
    if (n) { $("#statThreats") && ($("#statThreats").textContent = n.toLocaleString()); $("#pStatus").textContent = `🟢 ${n.toLocaleString()} threats`; }
  }).catch(() => { $("#pStatus").textContent = "🟢 700k+ threats"; });

  // ================= practice browser state =================
  const S = { view: "inbox", popup: false, ctx: false, panel: false, veil: false, toast: false,
              pasted: false, scanned: null, siteResult: SAFE, bankRbc: false };
  const views = { inbox: "messages.example.com", bank: "rbc-card-activation.help/secure", shop: "cascadebooks.example/checkout" };

  function renderResult(r) {
    const f = [...r.text.findings, ...r.urls.flatMap(u => u.findings), ...r.emails.flatMap(e => e.findings)].filter(x => x.weight).slice(0, 5);
    return `<span class="ss-level ss-level--${r.level}">${r.level} · ${r.score}/100</span>
      <ul class="ss-findings">${f.map(x => `<li class="${x.severity === "danger" ? "is-danger" : ""}">${esc(x.message)}</li>`).join("")
        || '<li class="is-ok">No warning signs found.</li>'}</ul>`;
  }
  // "This site" shows the rating of the page itself. A safe page says so in words (a bare "SAFE 0/100"
  // above a scam warning reads like a contradiction); the message result below is rated separately.
  function renderSite(r) {
    if (r.level !== "safe" && r.level !== "low") return renderResult(r);
    return `<span class="ss-level ss-level--safe">This page looks safe</span>
      <p class="ss-muted">${S.scanned ? "This rates the page you are on, not the message below." : "No warning signs found on this page."}</p>`;
  }
  const BADGE = { safe: null, low: null, medium: ["!", "medium"], high: ["!!", "high"], critical: ["✖", "critical"] };
  function setBadge(level) {
    const b = BADGE[level];
    $("#mBadge").hidden = !b;
    if (b) { $("#mBadge").textContent = b[0]; $("#mBadge").className = "ss-badge ss-badge--" + b[1]; }
  }

  function draw() {
    document.querySelectorAll("#mPage .view").forEach(v => v.hidden = v.dataset.view !== S.view);
    $("#mUrl").textContent = views[S.view];
    $("#mUrl").classList.toggle("is-danger", S.view === "bank");
    $("#mPopup").hidden = !S.popup;
    $("#mCtx").hidden = !S.ctx;
    $("#mPanel").hidden = !S.panel;
    $("#mVeil").hidden = !S.veil;
    $("#mToast").hidden = !S.toast;
    $("#pSite").innerHTML = `<div class="pp-host">${views[S.view].split("/")[0]}</div>` + renderSite(S.siteResult);
    $("#pTxt").value = S.pasted ? RBC_TEXT : "";
    $("#pOut").innerHTML = S.scanned ? renderResult(S.scanned) : "";
    $("#pBankRbc input").checked = S.bankRbc;
    $("#msgRbc").classList.toggle("is-selected", S.ctx || S.panel);
    setBadge(S.siteResult.level);
    refresh();
  }

  async function go(view) {
    Object.assign(S, { view, popup: false, ctx: false, panel: false, veil: false, toast: false });
    S.siteResult = view === "bank" ? await scan(RBC_URL) : SAFE;
    $("#mPage").scrollTop = 0;
    if (view === "bank") {
      $("#veilLevel") && ($("#veilLevel").textContent = S.siteResult.level.toUpperCase());
      draw();
      setTimeout(() => { S.veil = true; draw(); }, 450);  // Card Guard kicks in once the form is detected
      return;
    }
    draw();
  }

  // ---- actions (work any time; the tutorial just points at them)
  const A = {
    togglePopup() { S.popup = !S.popup; S.ctx = false; draw(); },
    async paste() { S.popup = true; S.pasted = true; S.scanned = null; draw(); $("#pOut").innerHTML = '<p class="ss-muted">Checking…</p>'; S.scanned = await scan(RBC_TEXT); draw(); },
    openBanks() { $("#pBanks").open = true; refresh(); },
    tickRbc() { $("#pBanks").open = true; S.bankRbc = !S.bankRbc; draw(); },
    openCtx(x, y) {
      S.popup = false; S.ctx = true;
      const m = $("#mock").getBoundingClientRect(), msg = $("#msgRbc").getBoundingClientRect();
      const left = x != null ? x - m.left : msg.left - m.left + 40, top = y != null ? y - m.top : msg.top - m.top + 30;
      Object.assign($("#mCtx").style, { left: Math.min(left, m.width - 280) + "px", top: Math.min(top, m.height - 120) + "px" });
      draw();
    },
    async checkText() {
      S.ctx = false; S.panel = true; draw();
      $("#mPanel").innerHTML = '<p class="ss-muted">Checking…</p>';
      const r = await scan(RBC_TEXT);
      $("#mPanel").innerHTML = `<div class="ov-panel-head"><b>🛡️ SAYNO</b><button class="ov-close" id="panelX" aria-label="Close">×</button></div>
        ${renderResult(r)}<p class="ss-muted">${esc(r.advice[0] || "")}</p>`;
      $("#panelX").onclick = () => { S.panel = false; draw(); };
      S.checkedText = true; refresh();
    },
    clickLink() { go("bank"); },
    leave() { S.left = true; go("inbox"); },
    stay() { S.veil = false; draw(); },
    openShop() { go("shop"); },
    typeCard() {
      const i = $("#shopCard"); let n = 0; const card = "4242 4242 4242 4242";
      const t = setInterval(() => { i.value = card.slice(0, ++n); if (n >= card.length) { clearInterval(t); S.toast = true; draw(); } }, 35);
    },
  };

  $("#mExt").onclick = A.togglePopup;
  $("#pTxt").onclick = A.paste;
  $("#pBanksSum").addEventListener("click", () => setTimeout(refresh, 0));
  $("#pBankRbc").addEventListener("click", e => { e.preventDefault(); A.tickRbc(); });
  $("#msgRbc").addEventListener("contextmenu", e => { e.preventDefault(); A.openCtx(e.clientX, e.clientY); });
  $("#msgRbc").addEventListener("click", e => { if (e.target.id !== "rbcLink") A.openCtx(e.clientX, e.clientY); });
  $("#msgRbc").addEventListener("keydown", e => { if (e.key === "Enter" || e.key === "ContextMenu") A.openCtx(); });
  $("#ctxCheck").onclick = A.checkText;
  $("#rbcLink").onclick = e => { e.stopPropagation(); A.clickLink(); };
  $("#ovLeave").onclick = A.leave;
  $("#ovStay").onclick = A.stay;
  $("#goShop").onclick = A.openShop;
  $("#shopCard").onclick = A.typeCard;
  $("#mHome").onclick = () => go("inbox");
  document.addEventListener("click", e => { if (S.ctx && !e.target.closest("#mCtx, #msgRbc")) { S.ctx = false; draw(); } });
  $("#mock").addEventListener("click", e => {
    if (S.popup && !e.target.closest("#mPopup, #mExt")) { S.popup = false; draw(); }
  });

  // ================= tutorial steps =================
  const STEPS = [
    { title: "Open SAYNO",
      text: "<p>SAYNO lives in your toolbar as a <b>shield</b>.</p><span class='do'>👉 Click the shield.</span>",
      target: () => "#mExt", label: "Click the shield",
      setup() { Object.assign(S, { popup: false, ctx: false, panel: false }); if (S.view !== "inbox") return go("inbox"); draw(); },
      done: () => S.popup, doIt: () => A.togglePopup() },
    { title: "Message check",
      text: "<p>Paste any text or link. You get a <b>danger score</b> and the reasons.</p><span class='do'>👉 Click the box to paste the fake RBC text.</span>",
      target: () => S.scanned ? "#pOut" : "#pTxt", label: () => S.scanned ? "Score and reasons" : "Click to paste",
      setup() { S.popup = true; draw(); },
      done: () => !!S.scanned, doIt: () => A.paste() },
    { title: "Right-click check",
      text: "<p>Check text on <b>any website</b> without opening SAYNO.</p><span class='do'>👉 Right-click the RBC message, then <b>Check this text with SAYNO</b>.</span>",
      target: () => S.popup ? "#mExt" : S.ctx ? "#ctxCheck" : "#msgRbc",
      label: () => S.popup ? "Close the popup" : S.ctx ? "Choose this" : "Right-click this message",
      setup() { S.checkedText = false; if (S.view !== "inbox") return go("inbox"); S.panel = false; draw(); },
      done: () => S.checkedText, doIt: () => { S.popup = false; A.checkText(); } },
    { title: "Card Guard",
      text: "<p>Tap the link in the RBC message. <b>Card Guard</b> blocks the fake bank page before you type anything.</p><span class='do'>👉 Click the link, then <b>Get me out of here</b>.</span>",
      target: () => S.view === "bank" ? (S.veil ? "#ovLeave" : null) : "#rbcLink",
      label: () => S.view === "bank" ? "Leave safely" : "Click the link",
      setup() { S.left = false; Object.assign(S, { popup: false, ctx: false, panel: false }); if (S.view !== "inbox") return go("inbox"); draw(); },
      done: () => S.left, doIt: async () => { if (S.view !== "bank") await go("bank"); A.leave(); } },
    { title: "Safe shopping",
      text: "<p>Real shops still work. You only get a <b>small reminder</b>.</p><span class='do'>👉 Open the Cascade Books link, then click the card field.</span>",
      target: () => S.view === "shop" ? (S.toast ? null : "#shopCard") : "#goShop",
      label: () => S.view === "shop" ? "Click to type a test card" : "Open the shop",
      setup() { S.toast = false; if (S.view === "bank") return go("inbox"); draw(); },
      done: () => S.toast, doIt: async () => { if (S.view !== "shop") await go("shop"); A.typeCard(); } },
    { title: "You're protected",
      text: "<p>That's it: <b>Card Guard</b>, <b>site check</b>, <b>message check</b> and <b>auto-report</b> all work on their own.</p><p><a class='ss-btn' href='#add'>Add to browser</a></p>",
      target: () => null, setup() { S.popup = false; if (S.view !== "inbox") return go("inbox"); draw(); } },
  ];

  let cur = 0;
  const doneSet = new Set();

  function renderStepList() {
    $("#tSteps").innerHTML = STEPS.map((s, i) =>
      `<li class="${i === cur ? "is-current" : ""} ${doneSet.has(i) ? "is-done" : ""}" data-i="${i}" tabindex="0">${esc(s.title)}</li>`).join("");
    document.querySelectorAll("#tSteps li").forEach(li => {
      li.onclick = () => show(+li.dataset.i);
      li.onkeydown = e => { if (e.key === "Enter") show(+li.dataset.i); };
    });
  }

  async function show(i) {
    cur = Math.max(0, Math.min(STEPS.length - 1, i));
    const s = STEPS[cur];
    $("#tCount").textContent = `Step ${cur + 1} of ${STEPS.length}`;
    $("#tTitle").textContent = s.title;
    $("#tText").innerHTML = s.text;
    $("#tProg").style.width = `${(cur / (STEPS.length - 1)) * 100}%`;
    $("#tBack").disabled = cur === 0;
    $("#tNext").hidden = cur === STEPS.length - 1;
    $("#tDoIt").hidden = !s.doIt;
    document.querySelectorAll("#tText [data-b]").forEach(b => b.onclick = () => setBadge(b.dataset.b));
    renderStepList();
    await s.setup?.();
    refresh();
  }

  // Called after every state change: completion check + move the ring.
  function refresh() {
    const s = STEPS[cur];
    if (!s) return;
    const complete = !s.done || s.done();
    if (s.done && complete && !doneSet.has(cur)) {
      doneSet.add(cur);
      $("#tText").insertAdjacentHTML("beforeend", "<span class='do done'>✓ Nice! Press <b>Next</b> to continue.</span>");
      renderStepList();
    } else if (!s.done) doneSet.add(cur);
    // Next is always available so anyone can skip ahead; it just looks like the main action once the step is done.
    // "Do it for me" stays next to it, so both choices are open at the same time.
    $("#tNext").disabled = false;
    $("#tNext").classList.toggle("ss-btn--ghost", !complete);
    placeHotspot();
    setTimeout(placeHotspot, 260);  // again after popup / panel animations settle
  }

  function placeHotspot() {
    const s = STEPS[cur], hot = $("#hot");
    const sel = s.target?.();
    const el = sel && (typeof sel === "string" ? $(sel) : sel);
    if (!el || (s.done && s.done()) || !el.getClientRects().length) { hot.hidden = true; return; }
    // keep the target visible inside the practice page without scrolling the whole website
    for (const box of [$("#mPage"), $("#mPopup")]) {
      if (!box.contains(el) || box === el) continue;
      const pr = box.getBoundingClientRect(), er = el.getBoundingClientRect();
      if (er.top < pr.top) box.scrollTop -= pr.top - er.top + 16;
      else if (er.bottom > pr.bottom) box.scrollTop += Math.min(er.bottom - pr.bottom + 16, er.top - pr.top - 16);
    }
    const m = $("#mock").getBoundingClientRect(), r = el.getBoundingClientRect(), pad = 5;
    Object.assign(hot.style, { left: r.left - m.left - pad + "px", top: r.top - m.top - pad + "px",
      width: r.width + pad * 2 + "px", height: r.height + pad * 2 + "px" });
    const label = typeof s.label === "function" ? s.label() : s.label;
    $("#hotLabel").textContent = label || "Click here";
    hot.classList.toggle("is-above", r.bottom - m.top > m.height - 60);
    const mid = r.left + r.width / 2 - m.left;  // keep the label inside the practice browser
    hot.classList.toggle("is-right", mid > m.width - 110);
    hot.classList.toggle("is-left", mid < 110);
    hot.hidden = false;
  }

  $("#tNext").onclick = () => show(cur + 1);
  $("#tBack").onclick = () => show(cur - 1);
  $("#tDoIt").onclick = async () => { await STEPS[cur].doIt?.(); refresh(); };
  $("#mPage").addEventListener("scroll", placeHotspot);
  $("#mPopup").addEventListener("scroll", placeHotspot);
  window.addEventListener("resize", placeHotspot);
  new ResizeObserver(placeHotspot).observe($("#mock"));

  // Deep link: /#tutorial-5 opens step 5 (handy when presenting).
  const deep = location.hash.match(/^#tutorial-(\d+)$/);
  // /tutorial = the tutorial on its own (full-screen for presenting or embedding)
  const only = /\/tutorial\/?$/.test(location.pathname);
  if (only) document.body.classList.add("tut-only");
  draw();
  if (deep) {
    if (!only) document.getElementById("tutorial").scrollIntoView({ behavior: "instant" });
    (async () => { for (let i = 0; i < +deep[1]; i++) await show(i); })();
  } else show(0);
})();
