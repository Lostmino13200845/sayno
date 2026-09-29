// Scam Shield website: live threat count + the interactive tutorial ("practice browser").
// Every step: instructions on the left, a pulsing ring on the thing to click on the right.
(() => {
  const $ = s => document.querySelector(s);
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  const RBC_TEXT = "RBC: Your new debit card is not yet activated and has been temporarily locked. Activate your card within 24 hours at https://rbc-card-activation.help/secure to avoid suspension.";
  const RBC_URL = "https://rbc-card-activation.help/secure";

  // Offline fallbacks (same shape as /api/scan) so the tutorial also works as a static page.
  const CANNED = {
    [RBC_TEXT]: { score: 72, level: "high", reported: 0,
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
    try {
      const r = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, online: false, log: false }) });  // log:false = practice, never stored/reported
      if (!r.ok) throw 0;
      return await r.json();
    } catch { return CANNED[text] || SAFE; }
  }

  // ---- live threat count
  fetch("/api/status").then(r => r.json()).then(s => {
    const n = s.protection?.threats;
    if (n) { $("#statThreats").textContent = n.toLocaleString(); $("#pStatus").textContent = `🟢 ${n.toLocaleString()} threats`; }
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
    $("#pSite").innerHTML = `<div class="pp-host">${views[S.view].split("/")[0]}</div>` + renderResult(S.siteResult);
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
      $("#mPanel").innerHTML = `<div class="ov-panel-head"><b>🛡️ Scam Shield</b><button class="ov-close" id="panelX" aria-label="Close">×</button></div>
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
    { title: "Find the shield",
      text: "<p>After you install Scam Shield, a blue <b>shield</b> sits in your browser's toolbar, top right.</p><span class='do'>👉 Click the shield to open it.</span>",
      target: () => "#mExt", label: "Click the shield",
      setup() { Object.assign(S, { popup: false, ctx: false, panel: false }); if (S.view !== "inbox") return go("inbox"); draw(); },
      done: () => S.popup, doIt: () => A.togglePopup() },
    { title: "What the popup shows",
      text: "<p>The top line shows the protection is live: the <b>number of known scam sites</b> it checks against, updated every 5 minutes.</p><p><b>This site</b> rates the page you're on. Your messages page is <b>safe</b>.</p>",
      target: () => "#pSite", label: "Rating of this page",
      setup() { S.popup = true; draw(); } },
    { title: "Check a suspicious message",
      text: "<p>Got a strange text or e-mail? <b>Copy it and paste it</b> into this box. It's checked the moment you paste, with no button to press.</p><span class='do'>👉 Click the box to paste the fake RBC text.</span>",
      target: () => "#pTxt", label: "Click to paste",
      setup() { S.popup = true; draw(); },
      done: () => !!S.scanned, doIt: () => A.paste() },
    { title: "Read the result",
      text: "<p>Every message gets a <b>danger score from 0 to 100</b> and a level: <span class='ss-level ss-level--safe'>safe</span> <span class='ss-level ss-level--medium'>medium</span> <span class='ss-level ss-level--high'>high</span> <span class='ss-level ss-level--critical'>critical</span></p><p>Below it, in plain words, <b>why</b>: pressure, a fake RBC address, a “new card” trick.</p>",
      target: () => "#pOut", label: "Score and reasons",
      async setup() { S.popup = true; if (!S.scanned) await A.paste(); draw(); } },
    { title: "Tell it your bank",
      text: "<p>Open <b>My bank(s)</b> and tick the bank you really use. Only your bank's real website is then trusted with your card; look-alikes are not.</p><span class='do'>👉 Let's say you bank with RBC: tick it.</span>",
      target: () => $("#pBanks").open ? "#pBankRbc" : "#pBanksSum", label: () => $("#pBanks").open ? "Tick RBC" : "Open My bank(s)",
      setup() { S.popup = true; draw(); },
      done: () => S.bankRbc, doIt: () => { A.openBanks(); if (!S.bankRbc) A.tickRbc(); } },
    { title: "Your two switches",
      text: "<p><b>Block fake pages that ask for my card:</b> that's Card Guard. Keep it on.</p><p><b>New-account mode:</b> extra reminders for your first months with a new account, or when you hold a large balance.</p>",
      target: () => "#pNewcomer", label: "Both on by default",
      setup() { S.popup = true; draw(); } },
    { title: "Right-click to check any text",
      text: "<p>You can also check text <b>on any website</b>, such as webmail or chat, without opening the popup.</p><span class='do'>👉 Close the popup, then right-click (or click) the RBC message and choose <b>Check this text with Scam Shield</b>.</span>",
      target: () => S.popup ? "#mExt" : S.ctx ? "#ctxCheck" : "#msgRbc",
      label: () => S.popup ? "Close the popup" : S.ctx ? "Choose this" : "Right-click this message",
      setup() { S.checkedText = false; if (S.view !== "inbox") return go("inbox"); S.panel = false; draw(); },
      done: () => S.checkedText, doIt: () => { S.popup = false; A.checkText(); } },
    { title: "What if you tap the link?",
      text: "<p>Lots of people tap the link before thinking. That's fine: this is where <b>Card Guard</b> steps in.</p><span class='do'>👉 Click the link in the RBC message.</span>",
      target: () => "#rbcLink", label: "Click the link",
      setup() { Object.assign(S, { popup: false, ctx: false, panel: false }); if (S.view !== "inbox") return go("inbox"); draw(); },
      done: () => S.view === "bank" && S.veil, doIt: () => A.clickLink() },
    { title: "Card Guard blocks the fake page",
      text: "<p>The page pretends to be RBC and asks for your <b>card number, CVV and PIN</b>. Card Guard blocks it <b>before you type anything</b> and explains why. The shield in the toolbar turned orange too.</p><p><b>Get me out of here</b> takes you back. <b>Continue</b> exists only for rare mistakes.</p><span class='do'>👉 Click “Get me out of here”.</span>",
      target: () => S.veil ? "#ovLeave" : null, label: "Leave safely",
      async setup() { S.left = false; if (S.view !== "bank") await go("bank"); },
      done: () => S.left, doIt: () => A.leave() },
    { title: "Normal shopping still works",
      text: "<p>Card Guard doesn't get in the way of real shops. Typing your card on a normal checkout only shows a <b>small reminder</b> in new-account mode.</p><span class='do'>👉 Open the Cascade Books link, then click the card field.</span>",
      target: () => S.view === "shop" ? (S.toast ? null : "#shopCard") : "#goShop",
      label: () => S.view === "shop" ? "Click to type a test card" : "Open the shop",
      setup() { S.toast = false; if (S.view === "bank") return go("inbox"); draw(); },
      done: () => S.toast, doIt: async () => { if (S.view !== "shop") await go("shop"); A.typeCard(); } },
    { title: "The shield's colours",
      text: "<p>The toolbar shield always tells you how risky the current site is. Click a colour to preview it:</p><p class='badges'>" +
        "<button class='ss-btn ss-btn--ghost ss-btn--s' data-b='safe'>No badge · nothing found</button> " +
        "<button class='ss-btn ss-btn--ghost ss-btn--s' data-b='medium'><span class='ss-badge ss-badge--medium'>!</span> be careful</button> " +
        "<button class='ss-btn ss-btn--ghost ss-btn--s' data-b='high'><span class='ss-badge ss-badge--high'>!!</span> high risk</button> " +
        "<button class='ss-btn ss-btn--ghost ss-btn--s' data-b='critical'><span class='ss-badge ss-badge--critical'>✖</span> known scam</button></p>",
      target: () => "#mExt", label: "Watch the badge",
      setup() { Object.assign(S, { popup: false, toast: false }); draw(); } },
    { title: "You're ready 🎉",
      text: "<p>That's everything: <b>site checks</b>, <b>Card Guard</b>, <b>message checks</b> and <b>automatic reporting</b>.</p><p>Remember: your bank will <b>never</b> ask for your PIN, CVV or a one-time code.</p><p><a class='ss-btn' href='#install'>Install Scam Shield</a> <a class='ss-btn ss-btn--ghost' href='/app'>Open the web scanner</a></p>",
      target: () => null, setup() { S.popup = false; draw(); } },
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
    $("#tNext").disabled = !complete;
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
  const only = location.pathname === "/tutorial";
  if (only) document.body.classList.add("tut-only");
  draw();
  if (deep) {
    if (!only) document.getElementById("tutorial").scrollIntoView({ behavior: "instant" });
    (async () => { for (let i = 0; i < +deep[1]; i++) await show(i); })();
  } else show(0);
})();
