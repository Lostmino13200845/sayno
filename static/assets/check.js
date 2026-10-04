// Message Check and Website Check. Everything runs in this browser tab: the scoring rules (engine.js) and the
// block-list lookups (lookup.js). What you paste is never sent anywhere.
(() => {
  const root = document.querySelector("main[data-check]");
  if (!root) return;
  const mode = root.dataset.check;                       // "message" | "website"
  const $ = id => document.getElementById(id);
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const base = () => window.SY.base;

  const EXAMPLES = {
    message: {
      scam: "RBC: Your new debit card is not yet activated and has been temporarily locked. Activate your card within 24 hours at https://rbc-card-activation.help/secure to avoid suspension.",
      normal: "Hi sweetie, dinner on Sunday at 6? Dad is making lasagna",
    },
    website: { scam: "http://rbc-royalbank-verify.top/login", normal: "https://www.rbcroyalbank.com/" },
  };
  const ICON = {
    warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3.500 22 20.500H2z"/><path d="M12 10v4.500M12 17.500v.5"/></svg>',
    safe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m4.500 12.500 5 5L20 6.500"/></svg>',
    tick: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 12.500 4.500 4.500L19 7.500"/></svg>',
  };

  const views = { input: $("view-input"), scan: $("view-scan"), result: $("view-result") };
  const field = $("text"), err = $("err");
  let lastInput = "";

  function setStep(n) { [1, 2, 3].forEach(i => { const li = $("tr-" + i); if (i === n) li.setAttribute("aria-current", "step"); else li.removeAttribute("aria-current"); }); }
  function show(name, step) {
    Object.entries(views).forEach(([k, el]) => { el.hidden = k !== name; });
    setStep(step);
    const h = views[name].querySelector("h1");
    if (h) { h.setAttribute("tabindex", "-1"); h.focus({ preventScroll: true }); }
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
  const sleep = ms => new Promise(r => setTimeout(r, ms));

  // ---------- the engine (loaded on first use)
  let mods = null;
  function load() {
    mods ||= Promise.all([import(base() + "/assets/engine.js"), import(base() + "/assets/lookup.js"),
      import(base() + "/assets/heuristics.js"), import(base() + "/assets/heuristics-data.js")])
      .then(([e, l, h, d]) => ({ ...l, analyzeText: e.analyzeText, isOfficial: h.isOfficial, brands: Object.keys(d.default.brands) }));
    return mods;
  }
  async function analyze(text) {
    const L = await load();
    let listsReady = false;
    try { await L.syncPrefixes(window.SY.data); } catch { /* offline: the checks still work, just without the lists */ }
    const result = await L.analyzeText(text, {
      listUrl: async u => { const r = await L.checkUrl(u, window.SY.data); listsReady = listsReady || r.ready; return r.listed; },
      listEmailDomain: async d => { const r = await L.checkEmailDomain(d, window.SY.data); listsReady = listsReady || r.ready; return { disposable: r.disposable, listed: r.listed }; },
    });
    return { result, listsReady, L };
  }

  // ---------- helpers for the result
  function normalizeAddress(raw) {
    let s = raw.trim();
    if (!s) return null;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = "https://" + s;
    try { const u = new URL(s); return u.hostname.includes(".") ? u.href : null; } catch { return null; }
  }
  function outcome(level) { return level === "high" || level === "critical" ? "high" : level === "medium" ? "caution" : "safe"; }
  function reasonsOf(r) {
    const all = [...r.text.findings, ...r.urls.flatMap(u => u.findings), ...r.emails.flatMap(e => e.findings)].filter(f => f.weight > 0);
    all.sort((a, b) => (b.severity === "danger") - (a.severity === "danger") || b.weight - a.weight);
    const seen = new Set(), out = [];
    for (const f of all) if (!seen.has(f.message)) { seen.add(f.message); out.push(f); }
    return out.slice(0, 5);
  }
  function excerptHtml(text, r) {
    const spans = [];
    const find = needle => { const i = text.toLowerCase().indexOf(String(needle).toLowerCase()); if (i >= 0) spans.push([i, i + needle.length]); };
    r.text.findings.forEach(f => f.evidence && find(f.evidence));
    r.urls.filter(u => u.score >= 15).forEach(u => find(u.url));
    spans.sort((a, b) => a[0] - b[0]);
    let out = "", pos = 0;
    for (const [s, e] of spans) { if (s < pos) continue; out += esc(text.slice(pos, s)) + "<mark class=\"hit\">" + esc(text.slice(s, e)) + "</mark>"; pos = e; }
    return out + esc(text.slice(pos));
  }
  const numbered = items => `<ol class="reasons">${items.map((t, i) => `<li><span class="num">${i + 1}</span><span>${t}</span></li>`).join("")}</ol>`;
  const qa = (title, body) => `<div class="qa"><h2>${title}</h2><div>${body}</div></div>`;

  // ---------- result screens
  function renderMessage(text, r) {
    const o = outcome(r.level), urls = r.urls, reasons = reasonsOf(r);
    const firstUrl = urls[0] && urls[0].url;
    const checkSite = firstUrl ? `<a class="btn btn-secondary btn-lg" href="${base()}/website-check/#q=${encodeURIComponent(firstUrl)}">Check the website</a>` : "";
    let head, stop, steps;
    if (o === "high") {
      head = `<span class="verdict verdict--high">${ICON.warn}HIGH RISK</span><h1>This message shows signs of a scam.</h1><p class="lead">It may look like it comes from a company you trust, but several things do not add up. You are not in trouble. You noticed it before acting.</p>`;
      stop = `<div class="stop-box"><strong>${urls.length ? "DO NOT CLICK THE LINK." : "DO NOT REPLY OR SEND ANYTHING."}</strong><p style="margin-top:8px">Do not reply and do not enter any card details.</p></div>`;
      steps = ["Do not tap any link or reply to the message.", "Open your bank's app, or type its address yourself, to see if anything is wrong.", "If you are unsure, call the number on the back of your card.", ...r.advice.slice(2).map(esc)];
    } else if (o === "caution") {
      head = `<span class="verdict verdict--caution">${ICON.warn}BE CAREFUL</span><h1>This message has some warning signs.</h1><p class="lead">SAYNO is not sure. Treat it with caution until you have checked it another way.</p>`;
      stop = `<div class="note-box"><strong>Do not click or reply yet.</strong><p class="muted">Check with the company using an app or phone number you already trust.</p></div>`;
      steps = ["Do not tap any link until you have checked it.", "Contact the company through its official app or a website you type yourself.", "If it asks for card details or codes, treat it as a scam.", ...r.advice.slice(1).map(esc)];
    } else {
      head = `<span class="verdict verdict--safe">${ICON.safe}SAFE</span><h1>No strong scam signs were found.</h1><p class="lead">SAYNO did not find pressure, threats, requests for card details or dangerous links in this message.</p>`;
      stop = `<div class="note-box"><strong>Safe does not guarantee trustworthy.</strong><p class="muted">SAYNO looks for known scam signs. If something still feels wrong, contact the person or company using a phone number or app you already trust.</p></div>`;
      steps = ["You can carry on.", "If the message asks you to open a link and enter card details, check that website first."];
    }
    const happened = o === "safe"
      ? `<p>SAYNO checked your message and found no strong scam signals.</p>`
      : `<p style="margin-bottom:14px">SAYNO checked your message and found ${reasons.length > 1 ? "several scam signs" : "a warning sign"}. The underlined parts are what it noticed.</p><div class="excerpt">${excerptHtml(text, r)}</div>`;
    const why = o === "safe"
      ? `<ul class="check-list">${["The wording: pressure, threats and requests for card or personal details", "Links and web addresses in the message", "Email addresses and where they claim to come from", "Lists of known dangerous websites"].map(t => `<li><span class="tick">${ICON.tick}</span>${t}</li>`).join("")}</ul>`
      : numbered(reasons.map(f => esc(f.message)));
    const doNow = `${numbered(steps)}<div class="flow" style="margin-top:22px">${o === "safe"
      ? `<a class="btn btn-primary btn-lg" href="${base()}/">Done</a><a class="btn btn-secondary btn-lg" href="${base()}/website-check/">Check a website</a>`
      : `<button class="btn btn-primary btn-lg" type="button" data-again>Go back</button>${checkSite}`}</div>
      <p style="margin-top:14px"><button class="linkish" type="button" data-again>Check another message</button></p>`;
    return `<div class="stack" style="--gap:1.25rem">${head}</div><div style="margin-top:2rem">${stop}</div>
      <div style="margin-top:2.25rem">${qa("What happened", happened)}${qa(o === "safe" ? "What we checked" : "Why SAYNO says this", why)}${qa("What to do now", doNow)}</div>`;
  }

  function renderWebsite(href, r, listsReady, L) {
    const o = outcome(r.level), u = r.urls[0], host = u.host, reasons = reasonsOf(r);
    const brand = L.brands.find(b => L.isOfficial(host, b));
    const signals = [];
    if (/^https:/i.test(href)) signals.push("It uses a secure connection (https)");
    if (brand) signals.push(`The address matches the official website of ${brand.length <= 4 ? brand.toUpperCase() : brand[0].toUpperCase() + brand.slice(1)}`);
    if (listsReady && !u.findings.some(f => /threat database/i.test(f.message))) signals.push("It is not on any list of known dangerous websites");
    if (!u.findings.some(f => f.weight > 0)) signals.push("The address is not disguised or made to look like another site");
    let head, stop, steps;
    if (o === "high") {
      head = `<span class="verdict verdict--high">${ICON.warn}HIGH RISK</span><h1>This website looks suspicious.</h1><p class="lead">It may be trying to look like a company you trust. Do not use it.</p>`;
      stop = `<div class="stop-box"><strong>DO NOT ENTER ANY OF THIS ON THE WEBSITE:</strong><ul class="nogo" style="justify-content:center">${["Card number", "CVV / security code", "Expiry date", "PIN", "Online banking password", "One-time codes", "SIN"].map(t => `<li>${t}</li>`).join("")}</ul></div>`;
      steps = ["Do not open this website.", "If you already opened it, do not type anything. Close the page.", "Go to your bank by opening its app or typing its address yourself."];
    } else if (o === "caution") {
      head = `<span class="verdict verdict--caution">${ICON.warn}BE CAREFUL</span><h1>This website has some warning signs.</h1><p class="lead">SAYNO is not sure about it. Do not enter sensitive information until you are certain.</p>`;
      stop = `<div class="note-box"><strong>Do not enter card details or passwords here.</strong><p class="muted">Reach the company through its app or a website address you type yourself.</p></div>`;
      steps = ["Do not enter card details, passwords or codes.", "Reach the company through its official app or an address you type yourself.", "If a message sent you here, treat the message as suspicious too."];
    } else {
      head = `<span class="verdict verdict--safe">${ICON.safe}SAFE</span><h1>No strong warning signs were found.</h1><p class="lead">SAYNO checked <b>${esc(host)}</b> and did not find signs that it is malicious.</p>`;
      stop = `<div class="note-box"><strong>Safe does not guarantee trustworthy.</strong><p class="muted">SAYNO cannot see everything. Still type your details only into websites you opened yourself, and never share codes sent to your phone.</p></div>`;
      steps = ["You can continue.", "Card Guard keeps watching while you browse, in case a page asks for card details it should not."];
    }
    const happened = `<p style="margin-bottom:12px">SAYNO checked this address without opening it:</p><p class="excerpt" style="font-weight:700;font-size:1.15rem">${esc(href)}</p>`;
    const why = o === "safe"
      ? `<ul class="check-list">${(signals.length ? signals : ["No warning signs were found in the address"]).map(t => `<li><span class="tick">${ICON.tick}</span>${t}</li>`).join("")}</ul>`
      : numbered(reasons.map(f => esc(f.message)));
    const doNow = `${numbered(steps)}<div class="flow" style="margin-top:22px">${o === "safe"
      ? `<a class="btn btn-primary btn-lg" href="${base()}/">Done</a><button class="btn btn-secondary btn-lg" type="button" data-again>Check another website</button>`
      : `<a class="btn btn-primary btn-lg" href="${base()}/">Leave website</a><button class="btn btn-secondary btn-lg" type="button" data-again>Go back</button>`}</div>`;
    return `<div class="stack" style="--gap:1.25rem">${head}</div><div style="margin-top:2rem">${stop}</div>
      <div style="margin-top:2.25rem">${qa("What happened", happened)}${qa(o === "safe" ? "The signals" : "Why SAYNO says this", why)}${qa("What to do now", doNow)}</div>`;
  }

  // ---------- run a check
  async function run(rawInput) {
    show("scan", 1);
    const bar = $("bar"), items = [...document.querySelectorAll("#view-scan [data-step]")];
    const setState = (n, state) => { const li = items[n - 1]; li.dataset.state = state; li.querySelector(".tick").innerHTML = state === "done" ? ICON.tick : state === "active" ? "&hellip;" : "&nbsp;"; };
    const progress = pct => { bar.style.width = pct + "%"; bar.parentElement.setAttribute("aria-valuenow", pct); };
    items.forEach((_, i) => setState(i + 1, i ? "todo" : "active")); progress(10);
    const started = performance.now();
    const work = analyze(rawInput);
    await sleep(500); setState(1, "done"); setState(2, "active"); progress(40);
    await sleep(500); setState(2, "done"); setState(3, "active"); progress(70);
    let out;
    try { out = await work; } catch (e) {
      views.result.innerHTML = `<div class="stack"><h1>We could not finish the check.</h1><p class="lead">Something went wrong on this device. Nothing was sent anywhere. Please try again.</p><div class="flow"><button class="btn btn-primary btn-lg" type="button" data-again>Try again</button></div></div>`;
      show("result", 2); return;
    }
    await sleep(Math.max(0, 1500 - (performance.now() - started)));
    setState(3, "done"); progress(100); await sleep(250);
    const { result, listsReady, L } = out;
    if (mode === "website") {
      if (!result.urls.length) { show("input", 1); err.hidden = false; return; }
      views.result.innerHTML = renderWebsite(rawInput, result, listsReady, L);
    } else {
      views.result.innerHTML = renderMessage(rawInput, result);
    }
    show("result", 2);
  }

  function reset(keepText) {
    if (!keepText) field.value = "";
    err.hidden = true; show("input", 1); field.focus({ preventScroll: true });
  }

  $("form").addEventListener("submit", e => {
    e.preventDefault(); err.hidden = true;
    const raw = field.value.trim();
    if (!raw) { err.hidden = false; field.focus(); return; }
    if (mode === "website") {
      const href = normalizeAddress(raw);
      if (!href) { err.hidden = false; field.focus(); return; }
      lastInput = href; run(href);
    } else { lastInput = raw; run(raw); }
  });
  document.querySelectorAll("[data-example]").forEach(b => b.addEventListener("click", () => { field.value = EXAMPLES[mode][b.dataset.example]; err.hidden = true; field.focus(); }));
  views.result.addEventListener("click", e => { if (e.target.closest("[data-again]")) reset(false); });

  // links from other pages: /website-check/#q=<address> checks that address straight away
  const q = new URLSearchParams(location.hash.slice(1)).get("q");
  if (q) {
    history.replaceState(null, "", location.pathname);
    field.value = q;
    $("form").requestSubmit();
  }
})();
