// Report a scam: an incident-type template with blanks, a live preview of the exact email, and three ways to send it.
// "Send report" posts the structured fields to the SAYNO relay (docs/REPORT_BACKEND.md), which emails them from the
// team address. Until REPORT_ENDPOINT is set the page offers only "Copy" and "Open in my email app".
const REPORT_ENDPOINT = "";

(() => {
  const $ = id => document.getElementById(id);
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const SY = window.SY || { base: "" };

  const IMPERSONATING = ["Not sure", "RBC", "TD", "BMO", "Scotiabank", "CIBC", "National Bank", "Desjardins", "Another bank", "Canada Revenue Agency (CRA)",
    "Service Canada", "A government agency", "Canada Post", "A delivery company", "Interac", "A store or brand", "Someone I know", "Other"];

  // Each incident type decides which blanks appear and which common requests the user can tick.
  const TYPES = {
    website: {
      label: "Scam website or link", hint: "A fake bank, delivery, tax or shop page.",
      fields: [
        { id: "url", label: "The web address (link)", kind: "url", required: true, placeholder: "https://", help: "Copy it from the message or address bar. Do not open it again." },
        { id: "via", label: "How did you find it?", kind: "select", options: ["Text message", "Email", "Social media", "Online ad or search result", "Phone call", "Other"] },
        { id: "who", label: "Who was it pretending to be?", kind: "select", options: IMPERSONATING },
        { id: "asked", label: "What did the page ask you to do or enter?", kind: "multi", options: ["Card number, expiry or CVV", "Card PIN", "Online banking username or password", "A one-time code (text or email)", "SIN or ID details", "Personal details (name, address, birth date)", "Pay by e-Transfer, gift cards or crypto", "Install an app or give remote access", "Nothing yet, I just spotted it"] },
        { id: "notes", label: "Anything else we should know? (optional)", kind: "textarea", rows: 3 }
      ]
    },
    text: {
      label: "Scam text message (SMS)", hint: "A text that asks you to click, reply or call.",
      fields: [
        { id: "sender", label: "The number it came from", kind: "text", required: true, placeholder: "+1 ...", help: "A short code or a phone number." },
        { id: "message", label: "The message text", kind: "textarea", required: true, rows: 5, help: "Copy and paste it exactly." },
        { id: "url", label: "A link inside the message (if any)", kind: "url", placeholder: "https://" },
        { id: "who", label: "Who was it pretending to be?", kind: "select", options: IMPERSONATING },
        { id: "asked", label: "What did the text ask you to do?", kind: "multi", options: ["Click a link", "Reply to the message", "Call a phone number", "Share a one-time code", "Send an e-Transfer or buy gift cards", "Install an app", "Enter card or banking details on a website", "Confirm a delivery or payment"] },
        { id: "notes", label: "Anything else we should know? (optional)", kind: "textarea", rows: 3 }
      ]
    },
    email: {
      label: "Scam email", hint: "An email that looks like your bank, the CRA or a delivery company.",
      fields: [
        { id: "sender", label: "The sender's email address", kind: "email", required: true, placeholder: "name@example.com", help: "The address shown on the email, not the display name." },
        { id: "subject", label: "The subject line", kind: "text" },
        { id: "message", label: "The email text", kind: "textarea", required: true, rows: 6, help: "Copy and paste the main text. Leave out your own name and address." },
        { id: "url", label: "A link inside the email (if any)", kind: "url", placeholder: "https://" },
        { id: "who", label: "Who was it pretending to be?", kind: "select", options: IMPERSONATING },
        { id: "asked", label: "What did the email ask you to do?", kind: "multi", options: ["Click a link", "Open an attachment", "Log in to my bank or account", "Update payment details", "Reply with personal details", "Send an e-Transfer, gift cards or crypto", "Share a one-time code", "Install software or give remote access"] },
        { id: "notes", label: "Anything else we should know? (optional)", kind: "textarea", rows: 3 }
      ]
    },
    call: {
      label: "Scam phone call", hint: "A caller claiming to be your bank, the CRA or the police.",
      fields: [
        { id: "sender", label: "The phone number that called", kind: "text", required: true, placeholder: "+1 ..." },
        { id: "who", label: "Who did the caller say they were?", kind: "select", options: IMPERSONATING },
        { id: "asked", label: "What did the caller ask you to do?", kind: "multi", options: ["Share a one-time code", "Move money to a \"safe account\"", "Buy gift cards or crypto", "Install remote-access software", "Share my SIN or ID", "Share card details or PIN", "Pay a fine or tax debt", "Press a number to continue"] },
        { id: "message", label: "What did they say? (optional)", kind: "textarea", rows: 4 },
        { id: "notes", label: "Anything else we should know? (optional)", kind: "textarea", rows: 3 }
      ]
    },
    social: {
      label: "Fake social media, marketplace or ad", hint: "A fake profile, listing, giveaway or investment offer.",
      fields: [
        { id: "url", label: "The link to the profile, listing or ad", kind: "url", required: true, placeholder: "https://" },
        { id: "via", label: "Where did you see it?", kind: "select", options: ["Facebook", "Instagram", "TikTok", "WhatsApp or Telegram", "Marketplace or classifieds", "Dating app", "Other"] },
        { id: "who", label: "Who was it pretending to be?", kind: "select", options: IMPERSONATING },
        { id: "asked", label: "What did they ask you to do?", kind: "multi", options: ["Pay a deposit or fee in advance", "Move the chat to WhatsApp, Telegram or text", "Send an e-Transfer or gift cards", "Click a link or log in", "Share a one-time code", "Invest or send crypto", "Share personal or card details"] },
        { id: "notes", label: "Anything else we should know? (optional)", kind: "textarea", rows: 3 }
      ]
    }
  };

  const LIMITS = { url: 600, text: 200, email: 200, textarea: 2000 };
  const state = { type: "website", values: {}, asked: {} };

  // ---------- build the form for the chosen type
  function renderTypes() {
    $("rs-types").innerHTML = Object.entries(TYPES).map(([k, t]) =>
      `<label class="card card--plain row-choice rs-type"><input type="radio" name="rs-type" value="${k}" ${k === state.type ? "checked" : ""}>
        <span><b>${esc(t.label)}</b><br><span class="small">${esc(t.hint)}</span></span></label>`).join("");
    $("rs-types").querySelectorAll("input").forEach(r => r.addEventListener("change", () => { state.type = r.value; renderFields(); update(); }));
  }

  function renderFields() {
    const t = TYPES[state.type];
    $("rs-fields").innerHTML = `<h2 style="font-size:1.1rem">Fill in the blanks</h2>` + t.fields.map(f => {
      const id = "f-" + f.id, v = state.values[f.id] || "", req = f.required ? ' <span class="small">(required)</span>' : "";
      const help = f.help ? `<p class="small" id="${id}-h" style="margin-top:6px">${esc(f.help)}</p>` : "";
      const d = f.help ? ` aria-describedby="${id}-h"` : "";
      const err = `<p class="small rs-err" id="${id}-e" role="alert" hidden></p>`;
      if (f.kind === "multi") {
        return `<fieldset class="rs-fieldset"><legend class="label">${esc(f.label)}</legend>` + f.options.map((o, i) =>
          `<label class="rs-check"><input type="checkbox" data-asked="${i}" ${(state.asked[f.id] || []).includes(o) ? "checked" : ""}> <span>${esc(o)}</span></label>`).join("") + `</fieldset>`;
      }
      let input;
      if (f.kind === "select") input = `<select class="field" id="${id}" data-f="${f.id}">${f.options.map((o, i) => `<option ${v ? (v === o ? "selected" : "") : (i === 0 ? "selected" : "")}>${esc(o)}</option>`).join("")}</select>`;
      else if (f.kind === "textarea") input = `<textarea class="field" id="${id}" data-f="${f.id}" rows="${f.rows || 4}" maxlength="${LIMITS.textarea}"${d}>${esc(v)}</textarea>`;
      else input = `<input class="field" id="${id}" data-f="${f.id}" type="${f.kind === "email" ? "email" : "text"}" ${f.kind === "url" ? 'inputmode="url"' : ""} maxlength="${LIMITS[f.kind] || 200}" placeholder="${esc(f.placeholder || "")}" value="${esc(v)}" autocomplete="off" spellcheck="false"${d}>`;
      return `<div><label class="label" for="${id}">${esc(f.label)}${req}</label>${input}${help}${err}</div>`;
    }).join("");

    $("rs-fields").querySelectorAll("[data-f]").forEach(el => el.addEventListener("input", () => { state.values[el.dataset.f] = el.value; update(); }));
    const multi = t.fields.find(f => f.kind === "multi");
    $("rs-fields").querySelectorAll("[data-asked]").forEach(cb => cb.addEventListener("change", () => {
      state.asked[multi.id] = [...$("rs-fields").querySelectorAll("[data-asked]")].filter(c => c.checked).map(c => multi.options[+c.dataset.asked]);
      update();
    }));
  }

  // ---------- read the form, validate, and build the email (the relay builds the same text on its side)
  function collect() {
    const t = TYPES[state.type], out = { type: state.type, typeLabel: t.label, fields: {}, asked: [] };
    t.fields.forEach(f => {
      if (f.kind === "multi") out.asked = (state.asked[f.id] || []).slice();
      else {
        let v = (state.values[f.id] !== undefined ? state.values[f.id] : (f.kind === "select" ? f.options[0] : "")).toString().trim();
        out.fields[f.id] = v.replace(/\r\n/g, "\n").slice(0, LIMITS.textarea);
      }
    });
    return out;
  }

  function problems(r) {
    const t = TYPES[state.type], list = [];
    t.fields.forEach(f => {
      if (f.kind === "multi" || f.kind === "select") return;
      const v = r.fields[f.id] || "";
      if (f.required && !v) list.push([f.id, "This is needed so the report can be used."]);
      else if (v && f.kind === "url" && !/^https?:\/\/[^\s/$.?#][^\s]*$/i.test(v)) list.push([f.id, "Paste the full link, starting with http:// or https://"]);
      else if (v && f.kind === "email" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) list.push([f.id, "That does not look like an email address."]);
    });
    return list;
  }

  function buildSubject(r) {
    const f = r.fields;
    const key = f.url ? (f.url.replace(/^https?:\/\//i, "").split(/[/?#]/)[0]) : (f.sender || "");
    return `[SAYNO report] ${r.typeLabel}${key ? ": " + key : ""}`.slice(0, 120);
  }

  function buildBody(r) {
    const f = r.fields, L = [];
    L.push("Scam report from the SAYNO team, sent on behalf of a member of the public.");
    L.push("The reporter's name and email address are not included.", "");
    L.push(`Type: ${r.typeLabel}`);
    if (f.who && f.who !== "Not sure") L.push(`Pretending to be: ${f.who}`);
    if (f.via) L.push(`Received via: ${f.via}`);
    L.push(`Reported: ${new Date().toISOString().slice(0, 10)} (UTC)`, "");
    const ind = [];
    if (f.url) ind.push(`Link: ${f.url}`);
    if (f.sender) ind.push(`${r.type === "email" ? "Sender address" : "Phone number"}: ${f.sender}`);
    if (f.subject) ind.push(`Subject: ${f.subject}`);
    if (ind.length) L.push("Details to block or investigate:", ...ind.map(x => "  " + x), "");
    if (r.asked.length) L.push("What the scammer asked for:", ...r.asked.map(x => "  - " + x), "");
    if (f.message) L.push(r.type === "call" ? "What they said:" : "Message text:", ...f.message.split("\n").map(x => "  " + x), "");
    if (f.notes) L.push("Notes:", ...f.notes.split("\n").map(x => "  " + x), "");
    L.push(`Sent through ${location.origin}${SY.base || ""}/report-scam/`);
    return L.join("\n");
  }

  // ---------- live preview and the three send paths
  function recipientsFor(r) { return (r.fields.url || r.type === "email") ? "reportphishing@apwg.org" : ""; }

  function update() {
    const r = collect();
    $("rs-preview").textContent = `Subject: ${buildSubject(r)}\n\n${buildBody(r)}`;
    const to = recipientsFor(r);
    const body = buildBody(r).slice(0, 1700);
    $("rs-mailto").href = `mailto:${to}?subject=${encodeURIComponent(buildSubject(r))}&body=${encodeURIComponent(body)}`;
    $("rs-send").disabled = !REPORT_ENDPOINT;
    $("rs-send").title = REPORT_ENDPOINT ? "" : "Sending from the SAYNO team address is not switched on yet. Copy the report or use your email app.";
  }

  function validate() {
    document.querySelectorAll(".rs-err").forEach(e => { e.hidden = true; });
    const r = collect(), p = problems(r);
    p.forEach(([id, msg]) => { const e = $("f-" + id + "-e"); if (e) { e.textContent = msg; e.hidden = false; } });
    if (p.length) { const el = $("f-" + p[0][0]); if (el) el.focus(); }
    return !p.length;
  }

  function status(msg, bad) { const s = $("rs-status"); s.textContent = msg; s.style.color = bad ? "var(--sy-high)" : ""; }

  $("rs-copy").addEventListener("click", async () => {
    if (!validate()) return status("Please fix the highlighted blanks first.", true);
    const text = $("rs-preview").textContent;
    try { await navigator.clipboard.writeText(text); status("Copied. You can paste it into any report form or email."); }
    catch { $("rs-preview").focus(); status("Select the text in the preview and copy it yourself."); }
  });

  $("rs-mailto").addEventListener("click", e => { if (!validate()) { e.preventDefault(); status("Please fix the highlighted blanks first.", true); } });

  $("rs-send").addEventListener("click", async () => {
    if (!REPORT_ENDPOINT) return;
    if ($("rs-trap").value) return;                     // a bot filled the hidden field
    if (!validate()) return status("Please fix the highlighted blanks first.", true);
    if (!$("rs-consent").checked) return status("Please tick the box to confirm you are happy for us to send this.", true);
    const r = collect(), btn = $("rs-send");
    btn.disabled = true; status("Sending...");
    try {
      const res = await fetch(REPORT_ENDPOINT, { method: "POST", headers: { "Content-Type": "text/plain;charset=utf-8" },
        body: JSON.stringify({ type: r.type, fields: r.fields, asked: r.asked, trap: $("rs-trap").value }) });
      const j = await res.json();
      if (j && j.ok) { status("Thank you. Your report was sent from the SAYNO team address. Nothing about you was included."); return; }
      status((j && j.error) || "The report could not be sent. Please copy it or use your email app.", true);
    } catch {
      status("We could not confirm that the report was sent. Please copy it or use your email app.", true);
    } finally { btn.disabled = false; }
  });

  // ---------- start, optionally pre-filled from a result page: /report-scam/#type=website&url=https://...
  const h = new URLSearchParams(location.hash.replace(/^#/, ""));
  if (TYPES[h.get("type")]) state.type = h.get("type");
  if (h.get("url")) state.values.url = h.get("url").slice(0, LIMITS.url);
  if (h.get("text")) state.values.message = h.get("text").slice(0, LIMITS.textarea);
  renderTypes(); renderFields(); update();
  if (!REPORT_ENDPOINT) status("Sending from the SAYNO team address is not switched on yet. You can copy the report or open it in your email app.");
})();
