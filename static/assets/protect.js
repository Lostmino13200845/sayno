// Protect yourself: the checklist (progress saved in this browser) and the private password breach check.
(() => {
  const $ = id => document.getElementById(id);
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const GUIDE = [
   ['Passwords & accounts', [
    ['Use a password manager', 'Bitwarden, 1Password, KeePassXC or your browser\'s manager. Let it generate every password.'],
    ['One unique password per site', 'When one site is breached, reused passwords let attackers into all your other accounts ("credential stuffing").'],
    ['Turn on 2-step verification everywhere', 'Prefer an authenticator app, passkey or security key over SMS codes. Start with e-mail, bank and social media.'],
    ['Switch to passkeys where offered', 'Google, Microsoft, Apple, Amazon, PayPal support them — passkeys cannot be phished.'],
    ['Secure your e-mail account first', 'Your inbox resets all other passwords. Strong password + 2FA + check recovery phone/e-mail and forwarding rules.'],
    ['Check your e-mail on haveibeenpwned.com', 'Change passwords for any breached service and subscribe to breach notifications.'],
   ]],
   ['Messages, links & calls', [
    ['Never share one-time codes', 'No bank, company or "support agent" will ever ask for a code sent to you. Anyone who asks is a scammer.'],
    ['Go to the official site yourself', 'Don\'t use links or phone numbers in unexpected messages — type the address or use the official app.'],
    ['Check the real link before clicking', 'Hover (desktop) or long-press (phone). Look at the domain just before the first single "/".'],
    ['Don\'t open unexpected attachments', 'Especially .zip, .html, .iso, .exe, Office files asking to "enable content", and QR codes in e-mails.'],
    ['Be suspicious of urgency and secrecy', 'Pressure to act "now", threats, prizes or "don\'t tell anyone" are the core scam tactics.'],
    ['Verify money requests by calling back', 'For family emergencies, invoices with new bank details, or a "boss" asking for gift cards — call a known number.'],
   ]],
   ['Devices', [
    ['Turn on automatic updates', 'Windows Update, browser, phone OS and apps. Most breaches exploit already-patched holes.'],
    ['Keep antivirus on', 'Microsoft Defender is built in — make sure real-time protection and "SmartScreen" are enabled.'],
    ['Encrypt your devices', 'Windows: BitLocker / Device Encryption. Phones: set a PIN (encryption is automatic).'],
    ['Lock screens & strong device PIN', 'Auto-lock after a short time; 6+ digit PIN or biometrics.'],
    ['Install apps only from official stores', 'Remove apps and browser extensions you don\'t use; review app permissions.'],
    ['Never give remote access to strangers', 'Uninstall AnyDesk/TeamViewer if you didn\'t install them for a trusted purpose.'],
   ]],
   ['Network', [
    ['Change your router\'s admin password', 'And update its firmware. Use WPA2/WPA3 Wi-Fi encryption with a strong Wi-Fi password.'],
    ['Avoid banking on public Wi-Fi', 'Use mobile data or a reputable VPN on public networks.'],
   ]],
   ['Money & identity', [
    ['Enable bank & card transaction alerts', 'You\'ll notice fraud within minutes instead of weeks.'],
    ['Add a SIM-swap PIN with your mobile carrier', 'Stops criminals from moving your number to their SIM and receiving your codes.'],
    ['Consider a credit freeze', 'Free in many countries; prevents new credit being opened in your name.'],
    ['Share less personal data', 'Limit birthdate, address, phone and ID photos online; use e-mail aliases for sign-ups.'],
   ]],
   ['Backups', [
    ['Back up important files (3-2-1 rule)', '3 copies, 2 different media, 1 offline/off-site — protects against ransomware and theft.'],
    ['Test restoring a backup', 'A backup you\'ve never restored is a hope, not a backup.'],
   ]],
  ];

  function renderGuide() {
    let done = {}; try { done = JSON.parse(localStorage.getItem("ss-guide") || "{}"); } catch {}
    let html = "", total = 0;
    GUIDE.forEach(([sec, items]) => {
      html += `<h3>${esc(sec)}</h3>`;
      items.forEach(([t, d]) => {
        total++; const id = sec + "|" + t;
        html += `<label><input type="checkbox" data-id="${esc(id)}" ${done[id] ? "checked" : ""}><span><b>${esc(t)}</b><br><span class="muted">${esc(d)}</span></span></label>`;
      });
    });
    $("checklist").innerHTML = html;
    const update = () => {
      const n = [...document.querySelectorAll("#checklist input")].filter(b => b.checked).length;
      $("prog").style.width = (100 * n / total) + "%";
      $("prog-txt").textContent = `${n} of ${total} done`;
    };
    document.querySelectorAll("#checklist input").forEach(b => b.addEventListener("change", () => {
      done[b.dataset.id] = b.checked; try { localStorage.setItem("ss-guide", JSON.stringify(done)); } catch {}
      update();
    }));
    update();
  }
  renderGuide();

  // password check: the password is hashed here; only the first 5 characters of the hash are sent
  $("pw-form").addEventListener("submit", async e => {
    e.preventDefault();
    const pw = $("pw").value; if (!pw) return;
    const out = $("pw-out"); out.style.color = ""; out.textContent = "Checking...";
    try {
      const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(pw));
      const hex = [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
      const res = await fetch("https://api.pwnedpasswords.com/range/" + hex.slice(0, 5), { headers: { "Add-Padding": "true" } });
      if (!res.ok) throw new Error("the lookup service answered " + res.status);
      const line = (await res.text()).split(/\r?\n/).find(l => l.startsWith(hex.slice(5)));
      const n = line ? parseInt(line.split(":")[1]) : 0;
      if (n) { out.style.color = "var(--sy-high)"; out.textContent = `This password appeared ${n.toLocaleString()} times in data breaches. Stop using it everywhere and change it now.`; }
      else { out.style.color = "var(--sy-safe)"; out.textContent = "Not found in known breaches. Still: make it long, unique per site, and stored in a password manager."; }
    } catch (err) { out.style.color = "var(--sy-high)"; out.textContent = "The check could not finish: " + err.message; }
    $("pw").value = "";
  });
})();
