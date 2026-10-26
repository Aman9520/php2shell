/* PHP2Scanner — professional console. Drives the dashboard from the live API (SSE). */
(() => {
  "use strict";
  const $ = (s, e = document) => e.querySelector(s);
  const $$ = (s, e = document) => Array.from(e.querySelectorAll(s));
  const root = document.documentElement;
  let reduce = false; try { reduce = matchMedia("(prefers-reduced-motion: reduce)").matches; } catch (e) {}
  const CVE_A = "CVE-2026-109618", CVE_B = "CVE-2026-109619";

  function toast(m, k) {
    const t = document.createElement("div"); t.className = "toast" + (k ? " " + k : ""); t.textContent = m;
    $("#toasts").appendChild(t); setTimeout(() => t.remove(), 2600);
  }

  /* ---------- Theme ---------- */
  const tBtn = $("#themeBtn"), tIco = $("#themeIco");
  const sun = '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>';
  const moon = '<path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8Z"/>';
  let dark = false; try { dark = matchMedia("(prefers-color-scheme: dark)").matches; const s = localStorage.getItem("p2s-theme"); if (s) dark = s === "dark"; } catch (e) {}
  function applyTheme() { root.setAttribute("data-theme", dark ? "dark" : "light"); tIco.innerHTML = dark ? sun : moon; }
  applyTheme();
  function toggleTheme() { dark = !dark; applyTheme(); try { localStorage.setItem("p2s-theme", dark ? "dark" : "light"); } catch (e) {} }
  tBtn.addEventListener("click", toggleTheme);

  /* ---------- Single / Bulk ---------- */
  $$("#seg button").forEach(b => b.addEventListener("click", () => {
    $$("#seg button").forEach(x => x.classList.toggle("on", x === b));
    $$("[data-p]").forEach(p => p.hidden = p.dataset.p !== b.dataset.t);
  }));
  const one = $("#one"), many = $("#many");
  function activeMode() { return $("#seg button.on").dataset.t; }
  function collectTargets() {
    if (activeMode() === "single") { const v = (one.value || "").trim(); return v ? [v] : []; }
    return (many.value || "").split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  }

  /* ---------- Config + profile presets ---------- */
  const cc = $("#cc"), ccv = $("#ccv"), to = $("#to"), tov = $("#tov"), prof = $("#prof"), tg = $$(".sw input");
  cc.addEventListener("input", () => ccv.textContent = cc.value);
  to.addEventListener("input", () => tov.textContent = to.value + "s");
  const PRESETS = { Quick: { c: 25, t: 5, r: false, s: false }, Standard: { c: 12, t: 10, r: true, s: false }, Deep: { c: 6, t: 20, r: true, s: true } };
  prof.addEventListener("change", () => {
    const p = PRESETS[prof.value]; if (!p) return;
    cc.value = p.c; ccv.textContent = p.c; to.value = p.t; tov.textContent = p.t + "s";
    if (tg[0]) tg[0].checked = p.r; if (tg[1]) tg[1].checked = p.s;
    const sp = $("#setProf"); if (sp) sp.textContent = prof.value;
    toast("Profile → " + prof.value + " · presets applied", "ok");
  });
  function readConfig() {
    return { profile: prof.value, concurrency: +cc.value, timeout: +to.value,
             follow_redirects: tg[0] ? tg[0].checked : true, verify_tls: tg[1] ? tg[1].checked : false };
  }

  /* ---------- Nav ---------- */
  $$("a[data-nav]").forEach(a => a.addEventListener("click", e => {
    e.preventDefault();
    $$("a[data-nav]").forEach(x => x.classList.toggle("on", x === a));
    const map = { top: "#top", findings: "#findings", reports: "#findings" };
    const el = $(map[a.dataset.nav]); if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  }));
  const setOv = $("#setOv");
  $("#navSettings").addEventListener("click", e => { e.preventDefault(); setOv.classList.add("open"); });
  $("#setX").addEventListener("click", () => setOv.classList.remove("open"));
  setOv.addEventListener("click", e => { if (e.target === setOv) setOv.classList.remove("open"); });
  $("#setTheme").addEventListener("click", toggleTheme);

  /* ---------- Render helpers ---------- */
  const kEl = { total: $("#kpiTotal"), vuln: $("#kpiVuln"), pot: $("#kpiPot"), safe: $("#kpiSafe"), fail: $("#kpiFail") };
  const dEl = { vuln: $("#distVuln"), pot: $("#distPot"), safe: $("#distSafe"), fail: $("#distFail"), conf: $("#confVuln") };
  const gn = $("#gn"), progBar = $("#progBar");
  function renderSummary(sm) {
    kEl.total.textContent = sm.total; kEl.vuln.textContent = sm.vulnerable; kEl.pot.textContent = sm.potential || 0;
    kEl.safe.textContent = sm.safe; kEl.fail.textContent = sm.failed;
    dEl.vuln.textContent = sm.vulnerable; dEl.pot.textContent = sm.potential || 0; dEl.safe.textContent = sm.safe; dEl.fail.textContent = sm.failed;
    dEl.conf.textContent = sm.vulnerable;
    if (gn) gn.textContent = sm.risk_score || 0;
    const rank = $(".tmap-stats .v"); // leave rank text; color risk by score
    const col = (sm.risk_score || 0) >= 70 ? "var(--crit)" : (sm.risk_score || 0) >= 40 ? "var(--warn)" : (sm.risk_score || 0) > 0 ? "var(--accent)" : "var(--fg-faint)";
    if (gn) gn.style.color = col;
    const total = sm.total || 1;
    if (progBar) progBar.style.width = Math.round((sm.scanned / total) * 100) + "%";
  }

  /* ---------- Findings table ---------- */
  const tb = $("#tb"), q = $("#q");
  let sortK = "sev", sortD = -1;
  const active = new Set(["crit", "warn", "ok", "fail"]);
  const badge = (s, v) => `<span class="badge b-${s}"><span class="d"></span>${v}</span>`;
  function sevRank(r) { return r.severity === "Critical" ? 3 : r.severity === "High" ? 2 : r.state === "potential" ? 1.5 : r.state === "fail" ? 1 : 0; }
  function sevKey(r) { return r.state === "vuln" ? "crit" : r.state === "potential" ? "warn" : r.state === "fail" ? "fail" : "ok"; }
  function verdict(r) { return r.state === "vuln" ? "Vulnerable" : r.state === "potential" ? "Potential" : r.state === "fail" ? "Unreachable" : "Not exposed"; }
  const hClass = (r) => r.status_class === "http-2" ? "hc2" : r.status_class === "http-3" ? "hc3" : (r.status_class === "http-4" || r.status_class === "http-5") ? "hc4" : "hcx";
  function renderTable() {
    const text = (q.value || "").toLowerCase();
    let list = state.results.filter(r => active.has(sevKey(r)) && r.url.toLowerCase().includes(text));
    list.sort((a, b) => {
      if (sortK === "url") return a.url < b.url ? -sortD : a.url > b.url ? sortD : 0;
      let av, bv;
      if (sortK === "http") { av = +a.status || 0; bv = +b.status || 0; }
      else if (sortK === "php") { av = parseFloat(a.php) || 0; bv = parseFloat(b.php) || 0; }
      else { av = sevRank(a); bv = sevRank(b); }
      return (av - bv) * sortD;
    });
    if (!state.results.length) { tb.innerHTML = `<tr><td colspan="5"><div class="empty">No scan yet — enter a target and press Start scan.</div></td></tr>`; return; }
    if (!list.length) { tb.innerHTML = `<tr><td colspan="5"><div class="empty">No findings match these filters.</div></td></tr>`; return; }
    tb.innerHTML = list.map(r => {
      const dom = r.host || r.url;
      const key = sevKey(r);
      const fav = key === "crit" ? "var(--crit)" : key === "warn" ? "var(--warn)" : key === "fail" ? "var(--fail)" : "var(--ok)";
      const openable = r.state === "vuln" || r.state === "potential";
      return `<tr data-u="${encodeURIComponent(r.url)}" data-open="${openable}">
        <td><span class="url"><span class="fav" style="background:${fav}"></span>${dom}</span></td>
        <td><span class="mono ${hClass(r)}">${r.status}</span></td>
        <td><span class="mono">${r.php}</span></td>
        <td>${r.cvss ? `<span class="cvss ${key === "crit" ? "v-crit" : "v-warn"}">${r.cvss}</span>` : '<span class="mono" style="color:var(--fg-faint)">—</span>'}</td>
        <td>${badge(key, verdict(r))}${(r.confidence && r.confidence !== "—") ? `<span style="display:block;font-size:10px;color:var(--fg-faint);margin-top:4px;font-family:var(--mono)">${r.confidence} confidence${r.sid_anomaly ? " · anomaly" : ""}</span>` : ""}</td></tr>`;
    }).join("");
    $$("#tb tr").forEach(tr => tr.addEventListener("click", () => {
      if (tr.dataset.open === "true") openDrawer(decodeURIComponent(tr.dataset.u)); else toast("No exposure on this target", "ok");
    }));
  }
  $$("th.srt").forEach(th => th.addEventListener("click", () => {
    const k = th.dataset.k; if (sortK === k) sortD *= -1; else { sortK = k; sortD = k === "url" ? 1 : -1; } renderTable();
  }));
  q.addEventListener("input", renderTable);
  $$(".chip[data-s]").forEach(c => c.addEventListener("click", () => { c.classList.toggle("on"); const s = c.dataset.s; active.has(s) ? active.delete(s) : active.add(s); renderTable(); }));

  /* ---------- Drawer ---------- */
  const ov = $("#ov");
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }
  function worst(r) {
    let c = Object.values(r.detail || {}).filter(d => d && d.status === "vulnerable");
    if (!c.length) c = Object.values(r.detail || {}).filter(d => d && d.status === "potential");
    c.sort((a, b) => b.cvss - a.cvss); return c[0] || null;
  }
  function openDrawer(url) {
    const r = state.results.find(x => x.url === url); if (!r) return;
    const crit = r.state === "vuln"; const d = worst(r); const ev = r.evidence || {};
    $("#drBadge").className = "badge b-" + (crit ? "crit" : "warn"); $("#drBadge").innerHTML = `<span class="d"></span>${crit ? "Critical" : "Review"}`;
    $("#drTitle").textContent = crit ? "PHP2Shell — unauthenticated RCE" : "Possible PHP2Shell exposure";
    $("#drTgt").textContent = r.url;
    const box = $("#drCvssBox"); box.style.background = crit ? "var(--crit-bg)" : "var(--warn-bg)"; box.style.borderColor = crit ? "var(--crit-line)" : "var(--warn-line)";
    $("#drCvss").textContent = d ? d.cvss : "—"; $("#drCvss").style.color = crit ? "var(--crit)" : "var(--warn)";
    $("#drCve").textContent = d ? d.id : "—"; $("#drPhp").textContent = r.php;
    $("#drBranch").textContent = (ev.cms && ev.cms !== "(none detected)") ? ev.cms : (crit ? "Affected" : "Confirmed PHP");
    $("#drConf").textContent = r.confidence || ev.confidence || (crit ? "High" : "Medium");
    const methods = (ev.detection_methods && ev.detection_methods.length)
      ? ev.detection_methods.map(m => esc(m)).join(", ") : esc(ev.runtime_confirmed_via);
    // Matched CVEs list (all version-range matches, with condition notes)
    const cves = r.matched_cves || [];
    const cvesSec = $("#drCvesSec"), cvesBox = $("#drCves");
    if (cves.length) {
      cvesBox.innerHTML = cves.map(m => {
        const cm = m.condition_met;
        const tag = !m.conditional ? `<span style="color:var(--crit)">applies</span>`
          : cm === "likely" ? `<span style="color:var(--crit)">condition likely</span>`
          : cm === "unlikely" ? `<span style="color:var(--fg-faint)">condition unlikely</span>`
          : `<span style="color:var(--warn)">condition unverified</span>`;
        const cond = m.conditional ? `<div style="font-size:11.5px;color:var(--fg-faint);margin-top:3px">Requires: ${esc(m.condition)}</div>` : "";
        return `<div style="border:1px solid var(--line);border-radius:9px;padding:11px 13px">
          <div style="display:flex;justify-content:space-between;gap:10px;align-items:center">
            <span style="font-family:var(--mono);font-size:12.5px;font-weight:600">${esc(m.id)}</span>
            <span style="font-family:var(--mono);font-size:11px">CVSS ${m.cvss} · ${tag}</span>
          </div>
          <div style="font-size:12.5px;color:var(--fg-dim);margin-top:4px">${esc(m.title)}</div>${cond}
        </div>`;
      }).join("");
      cvesSec.hidden = false;
    } else { cvesSec.hidden = true; }
    const anomalyLine = (ev.sid_anomaly && ev.sid_anomaly !== "(none)") ? `\n<span class="wn">⚠ ${esc(ev.sid_anomaly)}</span>` : "";
    const conflictLine = ev.version_conflict ? `\n<span class="wn">⚠ version sources disagree (proxy may hide origin)</span>` : "";
    const wafLine = (ev.waf && ev.waf !== "(none detected)") ? `\nWAF/CDN: <span class="ac">${esc(ev.waf)}</span>` : "";
    const mitLine = ev.mitigation_note ? `\n<span class="wn">ℹ ${esc(ev.mitigation_note)}</span>` : "";
    const exploit = r.exploitability || ev.exploitability || "";
    const preconds = (ev.preconditions && ev.preconditions.length) ? ev.preconditions.map(p => esc(p)).join(", ") : "version match only";
    const exploitBlock = exploit ? `\n\n<span class="dim"># exploitability assessment</span>\nverdict: <span class="hl">${esc(exploit)}</span>\npreconditions: <span class="ac">${preconds}</span>` + ((ev.sapi && ev.sapi !== "(unknown)") ? `\nSAPI: ${esc(ev.sapi)}` : "") : "";
    $("#drCode").innerHTML = crit
      ? `<span class="dim"># response headers</span>\nHTTP/1.1 <span class="ok">${esc(ev.status)}</span>\nServer: ${esc(ev.server)}\nX-Powered-By: <span class="hl">${esc(ev.x_powered_by)}</span>${wafLine}\n\n<span class="dim"># detection · confidence ${esc(r.confidence || "")}</span>\nmethods: <span class="ac">${methods}</span>${conflictLine}${mitLine}\n\n<span class="dim"># version match</span>\n→ detected <span class="hl">${esc(ev.php_detected)}</span>\n→ affected by <span class="ac">${d ? d.id : CVE_A}</span>${exploitBlock}`
      : `<span class="dim"># response headers</span>\nHTTP/1.1 <span class="ok">${esc(ev.status)}</span>\nServer: ${esc(ev.server)}\nSet-Cookie: <span class="ac">${esc(ev.php_session_cookie)}</span>${wafLine}\n\n<span class="dim"># detection · confidence ${esc(r.confidence || "")}</span>\nmethods: <span class="ac">${methods}</span>${anomalyLine}${mitLine}\n\n<span class="dim"># runtime confirmed, version hidden</span>\n→ PHP confirmed via <span class="ac">${esc(ev.runtime_confirmed_via)}</span>\n→ <span class="hl">likely affected — manual review advised</span>${exploitBlock}`;
    ov.classList.add("open");
  }
  $("#drX").addEventListener("click", () => ov.classList.remove("open"));
  ov.addEventListener("click", e => { if (e.target === ov) ov.classList.remove("open"); });
  document.addEventListener("keydown", e => { if (e.key === "Escape") { ov.classList.remove("open"); setOv.classList.remove("open"); } });

  /* ---------- Export ---------- */
  $$(".texport button").forEach(b => b.addEventListener("click", () => {
    if (!state.scanId) { toast("Run a scan first", "crit"); return; }
    const fmt = b.dataset.f; const a = document.createElement("a");
    a.href = `/api/scan/${state.scanId}/report.${fmt === "CSV" ? "csv" : "json"}`; a.download = "";
    document.body.appendChild(a); a.click(); a.remove(); toast("Downloading " + fmt + " report", "ok");
  }));

  /* ---------- Terminal ---------- */
  const term = $("#term");
  const tcursor = document.createElement("div"); tcursor.innerHTML = '<span class="ts"></span>  <span class="cursor"></span>';
  const logClass = { info: "cy", req: "", ok: "ok", crit: "cr", warn: "wn" };
  function termLine(ts, cls, html) {
    const d = document.createElement("div"); d.className = "ln";
    d.innerHTML = `<span class="ts">${ts}</span>  <span class="${cls}">${html}</span>`;
    if (tcursor.parentNode) term.insertBefore(d, tcursor); else term.appendChild(d);
    while (term.children.length > 60) term.removeChild(term.firstChild);
    term.scrollTop = term.scrollHeight;
  }

  /* ---------- Scan lifecycle ---------- */
  const EMPTY = () => ({ total: 0, scanned: 0, pending: 0, vulnerable: 0, potential: 0, safe: 0, failed: 0, max_cvss: 0, risk_score: 0 });
  const state = { scanId: null, es: null, running: false, results: [], summary: EMPTY() };
  function nowTs() { return new Date().toTimeString().slice(0, 8); }
  function resetUI() {
    state.results = []; state.summary = EMPTY();
    renderSummary(state.summary); renderTable();
    term.innerHTML = ""; term.appendChild(tcursor);
    if (progBar) progBar.style.width = "0%";
  }
  function handle(ev) {
    if (ev.type === "log") termLine(ev.ts, logClass[ev.level] || "", ev.msg);
    else if (ev.type === "result") { state.results.push(ev.result); renderTable(); }
    else if (ev.type === "progress") { state.summary = ev.summary; renderSummary(state.summary); }
    else if (ev.type === "done") {
      state.summary = ev.summary; state.running = false; renderSummary(state.summary);
      toast(`Scan complete · ${ev.summary.vulnerable} at risk`, ev.summary.vulnerable ? "crit" : "ok");
      if (state.es) { state.es.close(); state.es = null; }
      if (progBar) progBar.style.width = "100%";
    }
  }
  async function startScan() {
    if (state.running) { toast("A scan is already running", "crit"); return; }
    const targets = collectTargets();
    if (!targets.length) { toast("Enter at least one target", "crit"); return; }
    resetUI();
    state.summary.total = targets.length; renderSummary(state.summary);
    termLine(nowTs(), "cy", `$ scanning ${targets.length} target(s) · profile ${readConfig().profile}`);
    let res;
    try {
      res = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ targets, config: readConfig() }) });
    } catch (e) { toast("Could not reach the server", "crit"); return; }
    if (!res.ok) { const j = await res.json().catch(() => ({})); toast(j.detail || "Scan request failed", "crit"); return; }
    const { scan_id } = await res.json();
    state.scanId = scan_id; state.running = true;
    toast("Scan started · " + targets.length + " target(s)", "ok");
    state.es = new EventSource(`/api/scan/${scan_id}/stream`);
    state.es.onmessage = m => { try { handle(JSON.parse(m.data)); } catch (e) {} };
  }
  async function stopScan() {
    if (!state.scanId || !state.running) { toast("No scan running", "ok"); return; }
    try { await fetch(`/api/scan/${state.scanId}/stop`, { method: "POST" }); } catch (e) {}
    toast("Stopping scan…", "crit");
  }
  function clearScan() {
    if (state.es) { state.es.close(); state.es = null; }
    state.scanId = null; state.running = false; resetUI(); toast("Cleared");
  }
  $("#startBtn").addEventListener("click", startScan);
  $("#stopBtn").addEventListener("click", stopScan);
  $("#clearBtn").addEventListener("click", clearScan);
  $("#topScan").addEventListener("click", () => { $("#top").scrollIntoView({ behavior: "smooth" }); startScan(); });
  $("#goOne").addEventListener("click", () => { $$("#seg button").forEach(x => x.classList.toggle("on", x.dataset.t === "single")); $$("[data-p]").forEach(p => p.hidden = p.dataset.p !== "single"); startScan(); });
  one.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); $("#goOne").click(); } });

  /* ---------- Global activity map (illustrative decoration — not real data) ---------- */
  (function () {
    const svg = $("#tmapSvg"); if (!svg) return;
    const NS = "http://www.w3.org/2000/svg";
    const hots = [[62,64,"US-E"],[44,94,"US-W"],[96,132,"BR"],[180,58,"EU"],[196,118,"NG"],[232,72,"RU"],[246,104,"IN"],[286,122,"SG"],[300,70,"JP"],[318,150,"AU"]];
    const hg = $("#hots", svg), ag = $("#arcs", svg), apm = $("#apm");
    hots.forEach(([x, y, l]) => { const g = document.createElementNS(NS, "g"); g.setAttribute("class", "hot"); g.setAttribute("transform", `translate(${x},${y})`); g.innerHTML = `<circle class="hr" r="2.6"></circle><circle class="hd" r="2.2"></circle><text class="hlbl" x="5" y="2.5">${l}</text>`; hg.appendChild(g); });
    let c = 138; function tick() { c += Math.round((Math.random() - .45) * 14); c = Math.max(90, Math.min(214, c)); if (apm) apm.textContent = c; }
    function arc() {
      const a = hots[Math.floor(Math.random() * hots.length)]; let b = hots[Math.floor(Math.random() * hots.length)]; if (b === a) b = hots[(hots.indexOf(a) + 3) % hots.length];
      const [x1, y1] = a, [x2, y2] = b, mx = (x1 + x2) / 2, my = (y1 + y2) / 2 - Math.abs(x2 - x1) * .35 - 16;
      const p = document.createElementNS(NS, "path"); p.setAttribute("class", "arc"); p.setAttribute("d", `M${x1} ${y1} Q${mx} ${my} ${x2} ${y2}`); ag.appendChild(p);
      const len = p.getTotalLength(); p.style.strokeDasharray = `9 ${len}`;
      const an = p.animate([{ strokeDashoffset: len }, { strokeDashoffset: -9 }], { duration: 1150, easing: "ease-out" }); an.onfinish = () => p.remove();
      setTimeout(() => { const r = document.createElementNS(NS, "circle"); r.setAttribute("class", "hitring"); r.setAttribute("cx", x2); r.setAttribute("cy", y2); r.setAttribute("r", "2"); ag.appendChild(r); try { const ra = r.animate([{ r: 2, opacity: .9 }, { r: 9, opacity: 0 }], { duration: 600, easing: "ease-out" }); ra.onfinish = () => r.remove(); } catch (e) { setTimeout(() => r.remove(), 600); } }, 960);
    }
    tick(); setInterval(tick, 1400); if (!reduce) setInterval(arc, 720);
  })();

  /* ---------- Boot ---------- */
  resetUI();
})();
