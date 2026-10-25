/* PHP2Scanner — front-end controller. Drives the dashboard from the live API. */
(() => {
  "use strict";
  const root = document.documentElement;
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
  let reduce = false; try { reduce = matchMedia("(prefers-reduced-motion: reduce)").matches; } catch (e) {}

  const CVE_A = "CVE-2026-109618", CVE_B = "CVE-2026-109619";

  /* ---------------- Themes ---------------- */
  const STYLES = [
    ["s1","Neon Grid","#2bffb0"],["s2","Glass Aurora","#9f8bff"],["s3","Brutalist Mono","#111111"],["s4","SOC Enterprise","#2563eb"],
    ["s5","Amber CRT","#ffb000"],["s6","Crimson Threat","#ff2d55"],["s7","Nordic Minimal","#5c7b6e"],["s8","Synthwave Violet","#ff3df0"],
    ["s9","Matrix","#27ff5e"],["s10","Sky Material","#2962ff"],["s11","Blueprint","#38bdf8"],["s12","Ember Dark","#ff7a18"],
    ["s13","Mint Terminal","#0f9d7a"],["s14","Tokyo Night","#7aa2f7"],["s15","Mono Slate","#4c8dff"],["s16","Solar Flare","#ff9500"],
    ["s17","Deep Ocean","#1fd5c7"],["s18","Rose Quartz","#c04a6e"],["s19","Carbon Fiber","#5aa9e6"],["s20","Cyber Lime","#c6ff00"],
  ];
  const popGrid = $("#popGrid"), themePop = $("#themePop"), swDot = $("#swDot"), themeBtn = $("#themeBtn");
  popGrid.innerHTML = STYLES.map(([id, name, sw]) => `<button class="pop-item" data-id="${id}"><span class="sw" style="background:${sw}"></span>${name}</button>`).join("");
  let activeStyle = "s1";
  try { const v = localStorage.getItem("p2s-style"); if (v) activeStyle = v; } catch (e) {}
  function setStyle(id, announce) {
    activeStyle = id; root.setAttribute("data-style", id);
    try { localStorage.setItem("p2s-style", id); } catch (e) {}
    const meta = STYLES.find(s => s[0] === id); if (!meta) return;
    swDot.style.background = meta[2];
    $$(".pop-item", popGrid).forEach(b => b.classList.toggle("active", b.dataset.id === id));
    if (announce) toast("Theme → " + meta[1], "ok");
  }
  setStyle(activeStyle, false);
  themeBtn.addEventListener("click", e => { e.stopPropagation(); themePop.hidden = !themePop.hidden; });
  $$(".pop-item", popGrid).forEach(b => b.addEventListener("click", () => { setStyle(b.dataset.id, true); themePop.hidden = true; }));
  document.addEventListener("click", e => { if (!themePop.hidden && !themePop.contains(e.target) && e.target !== themeBtn) themePop.hidden = true; });

  /* ---------------- Toast / status ---------------- */
  const sbMid = $("#sbMid"), toastsEl = $("#toasts");
  function toast(msg, kind) {
    if (sbMid) sbMid.textContent = msg;
    const t = document.createElement("div"); t.className = "toast" + (kind ? " " + kind : "");
    const ico = kind === "crit" ? '<path d="M10.3 3.3 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.3a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4M12 17h.01"/>'
      : kind === "ok" ? '<path d="m20 6-11 11-5-5"/>'
      : '<circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/>';
    t.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ico}</svg><span>${msg}</span>`;
    toastsEl.appendChild(t);
    setTimeout(() => { t.classList.add("out"); setTimeout(() => t.remove(), 220); }, 2600);
  }

  /* ---------------- Tabs ---------------- */
  const tabsEl = $("#tabs");
  function setTab(name) {
    $$("button", tabsEl).forEach(b => b.classList.toggle("active", b.dataset.tab === name));
    $$("[data-panel]").forEach(p => p.hidden = p.dataset.panel !== name);
  }
  $$("button", tabsEl).forEach(b => b.addEventListener("click", () => setTab(b.dataset.tab)));

  /* ---------------- Config ---------------- */
  const conc = $("#cfgConc"), concV = $("#cfgConcV"), to = $("#cfgTo"), toV = $("#cfgToV"), profile = $("#cfgProfile");
  conc.addEventListener("input", () => concV.textContent = conc.value);
  to.addEventListener("input", () => toV.textContent = to.value + "s");
  const toggles = $$(".toggle input");
  function readConfig() {
    return {
      profile: profile.value,
      concurrency: +conc.value,
      timeout: +to.value,
      follow_redirects: toggles[0] ? toggles[0].checked : true,
      verify_tls: toggles[1] ? toggles[1].checked : false,
    };
  }

  /* ---------------- Single / Bulk ---------------- */
  const modeSeg = $("#modeSeg");
  $$("button", modeSeg).forEach(b => b.addEventListener("click", () => {
    $$("button", modeSeg).forEach(x => x.classList.toggle("active", x === b));
    $$("[data-mode-panel]").forEach(p => p.hidden = p.dataset.modePanel !== b.dataset.mode);
  }));
  const singleUrl = $("#singleUrl"), urls = $("#urls");
  $$(".sr-chip", $("#singleRecent")).forEach(c => c.addEventListener("click", () => { singleUrl.value = c.dataset.u; singleUrl.focus(); }));
  function activeMode() { return $("button.active", modeSeg).dataset.mode; }
  function collectTargets() {
    if (activeMode() === "single") {
      const v = (singleUrl.value || "").trim();
      return v ? [v] : [];
    }
    return (urls.value || "").split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  }

  /* ---------------- Dropzone / file import ---------------- */
  const dz = $("#dropzone");
  if (dz) {
    const loadFile = (file) => {
      if (!file) return;
      const rd = new FileReader();
      rd.onload = () => {
        urls.value = String(rd.result || "").split(/\r?\n/).map(s => s.trim()).filter(Boolean).join("\n");
        $$("button", modeSeg).forEach(x => x.classList.toggle("active", x.dataset.mode === "bulk"));
        $$("[data-mode-panel]").forEach(p => p.hidden = p.dataset.modePanel !== "bulk");
        toast("Loaded " + urls.value.split("\n").filter(Boolean).length + " targets from file", "ok");
      };
      rd.readAsText(file);
    };
    ["dragenter", "dragover"].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add("drag"); }));
    ["dragleave"].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove("drag"); }));
    dz.addEventListener("drop", e => { e.preventDefault(); dz.classList.remove("drag"); loadFile(e.dataTransfer.files[0]); });
    dz.addEventListener("click", () => {
      const inp = document.createElement("input"); inp.type = "file"; inp.accept = ".txt,text/plain";
      inp.onchange = () => loadFile(inp.files[0]); inp.click();
    });
  }

  /* ---------------- Rendering helpers ---------------- */
  const stats = {
    total: $('[data-count]'), // replaced below with explicit map
  };
  const statEls = {};
  $$(".stat").forEach(s => {
    const cls = Array.from(s.classList).find(c => c.startsWith("c-"));
    if (cls) statEls[cls.slice(2)] = $(".val", s);
  });
  const sparkEls = {};
  $$(".stat").forEach(s => { const cls = Array.from(s.classList).find(c => c.startsWith("c-")); if (cls) sparkEls[cls.slice(2)] = $(".spark i", s); });

  const progBar = $("#progBar"), progPct = $("#progPct"), findCount = $("#findCount"), threatVal = $("#threatVal");
  const threatBars = $$(".threat .bars i");

  function setProgress(summary) {
    const total = summary.total || 1;
    const pct = Math.round((summary.scanned / total) * 100);
    if (progBar) progBar.style.width = pct + "%";
    if (progPct) progPct.textContent = pct + "%";
  }

  function renderStats(summary) {
    const map = { total: summary.total, scanned: summary.scanned, vuln: summary.vulnerable, safe: summary.safe, fail: summary.failed };
    for (const k in map) if (statEls[k]) statEls[k].textContent = map[k];
    const t = summary.total || 1;
    if (sparkEls.total) sparkEls.total.style.width = "100%";
    if (sparkEls.scanned) sparkEls.scanned.style.width = Math.round(summary.scanned / t * 100) + "%";
    if (sparkEls.vuln) sparkEls.vuln.style.width = Math.round(summary.vulnerable / t * 100) + "%";
    if (sparkEls.safe) sparkEls.safe.style.width = Math.round(summary.safe / t * 100) + "%";
    if (sparkEls.fail) sparkEls.fail.style.width = Math.round(summary.failed / t * 100) + "%";
    if (findCount) findCount.textContent = summary.vulnerable;
  }

  /* gauge */
  const gaugeVal = $("#gaugeVal"), gaugeScore = $("#gaugeScore");
  const gaugeRank = $(".gauge-center .rank"), gaugeScoreEl = $(".gauge-center .score");
  function renderGauge(summary) {
    const score = summary.risk_score || 0;
    const col = score >= 70 ? "var(--crit)" : score >= 40 ? "var(--warn)" : score > 0 ? "var(--accent-cyan)" : "var(--fg-faint)";
    if (gaugeVal) { gaugeVal.setAttribute("stroke-dasharray", score + " 100"); gaugeVal.style.stroke = col; }
    if (gaugeScore) gaugeScore.textContent = score;
    if (gaugeScoreEl) gaugeScoreEl.style.color = col;
    if (gaugeRank) {
      gaugeRank.textContent = score >= 80 ? "Severe" : score >= 60 ? "High Risk" : score >= 30 ? "Guarded" : score > 0 ? "Low" : "No Risk";
      gaugeRank.style.color = col;
    }
    // header threat meter
    if (threatVal) {
      const lvl = score >= 70 ? "Elevated" : score >= 40 ? "Guarded" : score > 0 ? "Low" : "None";
      threatVal.textContent = lvl; threatVal.style.color = col;
    }
    threatBars.forEach((b, i) => b.classList.toggle("on", (i + 1) * 20 <= score));
  }

  /* donut */
  const donutCircles = $$(".donut svg circle"); // [track, crit, warn, ok, fail]
  const donutN = $(".donut-center .n");
  function renderDonut(summary) {
    const total = summary.total || 1, C = 276.46; // 2*pi*44
    const seg = (n) => (n / total) * C;
    const parts = [summary.vulnerable, summary.potential || 0, summary.safe, summary.failed];
    let offset = 0;
    [1, 2, 3, 4].forEach((ci, i) => {
      const c = donutCircles[ci]; if (!c) return;
      const len = seg(parts[i]);
      c.setAttribute("stroke-dasharray", `${len.toFixed(1)} ${(C - len).toFixed(1)}`);
      c.setAttribute("stroke-dashoffset", (-offset).toFixed(1));
      offset += len;
    });
    if (donutN) donutN.textContent = summary.vulnerable;
    const legendVals = $$(".legend-item b");
    if (legendVals.length >= 5) {
      legendVals[0].textContent = summary.vulnerable;
      legendVals[1].textContent = summary.potential || 0;
      legendVals[2].textContent = summary.safe;
      legendVals[3].textContent = summary.failed;
      legendVals[4].textContent = summary.pending;
    }
  }

  /* throughput chart */
  const W = 300, H = 130, N = 24;
  let chartData = new Array(N).fill(0);
  const area = $("#chartArea"), line = $("#chartLine"), dot = $("#chartDot"), rpsNow = $("#rpsNow");
  function drawChart() {
    const max = Math.max(10, ...chartData);
    const pts = chartData.map((v, i) => [(i / (N - 1)) * W, H - (v / max) * (H - 8) - 4]);
    const lp = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
    if (line) line.setAttribute("d", lp);
    if (area) area.setAttribute("d", lp + ` L${W} ${H} L0 ${H} Z`);
    const last = pts[pts.length - 1];
    if (dot) { dot.setAttribute("cx", last[0]); dot.setAttribute("cy", last[1]); }
    if (rpsNow) rpsNow.textContent = chartData[chartData.length - 1];
  }
  let chartTimer = null, lastScanned = 0;
  function startChart() {
    stopChart(); lastScanned = 0; chartData = new Array(N).fill(0); drawChart();
    if (reduce) return;
    chartTimer = setInterval(() => {
      const delta = state.summary.scanned - lastScanned; lastScanned = state.summary.scanned;
      chartData.push(delta); chartData.shift(); drawChart();
    }, 1000);
  }
  function stopChart() { if (chartTimer) { clearInterval(chartTimer); chartTimer = null; } }

  /* ---------------- Findings table ---------------- */
  const tbody = $("#tbody"), search = $("#search");
  let sortKey = "sev", sortDir = -1;
  const sevFilter = new Set(["crit", "warn", "ok", "fail"]);

  const cveBadge = (t) => t === "vulnerable"
    ? '<span class="badge b-crit"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.3 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.3a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4M12 17h.01"/></svg>Vulnerable</span>'
    : t === "potential"
    ? '<span class="badge b-warn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4M12 17h.01"/><circle cx="12" cy="12" r="9"/></svg>Possibly</span>'
    : t === "not_exposed"
    ? '<span class="badge b-ok"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m20 6-11 11-5-5"/></svg>Not exposed</span>'
    : '<span class="badge b-fail">—</span>';
  const stateBadge = (s) => s === "vuln"
    ? '<span class="badge b-crit"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.3 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.3a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4M12 17h.01"/></svg>At risk</span>'
    : s === "potential"
    ? '<span class="badge b-warn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>Potential</span>'
    : s === "safe"
    ? '<span class="badge b-ok"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z"/></svg>Secure</span>'
    : '<span class="badge b-warn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M18 6 6 18M6 6l12 12"/></svg>Failed</span>';
  function sevRank(r) { return r.severity === "Critical" ? 3 : r.severity === "High" ? 2 : r.state === "potential" ? 1.5 : r.state === "fail" ? 1 : 0; }
  function sevKey(r) { return r.severity === "Critical" ? "crit" : r.severity === "High" ? "warn" : r.state === "potential" ? "warn" : r.state === "fail" ? "fail" : "ok"; }
  function sevPill(r) {
    if (r.state === "vuln") return `<span class="sev-pill ${r.severity === "Critical" ? "sev-critical" : "sev-high"}">● ${r.cvss} ${r.severity === "Critical" ? "Crit" : "High"}</span>`;
    if (r.state === "potential") return '<span class="sev-pill sev-high">● review</span>';
    return '<span class="sev-pill sev-none">—</span>';
  }

  function renderTable() {
    const q = (search.value || "").toLowerCase();
    let list = state.results.filter(r => sevFilter.has(sevKey(r)) && r.url.toLowerCase().includes(q));
    list.sort((a, b) => {
      if (sortKey === "url") return a.url < b.url ? -sortDir : a.url > b.url ? sortDir : 0;
      let av, bv;
      if (sortKey === "http") { av = +a.status || 0; bv = +b.status || 0; }
      else if (sortKey === "php") { av = parseFloat(a.php) || 0; bv = parseFloat(b.php) || 0; }
      else { av = sevRank(a); bv = sevRank(b); }
      return (av - bv) * sortDir;
    });
    if (!state.results.length) {
      tbody.innerHTML = `<tr><td colspan="7"><div class="no-rows">No scan yet — enter targets and press Start Scan.</div></td></tr>`;
      return;
    }
    if (!list.length) {
      tbody.innerHTML = `<tr><td colspan="7"><div class="no-rows">No targets match these filters.</div></td></tr>`;
      return;
    }
    tbody.innerHTML = list.map(r => {
      const rowCls = r.state === "vuln" ? "row-crit" : r.state === "potential" ? "row-scan" : r.state === "safe" ? "row-ok" : "row-fail";
      const dom = r.host || r.url;
      const lock = r.https ? '<span class="lock">🔒</span> ' : '<span class="nolock">⚠</span> ';
      const openable = r.state === "vuln" || r.state === "potential";
      return `<tr class="${rowCls}" data-url="${encodeURIComponent(r.url)}" data-open="${openable}">
        <td class="url-cell">${lock}${dom}</td>
        <td class="http-code ${r.status_class}">${r.status}</td>
        <td class="mono">${r.php}</td>
        <td class="cve-cell">${cveBadge(r.findings[CVE_A])}</td>
        <td class="cve-cell">${cveBadge(r.findings[CVE_B])}</td>
        <td>${sevPill(r)}</td>
        <td>${stateBadge(r.state)}</td></tr>`;
    }).join("");
    $$("tr", tbody).forEach(tr => tr.addEventListener("click", () => {
      if (tr.dataset.open === "true") openDrawer(decodeURIComponent(tr.dataset.url));
      else toast("No findings for this target", "ok");
    }));
  }
  $$("th.sortable").forEach(th => th.addEventListener("click", () => {
    const k = th.dataset.sort;
    if (sortKey === k) sortDir *= -1; else { sortKey = k; sortDir = k === "url" ? 1 : -1; }
    $$("th.sortable").forEach(t => { t.classList.toggle("sorted", t === th); const a = $(".arrow", t); if (a) a.textContent = t === th ? (sortDir > 0 ? "↑" : "↓") : "↕"; });
    renderTable();
  }));
  search.addEventListener("input", renderTable);
  $$(".sev-chip", $("#sevChips")).forEach(c => c.addEventListener("click", () => {
    c.classList.toggle("on"); const s = c.dataset.sev;
    if (sevFilter.has(s)) sevFilter.delete(s); else sevFilter.add(s); renderTable();
  }));
  const defTh = $('th[data-sort="sev"]'); if (defTh) { defTh.classList.add("sorted"); const a = $(".arrow", defTh); if (a) a.textContent = "↓"; }

  /* ---------------- Timeline ---------------- */
  const timelineEl = $("#timeline");
  const nodeIco = {
    start: '<circle cx="12" cy="12" r="9"/>', ok: '<path d="m20 6-11 11-5-5"/>',
    crit: '<path d="M12 9v4M12 17h.01M10.3 3.3 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.3a2 2 0 0 0-3.4 0Z"/>',
    warn: '<path d="M18 6 6 18M6 6l12 12"/>', info: '<path d="M21 12a9 9 0 1 1-6.2-8.6"/>',
  };
  function renderTimeline() {
    if (!state.timeline.length) {
      timelineEl.innerHTML = `<div class="no-rows">The scan timeline appears here once a scan runs.</div>`;
      return;
    }
    timelineEl.innerHTML = state.timeline.map(ev => {
      const title = ev.k === "crit" ? `<b class="crit">${ev.title}</b>` : ev.k === "ok" ? `<b class="ok">${ev.title}</b>` : ev.title;
      return `<div class="tl-item"><div class="tl-node ${ev.k}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">${nodeIco[ev.k]}</svg></div>
        <div class="tl-body"><div class="tl-when">${ev.ts}</div><div class="tl-title">${title}</div>${ev.desc ? `<div class="tl-desc">${ev.desc}</div>` : ""}</div></div>`;
    }).join("");
  }

  /* ---------------- Terminal ---------------- */
  const term = $("#term");
  const termCursor = document.createElement("div");
  termCursor.innerHTML = '<span class="ts"></span>  <span class="cursor"></span>';
  function termLine(ts, cls, txt) {
    const d = document.createElement("div"); d.className = "ln";
    d.innerHTML = `<span class="ts">${ts}</span>  <span class="${cls}">${txt}</span>`;
    if (termCursor.parentNode) term.insertBefore(d, termCursor); else term.appendChild(d);
    while (term.children.length > 10) term.removeChild(term.firstChild);
    term.scrollTop = term.scrollHeight;
  }
  const logClass = { info: "cy", req: "", ok: "ok", crit: "cr", warn: "wn" };

  /* ---------------- Drawer ---------------- */
  const overlay = $("#overlay"), drawerBody = $("#drawerBody"), drawerTabs = $("#drawerTabs");
  let curFinding = null, drawerTab = "overview";
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }
  function worstDetail(r) {
    let cands = Object.values(r.detail || {}).filter(d => d && d.status === "vulnerable");
    if (!cands.length) cands = Object.values(r.detail || {}).filter(d => d && d.status === "potential");
    cands.sort((a, b) => b.cvss - a.cvss); return cands[0] || null;
  }
  const drawerContent = {
    overview(r) {
      const d = worstDetail(r) || {};
      const ev = r.evidence || {};
      return `<div class="score-row"><div class="score-ring"><svg width="74" height="74" viewBox="0 0 74 74"><circle cx="37" cy="37" r="30" fill="none" stroke="var(--surface-3)" stroke-width="8"/><circle cx="37" cy="37" r="30" fill="none" stroke="var(--crit)" stroke-width="8" stroke-linecap="round" pathLength="100" stroke-dasharray="${(d.cvss || 0) * 10} 100"/></svg><div class="c">${d.cvss || "—"}</div></div>
        <div class="meta-grid" style="flex:1">
          <div class="meta-item"><div class="k">CVE ID</div><div class="v">${esc(d.id || "—")}</div></div>
          <div class="meta-item"><div class="k">PHP</div><div class="v">${esc(r.php)}</div></div>
          <div class="meta-item"><div class="k">Vector</div><div class="v">${esc(d.vector || "—")}</div></div>
          <div class="meta-item"><div class="k">Fixed in</div><div class="v">${esc(d.fixed || "—")}</div></div>
        </div></div>
        <p style="font-size:13px;color:var(--fg-dim);line-height:1.6;margin:0">The target advertises an affected PHP build (${esc(ev.php_detected || r.php)}). Detection is based on version fingerprinting against the signature database; no payload was sent to the host.</p>`;
    },
    request(r) {
      return `<h4 class="dt-h">Fingerprint request</h4><div class="evidence"><span class="cy">GET</span> ${esc(r.url)} HTTP/1.1
Host: ${esc(r.host)}
User-Agent: php2scanner/1.0
Accept: */*</div>`;
    },
    response(r) {
      const ev = r.evidence || {};
      if (r.state === "fail") return `<h4 class="dt-h">Response</h4><div class="evidence"><span class="hl">${esc(ev.error || "request failed")}</span></div>`;
      return `<h4 class="dt-h">Observed response</h4><div class="evidence"><span class="dim"># headers</span>
HTTP/1.1 <span class="hl">${esc(ev.status)}</span>
Server: ${esc(ev.server)}
X-Powered-By: <span class="hl">${esc(ev.x_powered_by)}</span>

<span class="dim"># version match</span>
→ detected PHP <span class="hl">${esc(ev.php_detected)}</span>
→ within affected range for this signature</div>`;
    },
    fix(r) {
      const d = worstDetail(r);
      if (!d) return `<div class="no-rows">No remediation — target not vulnerable.</div>`;
      return `<h4 class="dt-h">Remediation</h4><div class="remediation">${d.remediation.map((s, i) => `<div class="step"><span class="num">${i + 1}</span><span>${esc(s)}</span></div>`).join("")}</div>`;
    },
    refs(r) {
      const d = worstDetail(r);
      if (!d) return `<div class="no-rows">No references.</div>`;
      return `<h4 class="dt-h">References</h4><div style="display:flex;gap:8px;flex-wrap:wrap">${d.references.map(ref => `<a class="ref-link" href="${esc(ref.url)}" target="_blank" rel="noopener">${esc(ref.label)} <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M7 17 17 7M7 7h10v10"/></svg></a>`).join("")}</div>`;
    },
  };
  function renderDrawer() { drawerBody.innerHTML = (drawerContent[drawerTab] || drawerContent.overview)(curFinding); }
  function openDrawer(url) {
    curFinding = state.results.find(r => r.url === url); if (!curFinding) return;
    const d = worstDetail(curFinding);
    $("#dTitle").textContent = d ? d.title : "Finding";
    $("#dTarget").textContent = curFinding.url;
    $("#dSevText").textContent = curFinding.severity;
    const tag = $("#dSevTag");
    tag.style.background = curFinding.severity === "Critical" ? "var(--crit-bg)" : "var(--warn-bg)";
    tag.style.color = curFinding.severity === "Critical" ? "var(--crit)" : "var(--warn)";
    drawerTab = "overview"; $$("button", drawerTabs).forEach(b => b.classList.toggle("active", b.dataset.dt === "overview"));
    renderDrawer(); overlay.classList.add("open");
  }
  function closeDrawer() { overlay.classList.remove("open"); }
  $$("button", drawerTabs).forEach(b => b.addEventListener("click", () => { drawerTab = b.dataset.dt; $$("button", drawerTabs).forEach(x => x.classList.toggle("active", x === b)); renderDrawer(); }));
  $("#closeBtn").addEventListener("click", closeDrawer);
  overlay.addEventListener("click", e => { if (e.target === overlay) closeDrawer(); });

  /* ---------------- Export ---------------- */
  const exportMenu = $("#exportMenu"), exportBtn = $("#exportBtn");
  exportBtn.addEventListener("click", e => { e.stopPropagation(); exportMenu.hidden = !exportMenu.hidden; });
  document.addEventListener("click", e => { if (!exportMenu.hidden && !exportMenu.contains(e.target) && e.target !== exportBtn) exportMenu.hidden = true; });
  $$("button", exportMenu).forEach(b => b.addEventListener("click", () => {
    exportMenu.hidden = true;
    if (!state.scanId) { toast("Run a scan first", "crit"); return; }
    const fmt = b.dataset.fmt;
    const url = `/api/scan/${state.scanId}/report.${fmt === "CSV" ? "csv" : "json"}`;
    if (fmt === "HTML report") { toast("HTML report export is coming soon", "ok"); return; }
    const a = document.createElement("a"); a.href = url; a.download = ""; document.body.appendChild(a); a.click(); a.remove();
    toast("Downloading " + fmt + " report", "ok");
  }));

  /* ---------------- Scan state + lifecycle ---------------- */
  const state = {
    scanId: null, es: null, running: false,
    results: [], timeline: [],
    summary: { total: 0, scanned: 0, pending: 0, vulnerable: 0, potential: 0, safe: 0, failed: 0, max_cvss: 0, risk_score: 0 },
  };

  function resetUI() {
    state.results = []; state.timeline = [];
    state.summary = { total: 0, scanned: 0, pending: 0, vulnerable: 0, potential: 0, safe: 0, failed: 0, max_cvss: 0, risk_score: 0 };
    term.innerHTML = ""; term.appendChild(termCursor);
    renderStats(state.summary); setProgress(state.summary); renderGauge(state.summary);
    renderDonut(state.summary); renderTable(); renderTimeline();
  }

  function handleEvent(ev) {
    if (ev.type === "log") {
      termLine(ev.ts, logClass[ev.level] || "", ev.msg);
    } else if (ev.type === "result") {
      const r = ev.result; state.results.push(r);
      // timeline entry
      if (r.state === "vuln") {
        const d = worstDetail(r);
        state.timeline.push({ k: "crit", ts: nowTs(), title: `${d ? d.id : "Finding"} confirmed`, desc: `${r.host} · ${d ? d.title : ""} · CVSS ${d ? d.cvss : ""}` });
      } else if (r.state === "fail") {
        state.timeline.push({ k: "warn", ts: nowTs(), title: `${r.host} unreachable`, desc: (r.evidence && r.evidence.error) || "request failed" });
      } else if (r.state === "potential") {
        state.timeline.push({ k: "warn", ts: nowTs(), title: `${r.host} possibly exposed`, desc: `PHP confirmed via ${(r.evidence && r.evidence.runtime_confirmed_via) || "runtime signal"} · version hidden` });
      } else {
        state.timeline.push({ k: "ok", ts: nowTs(), title: `${r.host} secure`, desc: `PHP ${r.php} · no exposure` });
      }
      renderTable(); renderTimeline();
    } else if (ev.type === "progress") {
      state.summary = ev.summary;
      renderStats(state.summary); setProgress(state.summary); renderGauge(state.summary); renderDonut(state.summary);
    } else if (ev.type === "done") {
      state.summary = ev.summary; state.running = false; stopChart();
      renderStats(state.summary); setProgress(state.summary); renderGauge(state.summary); renderDonut(state.summary);
      toast(`Scan complete · ${ev.summary.vulnerable} at risk`, ev.summary.vulnerable ? "crit" : "ok");
      if (state.es) { state.es.close(); state.es = null; }
    }
  }
  function nowTs() { return new Date().toTimeString().slice(0, 8); }

  async function startScan() {
    if (state.running) { toast("A scan is already running", "crit"); return; }
    const targets = collectTargets();
    if (!targets.length) { toast("Enter at least one target", "crit"); return; }
    resetUI();
    state.summary.total = targets.length; renderStats(state.summary); renderDonut(state.summary);
    state.timeline.push({ k: "start", ts: nowTs(), title: "Scan session started", desc: `${targets.length} target(s) · profile ${readConfig().profile}` });
    renderTimeline();
    let res;
    try {
      res = await fetch("/api/scan", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targets, config: readConfig() }),
      });
    } catch (e) { toast("Could not reach the server", "crit"); return; }
    if (!res.ok) { const j = await res.json().catch(() => ({})); toast(j.detail || "Scan request failed", "crit"); return; }
    const { scan_id } = await res.json();
    state.scanId = scan_id; state.running = true;
    startChart();
    toast("Scan started · " + targets.length + " target(s)", "ok");
    state.es = new EventSource(`/api/scan/${scan_id}/stream`);
    state.es.onmessage = (m) => { try { handleEvent(JSON.parse(m.data)); } catch (e) {} };
    state.es.onerror = () => { /* auto-reconnects; closed on done */ };
  }
  async function stopScan() {
    if (!state.scanId || !state.running) { toast("No scan running", "ok"); return; }
    try { await fetch(`/api/scan/${state.scanId}/stop`, { method: "POST" }); } catch (e) {}
    toast("Stopping scan…", "crit");
  }
  function clearResults() {
    if (state.es) { state.es.close(); state.es = null; }
    state.scanId = null; state.running = false; stopChart(); resetUI();
    toast("Cleared");
  }

  $("#startBtn").addEventListener("click", startScan);
  $("#stopBtn").addEventListener("click", stopScan);
  $("#clearBtn").addEventListener("click", clearResults);
  $("#singleGo").addEventListener("click", () => {
    $$("button", modeSeg).forEach(x => x.classList.toggle("active", x.dataset.mode === "single"));
    $$("[data-mode-panel]").forEach(p => p.hidden = p.dataset.modePanel !== "single");
    startScan();
  });
  singleUrl.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); $("#singleGo").click(); } });

  /* ---------------- Command palette ---------------- */
  const cmdkOverlay = $("#cmdkOverlay"), cmdkInput = $("#cmdkInput"), cmdkList = $("#cmdkList");
  const actions = [
    { g: "Scan", label: "Start scan", key: "", ico: '<path d="M8 5v14l11-7z"/>', run: startScan },
    { g: "Scan", label: "Stop scan", key: "", ico: '<rect x="6" y="6" width="12" height="12" rx="2"/>', run: stopScan },
    { g: "Scan", label: "Clear results", key: "", ico: '<path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/>', run: clearResults },
    { g: "Navigate", label: "Go to Overview", ico: '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/>', run: () => setTab("overview") },
    { g: "Navigate", label: "Go to Findings", ico: '<path d="M3 6h18M3 12h18M3 18h18"/>', run: () => setTab("findings") },
    { g: "Navigate", label: "Go to Timeline", ico: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>', run: () => setTab("timeline") },
    { g: "Export", label: "Export JSON", ico: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>', run: () => { if (state.scanId) location.href = `/api/scan/${state.scanId}/report.json`; else toast("Run a scan first", "crit"); } },
    { g: "Export", label: "Export CSV", ico: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>', run: () => { if (state.scanId) location.href = `/api/scan/${state.scanId}/report.csv`; else toast("Run a scan first", "crit"); } },
  ];
  const themeActions = STYLES.map(([id, name, sw]) => ({ g: "Theme", label: "Theme: " + name, sw, run: () => setStyle(id, true) }));
  const allActions = actions.concat(themeActions);
  let cmdkSel = 0, cmdkFiltered = allActions;
  function renderCmdk() {
    const q = cmdkInput.value.toLowerCase();
    cmdkFiltered = allActions.filter(a => a.label.toLowerCase().includes(q));
    if (cmdkSel >= cmdkFiltered.length) cmdkSel = 0;
    let html = "", lastG = "";
    cmdkFiltered.forEach((a, i) => {
      if (a.g !== lastG) { html += `<div class="cmdk-group">${a.g}</div>`; lastG = a.g; }
      const icon = a.sw ? `<span class="ci-sw" style="background:${a.sw}"></span>` : `<span class="ci-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${a.ico || ""}</svg></span>`;
      html += `<div class="cmdk-item ${i === cmdkSel ? "sel" : ""}" data-i="${i}">${icon}<span>${a.label}</span></div>`;
    });
    cmdkList.innerHTML = html || `<div class="no-rows">No matching commands</div>`;
    $$(".cmdk-item", cmdkList).forEach(el => {
      el.addEventListener("click", () => runCmdk(+el.dataset.i));
      el.addEventListener("mousemove", () => { cmdkSel = +el.dataset.i; markSel(); });
    });
  }
  function markSel() { $$(".cmdk-item", cmdkList).forEach(el => el.classList.toggle("sel", +el.dataset.i === cmdkSel)); }
  function runCmdk(i) { const a = cmdkFiltered[i]; if (!a) return; closeCmdk(); a.run(); }
  function openCmdk() { cmdkOverlay.classList.add("open"); cmdkInput.value = ""; cmdkSel = 0; renderCmdk(); setTimeout(() => cmdkInput.focus(), 30); }
  function closeCmdk() { cmdkOverlay.classList.remove("open"); }
  $("#cmdkBtn").addEventListener("click", openCmdk);
  cmdkInput.addEventListener("input", () => { cmdkSel = 0; renderCmdk(); });
  cmdkInput.addEventListener("keydown", e => {
    if (e.key === "ArrowDown") { e.preventDefault(); cmdkSel = Math.min(cmdkSel + 1, cmdkFiltered.length - 1); markSel(); ensureVisible(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); cmdkSel = Math.max(cmdkSel - 1, 0); markSel(); ensureVisible(); }
    else if (e.key === "Enter") { e.preventDefault(); runCmdk(cmdkSel); }
  });
  function ensureVisible() { const el = $(".cmdk-item.sel", cmdkList); if (el) el.scrollIntoView({ block: "nearest" }); }
  cmdkOverlay.addEventListener("click", e => { if (e.target === cmdkOverlay) closeCmdk(); });

  document.addEventListener("keydown", e => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); cmdkOverlay.classList.contains("open") ? closeCmdk() : openCmdk(); return; }
    if (e.key === "Escape") { closeCmdk(); closeDrawer(); themePop.hidden = true; exportMenu.hidden = true; return; }
    if (e.key === "/" && !/INPUT|TEXTAREA/.test(document.activeElement.tagName)) { e.preventDefault(); setTab("findings"); setTimeout(() => search.focus(), 0); }
  });

  /* ---------------- Boot ---------------- */
  resetUI();
  drawChart();
})();
