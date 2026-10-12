/* Sitewarden web UI.
 * Every string from a report (headers, cookies, certificate names...) comes from the scanned site and is
 * untrusted, so the UI only ever builds DOM nodes and sets textContent. The server also enforces
 * Trusted Types, which turns any accidental innerHTML into an exception instead of an XSS bug. */
(() => {
  "use strict";

  // ------------------------------------------------------------------ helpers
  const $app = document.getElementById("app");
  const STANDALONE = document.documentElement.dataset.standalone === "1";

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === null || v === undefined || v === false) continue;
        if (k === "class") el.className = v;
        else if (k === "text") el.textContent = v;
        else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
        else if (k === "style") el.style.cssText = v; // CSSOM, so the strict style-src CSP allows it
        else el.setAttribute(k, v === true ? "" : String(v));
      }
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid === null || kid === undefined || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }
  const svgNS = "http://www.w3.org/2000/svg";
  function s(tag, attrs, ...kids) {
    const el = document.createElementNS(svgNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
    kids.forEach((k) => el.append(k));
    return el;
  }
  const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
  const gradeClass = (g) => "g-" + ({ "A+": "Ap", "A-": "Am" }[g] || (g && /^[A-F]$/.test(g) ? g : "x"));
  const pill = (g) => h("span", { class: "pill " + gradeClass(g) }, g || "–");
  const SEVS = ["critical", "high", "medium", "low", "info", "pass"];
  const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info", pass: "Passed" };
  const CAT_TAB = { tls: "tls", certificate: "cert", headers: "http", cookies: "http", content: "content", dns: "dns", email: "email" };
  function ago(ts) {
    const d = Date.now() / 1000 - ts;
    if (d < 90) return "just now";
    if (d < 3600) return Math.round(d / 60) + " min ago";
    if (d < 86400) return Math.round(d / 3600) + " h ago";
    return Math.round(d / 86400) + " d ago";
  }
  function toast(msg) {
    const t = h("div", { class: "toast", role: "status" }, msg);
    document.body.append(t);
    setTimeout(() => t.remove(), 1800);
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); toast("Copied"); } catch { toast("Copy failed"); }
  }
  function download(name, text, type) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = h("a", { href: url, download: name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
  async function api(path, opts) {
    const r = await fetch(path, Object.assign({ headers: { "Content-Type": "application/json" } }, opts));
    let body = null;
    try { body = await r.json(); } catch { /* empty */ }
    if (!r.ok) throw new Error((body && body.error) || ("HTTP " + r.status));
    return body;
  }

  // ------------------------------------------------------------------ theme
  function themeIcon() {
    const NS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("width", "18");
    svg.setAttribute("height", "18");
    svg.setAttribute("aria-hidden", "true");
    const ring = document.createElementNS(NS, "circle");
    for (const [k, v] of [["cx", "12"], ["cy", "12"], ["r", "9"], ["fill", "none"], ["stroke", "currentColor"], ["stroke-width", "2"]]) ring.setAttribute(k, v);
    const half = document.createElementNS(NS, "path");
    half.setAttribute("d", "M12 3a9 9 0 0 1 0 18z");
    half.setAttribute("fill", "currentColor");
    svg.append(ring, half);
    return svg;
  }
  function applyTheme(t) {
    if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
  }
  let theme = null;
  try { theme = localStorage.getItem("sw-theme"); } catch { /* storage blocked */ }
  applyTheme(theme);
  function toggleTheme() {
    const dark = theme ? theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    theme = dark ? "light" : "dark";
    applyTheme(theme);
    try { localStorage.setItem("sw-theme", theme); } catch { /* ignore */ }
  }

  // ------------------------------------------------------------------ chrome
  function logo() {
    return s("svg", { viewBox: "0 0 64 64", "aria-hidden": "true" },
      s("defs", {}, (() => { const g = s("linearGradient", { id: "lg", x1: 0, y1: 0, x2: 1, y2: 1 },
        s("stop", { offset: 0, "stop-color": "#5eead4" }), s("stop", { offset: 1, "stop-color": "#22c55e" })); return g; })()),
      s("path", { d: "M32 4 8 13v17c0 15 10 26 24 30 14-4 24-15 24-30V13L32 4z", fill: "url(#lg)" }),
      s("path", { d: "m21 32 8 8 15-16", fill: "none", stroke: "#0b1220", "stroke-width": 6, "stroke-linecap": "round", "stroke-linejoin": "round" }));
  }
  function header() {
    const input = h("input", { name: "target", placeholder: "Scan another site", autocomplete: "off", spellcheck: "false", "aria-label": "Domain" });
    const form = h("form", { class: "mini-form", onsubmit: (e) => { e.preventDefault(); startScan(input.value, false); } }, input);
    return h("header", { class: "top" }, h("div", { class: "wrap" },
      h("a", { class: "brand", href: "/", onclick: nav("/") }, logo(), "Sitewarden"),
      h("nav", {}, STANDALONE ? null : form,
        STANDALONE ? null : h("a", { href: "/api/docs" }, "API"),
        h("button", { class: "icon-btn", title: "Toggle theme", "aria-label": "Toggle theme", onclick: toggleTheme }, themeIcon()))));
  }
  function footer() {
    return h("footer", {}, h("div", { class: "wrap" },
      h("div", {}, "Sitewarden · passive website security grading. Open source, MIT licensed."),
      h("div", {}, "Checks only what any visitor or mail server can see. No attack payloads are sent.")));
  }
  function nav(path) {
    return (e) => { if (e) e.preventDefault(); history.pushState({}, "", path); route(); };
  }
  function page(...content) {
    clear($app);
    $app.append(header(), h("main", {}, ...content), footer());
    window.scrollTo(0, 0);
  }

  // ------------------------------------------------------------------ home
  const FEATURES = [
    ["🔒", "TLS deep scan", "Hand-built handshakes enumerate every protocol (SSL 2 to TLS 1.3), cipher suite and key-exchange group, including post-quantum ML-KEM."],
    ["📜", "Certificate trust", "Full path validation against the Mozilla root store, incomplete-chain detection, OCSP/CRL revocation and Certificate Transparency."],
    ["🛡️", "Headers & CSP", "HSTS and preload status, a Content Security Policy evaluator built on Google's strict-CSP research, CORS, clickjacking and more."],
    ["🍪", "Cookies & content", "Session cookie flags, mixed content, Subresource Integrity, compromised CDNs and known-vulnerable JavaScript libraries."],
    ["🌐", "DNS integrity", "DNSSEC validated from the root trust anchor, CAA cross-checked with the real certificate, dangling CNAME takeover risk."],
    ["✉️", "Email spoofing", "SPF with the 10-lookup rule, DMARC policy and reporting, DKIM key strength, MTA-STS, TLS-RPT and STARTTLS on your mail servers."],
  ];
  async function home(prefill) {
    const input = h("input", { name: "target", placeholder: "example.com", autocomplete: "off", spellcheck: "false", autofocus: true, "aria-label": "Domain to scan", value: prefill || "" });
    const hidden = h("input", { type: "checkbox", name: "hidden" });
    const btn = h("button", { class: "btn", type: "submit" }, "Scan");
    const err = h("div");
    const form = h("form", { class: "scan-form", onsubmit: async (e) => {
      e.preventDefault();
      btn.disabled = true; clear(err);
      try { await startScan(input.value, hidden.checked); }
      catch (ex) { err.append(h("div", { class: "error-box" }, ex.message)); }
      finally { btn.disabled = false; }
    } }, input, btn);
    const recentBox = h("div");
    page(h("div", { class: "wrap" },
      h("section", { class: "hero" },
        h("span", { class: "eyebrow" }, "● Free · passive · open source"),
        h("h1", {}, "How secure is your website, ", h("span", { class: "grad" }, "really?")),
        h("p", { class: "lead" }, "One scan grades TLS, certificates, HTTP security headers, cookies, page scripts, DNSSEC and email spoofing protection, and tells you exactly how to fix each problem."),
        form,
        h("div", { class: "form-hint" }, h("label", {}, hidden, "Don't list my scan on this page")),
        err,
        h("div", { class: "examples" }, ["github.com", "mozilla.org", "cloudflare.com", "wikipedia.org"].map((d) =>
          h("button", { class: "chip", type: "button", onclick: () => { input.value = d; form.requestSubmit(); } }, d)))),
      h("div", { class: "features" }, FEATURES.map(([ico, t, d]) =>
        h("div", { class: "feature" }, h("div", { class: "ico" }, ico), h("h3", {}, t), h("p", {}, d)))),
      recentBox));
    input.focus();
    try {
      const data = await api("/api/recent");
      if (data.recent.length) {
        recentBox.append(h("div", { class: "section-title" }, `Recently scanned · ${data.stats.scans} scans of ${data.stats.sites} sites`),
          h("div", { class: "recent" }, data.recent.map((r) =>
            h("a", { href: "/scan/" + r.id, onclick: nav("/scan/" + r.id) }, pill(r.grade),
              h("div", { style: "min-width:0" }, h("div", { class: "host" }, r.target), h("div", { class: "when" }, ago(r.finished)))))));
      }
    } catch { /* recent list is optional */ }
  }
  async function startScan(target, hidden) {
    target = (target || "").trim();
    if (!target) throw new Error("Enter a domain name such as example.com");
    const res = await api("/api/scans", { method: "POST", body: JSON.stringify({ target, hidden }) });
    nav("/scan/" + res.id)();
  }

  // ------------------------------------------------------------------ scan progress
  const STAGES = [
    ["resolve", "Resolving the domain"], ["tls", "TLS handshakes"], ["certificate", "Certificate chain & revocation"],
    ["http", "HTTPS, redirects & headers"], ["content", "Page scripts & libraries"], ["dns", "DNSSEC, CAA & name servers"],
    ["email", "SPF, DMARC, DKIM & MTA-STS"], ["grade", "Grading"],
  ];
  async function scanView(id) {
    let data;
    try { data = await api("/api/scans/" + encodeURIComponent(id)); }
    catch (e) { page(h("div", { class: "wrap" }, h("div", { class: "error-box", style: "margin-top:40px" }, e.message))); return; }
    if (data.status === "done") { renderReport(data.report, data); return; }
    if (data.status === "error") { scanError(data); return; }

    const items = STAGES.map(([key, label]) => {
      const msg = h("span", { class: "msg" });
      const li = h("li", { "data-stage": key }, h("span", { class: "dot" }), h("span", {}, label), msg);
      return [key, li, msg];
    });
    const barFill = h("span", { style: "width:4%" });
    page(h("div", { class: "wrap" }, h("div", { class: "progress-card" },
      h("h2", {}, "Scanning " + data.target),
      h("div", { class: "sub" }, "This usually takes 15 to 60 seconds. You can share this page's address."),
      h("ul", { class: "stages" }, items.map((x) => x[1])),
      h("div", { class: "bar" }, barFill))));
    document.body.classList.add("on-scan");
    const seen = new Set();
    function apply(ev) {
      seen.add(ev.stage);
      const reached = STAGES.map(([k]) => k).filter((k) => seen.has(k));
      items.forEach(([key, li, msg]) => {
        const done = seen.has(key) && key !== ev.stage && ev.stage !== "error";
        li.classList.toggle("active", key === ev.stage);
        li.classList.toggle("done", done || (seen.has(key) && ["done"].includes(ev.stage)));
        const dot = li.querySelector(".dot");
        dot.textContent = li.classList.contains("done") ? "✓" : "";
        if (key === ev.stage) msg.textContent = ev.message;
      });
      barFill.style.width = Math.max(4, Math.round((reached.length / STAGES.length) * 100)) + "%";
    }
    data.progress.forEach(apply);
    const finish = async () => {
      const d = await api("/api/scans/" + encodeURIComponent(id));
      if (d.status === "done") renderReport(d.report, d);
      else if (d.status === "error") scanError(d);
      else setTimeout(finish, 1200);
    };
    if (window.EventSource) {
      const es = new EventSource("/api/scans/" + encodeURIComponent(id) + "/events");
      es.onmessage = (m) => { try { apply(JSON.parse(m.data)); } catch { /* ignore */ } };
      es.addEventListener("end", () => { es.close(); finish(); });
      es.onerror = () => { es.close(); setTimeout(finish, 1500); };
    } else {
      setTimeout(finish, 1500);
    }
  }
  function scanError(d) {
    page(h("div", { class: "wrap" }, h("div", { class: "progress-card" },
      h("h2", {}, "Could not scan " + d.target), h("div", { class: "error-box", style: "margin:12px 0 0;max-width:none" }, d.error || "Unknown error"),
      h("div", { class: "actions" }, h("a", { class: "btn small", href: "/", onclick: nav("/") }, "Try another site")))));
  }

  // ------------------------------------------------------------------ report
  function ring(grade, score) {
    const r = 74, c = 2 * Math.PI * r;
    const pct = Math.max(0, Math.min(100, score || 0)) / 100;
    const color = getComputedStyle(document.documentElement).getPropertyValue("--" + gradeClass(grade).replace("g-", "g-").toLowerCase()) || "";
    const fg = s("circle", { cx: 85, cy: 85, r, fill: "none", "stroke-width": 12, "stroke-linecap": "round",
      "stroke-dasharray": `${c * pct} ${c}`, class: "ringfg" });
    fg.style.stroke = color.trim() || "var(--accent)";
    return h("div", { class: "ring" },
      s("svg", { width: 170, height: 170, viewBox: "0 0 170 170" },
        s("circle", { cx: 85, cy: 85, r, fill: "none", stroke: "var(--line)", "stroke-width": 12 }), fg),
      h("div", { class: "letter" }, grade), h("div", { class: "score" }, `${score} / 100`));
  }

  function snippetBox(snips) {
    const names = Object.keys(snips || {});
    if (!names.length) return null;
    const pre = h("pre");
    const btns = [];
    let current = names[0];
    const show = (n) => { current = n; pre.textContent = snips[n]; btns.forEach((b) => b.classList.toggle("on", b.dataset.n === n)); };
    names.forEach((n) => btns.push(h("button", { type: "button", "data-n": n, onclick: () => show(n) }, n)));
    const box = h("div", { class: "snips" }, h("div", { class: "bar2" }, btns,
      h("button", { type: "button", class: "copy", onclick: () => copy(snips[current]) }, "Copy")), pre);
    show(current);
    return box;
  }

  function findingEl(f, open) {
    const body = h("div", { class: "body" },
      f.detail ? h("p", {}, f.detail) : null,
      h("div", { class: "kv" },
        f.evidence ? [h("div", {}, "Evidence"), h("div", { class: "evidence" }, f.evidence)] : null,
        f.fix ? [h("div", {}, "Fix"), h("div", { class: "fix" }, f.fix)] : null,
        f.tags && f.tags.length ? [h("div", {}, "References"), h("div", { class: "tags" }, f.tags.map((t) => h("span", { class: "tag" }, t)))] : null,
        f.refs && f.refs.length ? [h("div", {}, "Read more"), h("div", {}, f.refs.map((u) => h("div", {}, h("a", { href: u, target: "_blank", rel: "noopener noreferrer" }, u))))] : null,
        f.cap ? [h("div", {}, "Grade cap"), h("div", {}, "While this stands, the overall grade cannot be better than ", pill(f.cap))] : null),
      snippetBox(f.snippets));
    const el = h("div", { class: `finding sev sev-${f.severity}` + (open ? " open" : "") },
      h("button", { type: "button", "aria-expanded": open ? "true" : "false", onclick: () => {
        el.classList.toggle("open");
        el.firstChild.setAttribute("aria-expanded", el.classList.contains("open") ? "true" : "false");
      } }, h("span", { class: "badge" }, SEV_LABEL[f.severity]), h("span", { class: "title" }, f.title),
        h("span", { class: "catname" }, (report && report.categories[f.category] || {}).label || f.category), h("span", { class: "chev" }, "›")),
      body);
    return el;
  }

  let report = null;
  let meta = null;
  let activeTab = "findings";
  let sevFilter = new Set(["critical", "high", "medium", "low"]);
  let catFilter = null;

  function renderReport(r, m) {
    report = r; meta = m || {};
    activeTab = "findings"; catFilter = null;
    sevFilter = new Set(["critical", "high", "medium", "low"]);
    document.title = `${r.target} · ${r.grade} · Sitewarden`;
    drawReport();
  }

  function drawReport() {
    const r = report;
    const counts = r.summary || {};
    const tech = (r.http && r.http.technology) || {};
    const certs = r.certificates || [];
    const shareUrl = STANDALONE ? null : location.origin + "/scan/" + (r.id || meta.id || "");

    const gradeCard = h("div", { class: "card grade-card" }, ring(r.grade, r.score),
      r.capped_by && r.capped_by.length ? h("div", { class: "capped" }, "Capped by: " + r.capped_by.join("; ")) : null);
    const metaBits = [
      r.ip ? ["IP", r.ip] : null,
      tech.server ? ["Server", tech.server] : null,
      tech.edge ? ["Edge", tech.edge] : null,
      certs[0] ? ["Issuer", certs[0].leaf.issuer] : null,
      ["Scanned", new Date(r.scanned_at).toLocaleString()],
      ["Took", (r.duration_ms / 1000).toFixed(1) + " s"],
    ].filter(Boolean);
    const target = h("div", { class: "card pad target-card" },
      h("h1", {}, r.target + (r.port && r.port !== 443 ? ":" + r.port : "")),
      h("div", { class: "meta" }, metaBits.map(([k, v]) => h("span", {}, k + " ", h("b", {}, v)))),
      h("div", { class: "counts" }, SEVS.map((sv) => h("button", { type: "button", class: `count sev sev-${sv}`, onclick: () => {
        sevFilter = new Set([sv]); catFilter = null; activeTab = "findings"; drawReport();
        document.querySelector(".tabs").scrollIntoView({ behavior: "smooth" });
      } }, h("span", { class: "sw", style: "background:var(--sev)" }), h("b", {}, counts[sv] || 0), SEV_LABEL[sv]))),
      h("div", { class: "cats" }, Object.entries(r.categories).map(([k, c]) => h("button", { type: "button", class: "cat", onclick: () => {
        if (c.skipped) return;
        catFilter = k; sevFilter = new Set(SEVS); activeTab = "findings"; drawReport();
        document.querySelector(".tabs").scrollIntoView({ behavior: "smooth" });
      } }, pill(c.skipped ? null : c.grade), h("div", {}, h("div", { class: "lbl" }, c.label), h("div", { class: "sc" }, c.skipped ? "skipped" : c.score + "/100"))))),
      h("div", { class: "actions" },
        STANDALONE ? null : h("button", { class: "btn small ghost", type: "button", onclick: () => copy(shareUrl) }, "Copy link"),
        h("button", { class: "btn small ghost", type: "button", onclick: () => download(`sitewarden-${r.target}.json`, JSON.stringify(r, null, 2), "application/json") }, "JSON"),
        STANDALONE ? null : h("a", { class: "btn small ghost", href: `/api/scans/${r.id}/report.md` }, "Markdown"),
        STANDALONE ? null : h("a", { class: "btn small ghost", href: `/api/scans/${r.id}/report.html` }, "HTML report"),
        STANDALONE ? null : h("button", { class: "btn small ghost", type: "button", onclick: rescan }, "Rescan"),
        h("button", { class: "btn small ghost", type: "button", onclick: () => window.print() }, "Print")));

    const top = (r.findings || []).filter((f) => ["critical", "high", "medium"].includes(f.severity)).slice(0, 5);
    const topBox = top.length ? h("div", { class: "top-issues" }, h("div", { class: "section-title", style: "margin-top:24px" }, "Fix these first"),
      h("div", { class: "findings" }, top.map((f) => findingEl(f, false)))) : h("div", { class: "top-issues" },
      h("div", { class: "section-title", style: "margin-top:24px" }, "Fix these first"), h("div", { class: "empty" }, "No critical, high or medium issues. Nicely done."));

    const tabs = [
      ["findings", "All findings", (r.findings || []).filter((f) => f.severity !== "pass").length],
      ["tls", "TLS", null], ["cert", "Certificate", certs.length || null], ["http", "HTTP & cookies", null],
      ["content", "Content", null], ["dns", "DNS", null], ["email", "Email", null], ["compliance", "Compliance", null], ["share", "Badge & API", null],
    ];
    const tabBar = h("div", { class: "tabs", role: "tablist" }, tabs.map(([k, label, n]) =>
      h("button", { type: "button", role: "tab", class: "tab" + (activeTab === k ? " on" : ""), "aria-selected": activeTab === k ? "true" : "false",
        onclick: () => { activeTab = k; drawReport(); } }, label, n ? h("span", { class: "n" }, n) : null)));
    const panel = h("div", { role: "tabpanel" }, TABS[activeTab]());

    const notes = (r.notes || []).concat(Object.entries(r.errors || {}).map(([k, v]) => `Error in ${k}: ${v}`));
    page(h("div", { class: "wrap report" },
      h("div", { class: "summary" }, gradeCard, target),
      topBox, tabBar, panel,
      notes.length ? h("ul", { class: "limits" }, notes.map((n) => h("li", {}, n))) : null,
      h("ul", { class: "limits" }, (r.limitations || []).map((n) => h("li", {}, n)))));
    if (!STANDALONE) document.body.classList.add("on-scan");
  }

  async function rescan() {
    try {
      const res = await api("/api/scans", { method: "POST", body: JSON.stringify({ target: report.target, force: true }) });
      nav("/scan/" + res.id)();
    } catch (e) { toast(e.message); }
  }

  // ------------------------------------------------------------------ tab: findings
  function tabFindings() {
    const all = report.findings || [];
    const list = all.filter((f) => sevFilter.has(f.severity) && (!catFilter || f.category === catFilter));
    const chips = SEVS.map((sv) => h("button", { type: "button", class: "chip" + (sevFilter.has(sv) ? " on" : ""), onclick: () => {
      if (sevFilter.has(sv)) sevFilter.delete(sv); else sevFilter.add(sv);
      drawReport();
    } }, `${SEV_LABEL[sv]} ${all.filter((f) => f.severity === sv && (!catFilter || f.category === catFilter)).length}`));
    return h("div", {},
      h("div", { class: "filters" }, chips, h("span", { class: "spacer" }),
        catFilter ? h("button", { type: "button", class: "chip on", onclick: () => { catFilter = null; drawReport(); } }, (report.categories[catFilter] || {}).label + " ✕") : null),
      list.length ? h("div", { class: "findings" }, list.map((f) => findingEl(f, list.length <= 3)))
        : h("div", { class: "empty" }, "Nothing matches these filters."));
  }

  // ------------------------------------------------------------------ tab: TLS
  const yn = (v, goodWhenTrue = true) => v === null || v === undefined ? h("span", { class: "no" }, "n/a")
    : h("span", { class: (v === goodWhenTrue) ? "yes" : "bad" }, v ? "Yes" : "No");
  function tabTLS() {
    const t = report.tls;
    if (!t) return h("div", { class: "empty" }, "TLS was not tested.");
    const protoOrder = ["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0", "SSL 2.0"];
    const good = { "TLS 1.3": true, "TLS 1.2": true };
    const protos = h("div", { class: "proto-grid" }, protoOrder.map((p) => {
      const on = t.protocols[p];
      const cls = on ? (good[p] ? "yes" : "bad") : (good[p] && p === "TLS 1.3" ? "warn" : "no");
      return h("div", { class: "proto" }, h("div", { class: "n" }, p), h("div", { class: "s " + cls }, on ? "Enabled" : "Disabled"));
    }));
    const cipherTables = Object.entries(t.ciphers || {}).map(([p, list]) => h("div", { class: "panel" },
      h("h2", {}, `${p} cipher suites (${list.length})`),
      t.server_preference && t.server_preference[p] !== undefined && t.server_preference[p] !== null
        ? h("div", { class: "note" }, t.server_preference[p] ? "Server enforces its own order (listed in server preference order)." : "Server follows the client's order.") : null,
      h("div", { class: "scroll-x" }, h("table", { class: "t" },
        h("thead", {}, h("tr", {}, h("th", {}, "Suite"), h("th", {}, "Key exchange"), h("th", {}, "Bits"), h("th", {}, "Rating"))),
        h("tbody", {}, list.map((c) => h("tr", {},
          h("td", { class: "mono" }, c.name, h("div", { class: "note" }, c.code + (c.openssl ? " · " + c.openssl : ""))),
          h("td", {}, c.kx === "ANY" ? "(TLS 1.3)" : c.kx + (c.dh_bits ? ` ${c.dh_bits}-bit` : ""), c.forward_secret ? "" : h("div", { class: "note" }, "no forward secrecy")),
          h("td", {}, c.bits),
          h("td", {}, h("span", { class: "strength " + c.strength }, c.strength)))))))));
    const f = t.features || {};
    const feat = [
      ["Post-quantum key exchange", (t.post_quantum || []).length ? h("span", { class: "yes" }, t.post_quantum.join(", ")) : h("span", { class: "no" }, "No")],
      ["Key exchange groups", (t.groups || []).join(", ") || "n/a"],
      ["ALPN", (f.alpn || []).join(", ") || "none"],
      ["OCSP stapling", yn(f.ocsp_stapling)],
      ["Secure renegotiation", yn(f.secure_renegotiation)],
      ["Extended master secret", yn(f.extended_master_secret)],
      ["Downgrade protection (FALLBACK_SCSV)", yn(f.fallback_scsv)],
      ["TLS 1.3 downgrade sentinel", yn(f.tls13_downgrade_protection)],
      ["TLS compression (CRIME)", yn(f.tls_compression, false)],
      ["Heartbeat extension", yn(f.heartbeat_extension, false)],
      ["Session tickets", f.session_tickets === null || f.session_tickets === undefined ? "n/a" : (f.session_tickets ? "Yes" : "No")],
      ["SNI required", f.sni_required ? "Yes" : "No"],
      ["Handshakes performed", t.handshakes],
    ];
    return h("div", { class: "stack" },
      h("div", { class: "grid2" },
        h("div", { class: "panel" }, h("h2", {}, "Protocol versions"), protos),
        h("div", { class: "panel" }, h("h2", {}, "Handshake features"), h("dl", { class: "dl" }, feat.map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])))),
      report.mozilla ? h("div", { class: "panel" }, h("h2", {}, "Mozilla server-side TLS profiles"),
        ["modern", "intermediate"].map((p) => compRow(`Mozilla ${p[0].toUpperCase() + p.slice(1)}`, report.mozilla[p]))) : null,
      cipherTables.length ? h("div", { class: "stack" }, cipherTables) : null);
  }

  // ------------------------------------------------------------------ tab: certificate
  function tabCert() {
    const certs = report.certificates || [];
    if (!certs.length) return h("div", { class: "empty" }, "No certificate was analysed.");
    return h("div", { class: "stack" }, certs.map((c) => {
      const leaf = c.leaf;
      const rev = c.revocation || {};
      const days = leaf.days_left;
      return h("div", { class: "grid2" },
        h("div", { class: "panel" }, h("h2", {}, `${c.auth === "server" ? "" : c.auth + " "}certificate`),
          h("dl", { class: "dl" },
            [["Subject", leaf.subject], ["Names", (c.names || []).join(", ")], ["Issuer", leaf.issuer_dn],
              ["Valid", `${leaf.not_before.slice(0, 10)} to ${leaf.not_after.slice(0, 10)}`],
              ["Expires in", h("span", { class: days < 0 ? "bad" : days < 21 ? "warn" : "yes" }, days + " days")],
              ["Key", leaf.key], ["Signature", leaf.signature], ["Validation", c.validation],
              ["Trusted", c.trusted ? h("span", { class: "yes" }, "Yes (Mozilla root store)") : h("span", { class: "bad" }, "No: " + (c.trust_error || ""))],
              ["Hostname match", yn(c.hostname_ok)],
              ["CT (embedded SCTs)", String(c.scts)],
              ["OCSP Must-Staple", c.must_staple ? "Yes" : "No"],
              ["Revocation", rev.status ? `${rev.status}${rev.method ? " via " + rev.method : ""}` : "not checked"],
              ["Serial", h("span", { class: "mono" }, leaf.serial)],
              ["SHA-256", h("span", { class: "mono" }, leaf.sha256)],
              ["SPKI SHA-256", h("span", { class: "mono" }, leaf.spki_sha256)],
            ].map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]))),
        h("div", { class: "panel" }, h("h2", {}, "Chain sent by the server"),
          h("div", { class: "chain" }, c.presented.map((p, i) => [
            i ? h("div", { class: "arrow" }, "▲ signed by ▼") : null,
            h("div", { class: "cert" }, h("div", { class: "who" }, p.subject),
              h("div", { class: "sub2" }, `${p.key} · ${p.signature} · expires ${p.not_after.slice(0, 10)}${p.self_signed ? " · self-signed" : ""}`))])),
          c.path && c.path.length ? h("div", { style: "margin-top:14px" }, h("div", { class: "note" }, "Validated trust path" + (c.aia_fetched ? " (needed an intermediate the server did not send)" : "")),
            h("div", { class: "flow", style: "margin-top:6px" }, c.path.map((p, i) => [i ? "→" : null, h("span", { class: "hop" }, p)]))) : null));
    }));
  }

  // ------------------------------------------------------------------ tab: HTTP
  function hopsFlow(chain) {
    if (!chain || !chain.length) return h("span", { class: "note" }, "not tested");
    return h("div", { class: "flow" }, chain.map((hop, i) => [i ? "→" : null,
      h("span", { class: "hop" }, hop.url, " ", h("span", { class: "st" }, hop.error ? `(${hop.error})` : `[${hop.status}]`))]));
  }
  function tabHTTP() {
    const x = report.http;
    if (!x) return h("div", { class: "empty" }, "HTTP was not tested.");
    const hdrs = x.response_headers || [];
    const cookies = report.cookies || [];
    const csp = x.csp || {};
    return h("div", { class: "stack" },
      h("div", { class: "panel" }, h("h2", {}, "Redirects"),
        h("div", { class: "note" }, "Plain HTTP"), hopsFlow(x.http_chain),
        h("div", { class: "note", style: "margin-top:10px" }, "HTTPS"), hopsFlow(x.https_chain),
        h("dl", { class: "dl", style: "margin-top:14px" },
          h("dt", {}, "HSTS"), h("dd", {}, x.hsts ? h("span", { class: "mono" }, x.hsts.raw) : h("span", { class: "bad" }, "not set")),
          h("dt", {}, "HSTS preloaded"), h("dd", {}, x.hsts_preloaded ? h("span", { class: "yes" }, "Yes (" + x.hsts_preload_entry + ")") : "No"),
          h("dt", {}, "CSP"), h("dd", {}, csp.level || "none"),
          h("dt", {}, "security.txt"), h("dd", {}, x.security_txt && x.security_txt.present ? h("span", { class: "yes" }, x.security_txt.path) : "not found"))),
      csp.policies && csp.policies.length ? h("div", { class: "panel" }, h("h2", {}, "Content Security Policy"),
        csp.policies.map((p) => h("div", { class: "scroll-x", style: "margin-bottom:10px" }, h("div", { class: "note" }, p.source),
          h("table", { class: "t" }, h("tbody", {}, Object.entries(p.directives).map(([d, v]) =>
            h("tr", {}, h("td", { class: "mono", style: "white-space:nowrap" }, d), h("td", { class: "mono" }, v.join(" ") || "(empty)")))))))) : null,
      h("div", { class: "panel" }, h("h2", {}, `Cookies (${cookies.length})`), cookies.length ? h("div", { class: "scroll-x" }, h("table", { class: "t" },
        h("thead", {}, h("tr", {}, ["Name", "Secure", "HttpOnly", "SameSite", "Scope", "Lifetime"].map((c) => h("th", {}, c)))),
        h("tbody", {}, cookies.map((c) => h("tr", {},
          h("td", { class: "mono" }, c.name, c.session_like ? h("div", { class: "note" }, "session-like") : null),
          h("td", {}, yn(c.secure)), h("td", {}, c.session_like ? yn(c.httponly) : (c.httponly ? "Yes" : "No")),
          h("td", {}, c.samesite || h("span", { class: c.session_like ? "warn" : "no" }, "not set")),
          h("td", { class: "mono" }, (c.domain ? "Domain=" + c.domain : "host-only") + (c.path ? " Path=" + c.path : "")),
          h("td", {}, c.lifetime_days === null ? "session" : c.lifetime_days + " d")))))) : h("div", { class: "note" }, "No cookies were set.")),
      h("div", { class: "panel" }, h("h2", {}, "Response headers"), h("div", { class: "note" }, x.final_url || ""),
        h("div", { class: "scroll-x" }, h("table", { class: "t" }, h("tbody", {}, hdrs.map(([k, v]) =>
          h("tr", {}, h("td", { class: "mono", style: "white-space:nowrap" }, k), h("td", { class: "mono" }, v))))))));
  }

  // ------------------------------------------------------------------ tab: content
  function tabContent() {
    const c = report.content;
    if (!c || c.note) return h("div", { class: "empty" }, (c && c.note) || "Page content was not analysed.");
    const libs = c.libraries || [];
    return h("div", { class: "stack" },
      h("div", { class: "grid2" },
        h("div", { class: "panel" }, h("h2", {}, "Page"), h("dl", { class: "dl" },
          [["Subresources", c.resources], ["External scripts", (c.scripts || []).length], ["Inline scripts", c.inline_scripts],
            ["Inline event handlers", c.inline_event_handlers], ["Forms", c.forms]].map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]))),
        h("div", { class: "panel" }, h("h2", {}, `Third-party script hosts (${(c.third_party_script_hosts || []).length})`),
          (c.third_party_script_hosts || []).length ? h("div", { class: "tags" }, c.third_party_script_hosts.map((d) => h("span", { class: "tag" }, d)))
            : h("div", { class: "note" }, "None. Every script is first-party."))),
      h("div", { class: "panel" }, h("h2", {}, `JavaScript libraries (${libs.length})`), libs.length ? h("div", { class: "scroll-x" }, h("table", { class: "t" },
        h("thead", {}, h("tr", {}, ["Library", "Version", "Known vulnerabilities", "Found in"].map((x) => h("th", {}, x)))),
        h("tbody", {}, libs.map((l) => h("tr", {},
          h("td", {}, l.library), h("td", { class: "mono" }, l.version),
          h("td", {}, l.vulnerabilities.length ? h("span", { class: l.worst === "high" || l.worst === "critical" ? "bad" : "warn" },
            `${l.vulnerabilities.length} (${l.worst})`, h("div", { class: "note" }, [...new Set(l.vulnerabilities.flatMap((v) => v.cve))].slice(0, 5).join(", "))) : h("span", { class: "yes" }, "none known")),
          h("td", { class: "mono" }, l.source)))))) : h("div", { class: "note" }, "No known libraries detected (detection uses the Retire.js database).")),
      h("div", { class: "panel" }, h("h2", {}, "Scripts loaded"), h("div", { class: "scroll-x" }, h("table", { class: "t" }, h("tbody", {},
        (c.scripts || []).map((u) => h("tr", {}, h("td", { class: "mono" }, u))))))));
  }

  // ------------------------------------------------------------------ tab: DNS
  function tabDNS() {
    const d = report.dns;
    if (!d || d.dns_unavailable) return h("div", { class: "empty" }, "DNS was not tested.");
    const sec = d.dnssec || {};
    return h("div", { class: "stack" },
      h("div", { class: "grid2" },
        h("div", { class: "panel" }, h("h2", {}, "Records"), h("dl", { class: "dl" },
          [["Domain", d.domain], ["A", (d.a || []).join(", ") || "none"], ["AAAA", (d.aaaa || []).join(", ") || "none"],
            ["Name servers", (d.ns || []).join(", ")], ["NS networks", (d.ns_networks || []).join(", ")],
            ["CAA", d.caa && d.caa.records.length ? h("div", {}, d.caa.records.map((r) => h("div", { class: "mono" }, r)), h("div", { class: "note" }, "at " + d.caa.name)) : "none"],
          ].map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]))),
        h("div", { class: "panel" }, h("h2", {}, "DNSSEC chain of trust"),
          h("div", { style: "margin-bottom:10px" }, h("span", { class: sec.status === "secure" ? "yes" : sec.status === "bogus" ? "bad" : "warn" }, (sec.status || "unknown").toUpperCase()), " ", h("span", { class: "note" }, sec.detail || "")),
          h("div", { class: "chain" }, (sec.chain || []).map((z, i) => [i ? h("div", { class: "arrow" }, "▼ DS") : null,
            h("div", { class: "cert" }, h("div", { class: "who" }, z.zone === "." ? ". (root)" : z.zone),
              h("div", { class: "sub2" }, z.secure ? "validated" : (z.signed ? "signed" : "unsigned"), z.error ? " · " + z.error : ""),
              z.keys && z.keys.length ? h("div", { class: "note mono" }, z.keys.slice(0, 4).join(" · ")) : null)])))),
      d.cname_platforms ? h("div", { class: "panel" }, h("h2", {}, "Hosted platforms (CNAME)"), d.cname_platforms.map((c) => h("div", { class: "mono" }, `${c.name} → ${c.target} (${c.platform})`))) : null);
  }

  // ------------------------------------------------------------------ tab: email
  function spfTree(node) {
    if (!node) return null;
    return h("li", {}, h("b", {}, node.domain), h("div", { class: "rec" }, node.record),
      node.children && node.children.length ? h("ul", {}, node.children.map(spfTree)) : null);
  }
  function tabEmail() {
    const e = report.email;
    if (!e) return h("div", { class: "empty" }, "Email was not tested.");
    const spf = e.spf || {};
    const dm = e.dmarc;
    return h("div", { class: "stack" },
      h("div", { class: "grid2" },
        h("div", { class: "panel" }, h("h2", {}, "Mail servers"), h("dl", { class: "dl" },
          h("dt", {}, "Domain"), h("dd", {}, e.domain),
          h("dt", {}, "MX"), h("dd", {}, (e.mx || []).join(", ") || (e.null_mx ? "null MX (no mail)" : "none")),
          (e.smtp || []).map((m) => [h("dt", {}, m.host), h("dd", {}, m.error && m.starttls === null ? h("span", { class: "note" }, m.error)
            : [yn(m.starttls), " STARTTLS", m.tls_version ? " · " + m.tls_version : "", m.cert_valid === false ? h("span", { class: "warn" }, " · invalid cert") : ""])]))),
        h("div", { class: "panel" }, h("h2", {}, "DMARC"), dm ? h("div", {}, h("div", { class: "evidence" }, dm.record),
          h("dl", { class: "dl", style: "margin-top:10px" }, Object.entries(dm.tags).map(([k, v]) => [h("dt", { class: "mono" }, k), h("dd", { class: "mono" }, v)])))
          : h("div", { class: "bad" }, "No DMARC record"))),
      h("div", { class: "panel" }, h("h2", {}, `SPF (${spf.lookups ?? 0}/10 DNS lookups)`), spf.record
        ? h("div", { class: "tree" }, h("ul", {}, spfTree(spf.tree)), (spf.errors || []).map((x) => h("div", { class: "bad" }, x)))
        : h("div", { class: "bad" }, "No SPF record")),
      h("div", { class: "grid2" },
        h("div", { class: "panel" }, h("h2", {}, "DKIM keys found"), (e.dkim || []).length ? h("table", { class: "t" },
          h("tbody", {}, e.dkim.map((k) => h("tr", {}, h("td", { class: "mono" }, k.selector), h("td", {}, k.revoked ? "revoked" : `${k.key_type || "?"} ${k.bits || ""}`), h("td", {}, k.testing ? "test mode" : "")))))
          : h("div", { class: "note" }, "None under common selectors. DKIM selectors cannot be listed, so this is not proof DKIM is off.")),
        h("div", { class: "panel" }, h("h2", {}, "MTA-STS"), e.mta_sts ? h("dl", { class: "dl" },
          h("dt", {}, "Mode"), h("dd", {}, e.mta_sts.mode || "?"), h("dt", {}, "MX"), h("dd", { class: "mono" }, (e.mta_sts.mx || []).join(", ")),
          h("dt", {}, "Max age"), h("dd", {}, e.mta_sts.max_age || "?")) : h("div", { class: "note" }, "No MTA-STS policy."))));
  }

  // ------------------------------------------------------------------ tab: compliance
  function compRow(name, c) {
    if (!c) return null;
    return h("div", { class: "comp" }, h("div", { class: "mark " + (c.compliant ? "yes" : "bad") }, c.compliant ? "✔" : "✘"),
      h("div", {}, h("b", {}, c.name || name), c.compliant ? h("div", { class: "note" }, "Meets the requirements Sitewarden can observe externally.")
        : h("ul", {}, (c.problems || []).map((p) => h("li", {}, p)))));
  }
  function tabCompliance() {
    const comp = report.compliance || {};
    return h("div", { class: "panel" }, h("h2", {}, "Standards"),
      Object.entries(comp).map(([k, v]) => compRow(k, v)),
      h("p", { class: "note" }, "External checks can show non-compliance but cannot prove compliance: these standards also cover things only visible from inside your systems."));
  }

  // ------------------------------------------------------------------ tab: share
  function tabShare() {
    if (STANDALONE) return h("div", { class: "empty" }, "Open the hosted report to get a badge.");
    const badge = `${location.origin}/badge/${report.target}.svg`;
    const page2 = `${location.origin}/scan/${report.id}`;
    const md = `[![Sitewarden grade](${badge})](${page2})`;
    const line = (label, value) => h("div", { style: "margin-top:12px" }, h("div", { class: "note" }, label),
      h("div", { class: "copyline" }, h("input", { readonly: true, value }), h("button", { class: "btn small ghost", type: "button", onclick: () => copy(value) }, "Copy")));
    return h("div", { class: "grid2" },
      h("div", { class: "panel" }, h("h2", {}, "Grade badge"), h("img", { src: `/badge/${report.target}.svg`, alt: "Sitewarden grade badge", height: 20 }),
        line("Markdown", md), line("Image URL", badge), line("Report link", page2)),
      h("div", { class: "panel" }, h("h2", {}, "API & CLI"),
        h("p", { class: "note" }, "Start a scan and poll it:"),
        h("pre", { class: "evidence" }, `curl -s -X POST ${location.origin}/api/scans \\\n  -H 'Content-Type: application/json' \\\n  -d '{"target":"${report.target}"}'\n\ncurl -s ${location.origin}/api/scans/<id>`),
        h("p", { class: "note" }, "Or run it locally and fail CI below a grade:"),
        h("pre", { class: "evidence" }, `pip install sitewarden\nsitewarden scan ${report.target} --fail-under B`)));
  }

  const TABS = { findings: tabFindings, tls: tabTLS, cert: tabCert, http: tabHTTP, content: tabContent, dns: tabDNS, email: tabEmail, compliance: tabCompliance, share: tabShare };

  // ------------------------------------------------------------------ router
  function route() {
    document.body.classList.remove("on-scan");
    if (STANDALONE) {
      const data = JSON.parse(document.getElementById("report-data").textContent);
      renderReport(data, {});
      return;
    }
    const m = location.pathname.match(/^\/scan\/([A-Za-z0-9_-]{8,40})\/?$/);
    if (m) { scanView(m[1]); return; }
    const q = new URLSearchParams(location.search).get("url");
    home(q || "");
  }
  window.addEventListener("popstate", route);
  route();
})();
