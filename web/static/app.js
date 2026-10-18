"use strict";
const $ = (id) => document.getElementById(id);
const con = $("console");

function esc(s) { return (s || "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }

// Light syntax colouring so the console reads like the terminal it wraps.
function colour(text) {
  return esc(text)
    .replace(/^(\s*\[?\s*VULNERABLE.*)$/gm, '<span class="vuln">$1</span>')
    .replace(/\b(VULN|STILL OPEN|CRITICAL|SCOPE BLOCKED|REFUSED)\b/g, '<span class="vuln">$1</span>')
    .replace(/\b(not-reproduced|RE-CONFIRMED|clean|OK|in scope)\b/g, '<span class="ok">$1</span>')
    .replace(/\b(UNMEASURED|inconclusive|WARNING|not confirmed)\b/g, '<span class="warn">$1</span>');
}

function print(label, text, cls) {
  const div = document.createElement("div");
  if (label) div.innerHTML = `<span class="cmd">\n$ ${esc(label)}</span>\n`;
  div.innerHTML += colour(text || "(no output)");
  con.appendChild(div);
  con.scrollTop = con.scrollHeight;
}

async function api(path, body) {
  const opt = body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {};
  const r = await fetch(path, opt);
  return r.json();
}

let busy = false;
async function run(label, path, body, btn) {
  if (busy) return;
  busy = true;
  document.querySelectorAll("button").forEach((b) => (b.disabled = true));
  print(label, "running…");
  const marker = con.lastChild;
  try {
    const res = await api(path, body);
    marker.remove();
    print(label, res.output || res.error || "(done)");
    if (path !== "/api/coverage") await loadFindings();
  } catch (e) {
    marker.remove();
    print(label, "request failed: " + e.message);
  } finally {
    busy = false;
    document.querySelectorAll("button").forEach((b) => (b.disabled = false));
  }
}

async function loadFindings() {
  const { findings } = await api("/api/findings");
  $("fcount").textContent = `${findings.length} finding${findings.length === 1 ? "" : "s"}`;
  const box = $("findings");
  if (!findings.length) { box.innerHTML = '<p class="dim">none yet — run a probe</p>'; return; }
  box.innerHTML = "";
  for (const f of findings) {
    const el = document.createElement("div");
    el.className = "finding " + (f.severity || "Info");
    const where = f.endpoint ? `${f.endpoint}${f.param ? "?" + f.param : ""}` : "";
    el.innerHTML = `<div class="top"><span class="id">${esc(f.id)}</span>
      <span class="sev ${esc(f.severity)}">${esc(f.severity || "Info")}</span></div>
      <div class="title">${esc(f.title || "")}</div>
      <div class="where">${esc(f.class || "")}${where ? " @ " + esc(where) : ""}</div>`;
    el.title = "Click to sweep this finding's class across sibling endpoints";
    el.onclick = () => { $("v-finding").value = f.id; $("v-class").value = ""; print("", `selected ${f.id} — click "Sweep siblings" to hunt variants of its class`); };
    box.appendChild(el);
  }
}

async function boot() {
  const meta = await api("/api/meta");
  const pc = $("p-class"), vc = $("v-class");
  meta.probe_classes.forEach((c) => pc.add(new Option(c, c)));
  vc.add(new Option("(from finding)", ""));
  meta.sweep_classes.forEach((c) => vc.add(new Option(c, c)));
  pc.value = "sqli"; vc.value = "xss";

  const h = await api("/api/health");
  $("base").textContent = "base " + h.base;
  const b = $("bench");
  b.textContent = h.bench ? "● bench up" : "● bench down";
  b.className = "pill " + (h.bench ? "up" : "down");

  const sc = await api("/api/scope");
  $("scope").textContent = sc.exists ? `scope: ${(sc.in_scope || []).join(", ") || sc.target || "?"}` : "no scope";

  await loadFindings();
}

$("run-probe").onclick = () => {
  const body = { class: $("p-class").value, path: $("p-path").value, param: $("p-param").value };
  run(`ptx probe ${body.class} --path ${body.path} --param ${body.param}`, "/api/probe", body);
};
$("run-variants").onclick = () => {
  const body = { class: $("v-class").value, from_finding: $("v-finding").value, discover: $("v-discover").checked };
  const label = body.from_finding ? `ptx variants --from-finding ${body.from_finding}` : `ptx variants --class ${body.class}`;
  run(label + (body.discover ? " --discover" : ""), "/api/variants", body);
};
$("run-retest").onclick = () => run("ptx retest", "/api/retest", {});
$("run-fingerprint").onclick = () => run("ptx fingerprint --cve", "/api/fingerprint", { cve: true });
$("run-discover").onclick = () => run("ptx discover", "/api/discover", {});
$("run-coverage").onclick = async () => { const r = await api("/api/coverage"); print("ptx coverage", r.output); };
$("refresh").onclick = loadFindings;
$("clear").onclick = () => { con.innerHTML = '<span class="dim">console cleared.</span>'; };

boot();
setInterval(loadFindings, 15000);
