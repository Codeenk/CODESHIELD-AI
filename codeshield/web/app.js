"use strict";

const state = { scan: null, selected: null, pollTimer: null };

const $ = (id) => document.getElementById(id);

function token() {
  return $("token").value.trim();
}

function authHeaders() {
  const t = token();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { ...(options.headers || {}), ...authHeaders() },
  });
  return response;
}

// ---------------------------------------------------------------- health ---
async function checkHealth() {
  const badge = $("engine-badge");
  try {
    const response = await api("/health");
    const data = await response.json();
    if (data.model_available) {
      badge.textContent = `CodeBERT + rules (${data.model_id.split("/").pop()})`;
      badge.className = "badge badge-verified";
    } else {
      badge.textContent = "Rules only (model unavailable)";
      badge.className = "badge badge-partial";
      badge.title = data.model_note || "";
    }
  } catch (error) {
    badge.textContent = "API unreachable";
    badge.className = "badge badge-unverified";
  }
}

// ------------------------------------------------------------------ scan ---
async function startUpload() {
  const input = $("file-input");
  if (!input.files.length) {
    setStatus("Choose a file first.");
    return;
  }
  const body = new FormData();
  body.append("file", input.files[0]);
  setStatus("Uploading…");
  const response = await api("/api/scans", { method: "POST", body });
  if (!response.ok) {
    setStatus(`Upload failed: ${response.status}`);
    return;
  }
  const { id } = await response.json();
  poll(id);
}

async function startGithub() {
  const url = $("github-url").value.trim();
  if (!url) {
    setStatus("Enter a GitHub repository URL.");
    return;
  }
  setStatus("Requesting clone…");
  const response = await api("/api/scans/github", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    setStatus(`Failed: ${detail.detail || response.status}`);
    return;
  }
  const { id } = await response.json();
  poll(id);
}

function setStatus(text) {
  $("scan-status").textContent = text;
}

function poll(scanId) {
  clearInterval(state.pollTimer);
  let dots = 0;
  state.pollTimer = setInterval(async () => {
    dots = (dots + 1) % 4;
    setStatus(`Scanning${".".repeat(dots)}`);
    const response = await api(`/api/scans/${scanId}`);
    if (!response.ok) return;
    const scan = await response.json();
    if (scan.status === "done") {
      clearInterval(state.pollTimer);
      setStatus(`Done — ${scan.summary.total_findings} finding(s).`);
      state.scan = scan;
      renderScan(scan);
    } else if (scan.status === "error") {
      clearInterval(state.pollTimer);
      setStatus(`Scan error: ${scan.error}`);
    }
  }, 1500);
}

// ---------------------------------------------------------------- render ---
function renderScan(scan) {
  $("summary").classList.remove("hidden");
  const cards = $("severity-cards");
  cards.innerHTML = "";
  const order = ["critical", "high", "medium", "low"];
  for (const severity of order) {
    const count = scan.summary.by_severity[severity] || 0;
    const div = document.createElement("div");
    div.className = `card ${severity}`;
    div.innerHTML = `<div class="value">${count}</div><div class="label">${severity}</div>`;
    cards.appendChild(div);
  }

  const meta = $("scan-meta");
  meta.innerHTML =
    `<div><strong>Scan</strong> ${scan.id}</div>` +
    `<div class="muted">${scan.source}</div>` +
    `<div class="muted">Files: ${scan.summary.files_scanned} scanned, ${scan.summary.files_skipped} skipped</div>` +
    `<div class="muted">Model: ${scan.model_version || "rules only"}</div>` +
    `<div class="muted">Patches verified: ${scan.summary.patches_verified}/${scan.patches.length}</div>`;

  const dist = $("cwe-dist");
  dist.innerHTML =
    `<strong>CWE distribution</strong><div class="tags">` +
    Object.entries(scan.summary.by_cwe)
      .map(([cwe, n]) => `<span class="tag">${cwe} × ${n}</span>`)
      .join("") +
    `</div>`;

  populateFilters(scan);
  renderFindings();
}

function populateFilters(scan) {
  const sev = $("severity-filter");
  const cwe = $("cwe-filter");
  sev.innerHTML = `<option value="">All severities</option>`;
  cwe.innerHTML = `<option value="">All CWEs</option>`;
  for (const severity of ["critical", "high", "medium", "low", "info"]) {
    if ((scan.summary.by_severity[severity] || 0) > 0) {
      sev.innerHTML += `<option value="${severity}">${severity}</option>`;
    }
  }
  for (const key of Object.keys(scan.summary.by_cwe)) {
    cwe.innerHTML += `<option value="${key}">${key}</option>`;
  }
}

function visibleFindings() {
  if (!state.scan) return [];
  const severity = $("severity-filter").value;
  const cwe = $("cwe-filter").value;
  const text = $("text-filter").value.toLowerCase();
  return state.scan.findings.filter((finding) => {
    if (severity && finding.severity !== severity) return false;
    if (cwe && finding.cwe !== cwe) return false;
    if (text && !`${finding.file} ${finding.title}`.toLowerCase().includes(text)) return false;
    return true;
  });
}

function renderFindings() {
  const list = $("findings");
  const findings = visibleFindings();
  $("finding-count").textContent = state.scan ? `${findings.length}/${state.scan.findings.length}` : "";
  $("findings-empty").classList.toggle("hidden", findings.length > 0);
  list.innerHTML = "";
  for (const finding of findings) {
    const li = document.createElement("li");
    li.className = `sev-${finding.severity}` + (state.selected === finding.id ? " active" : "");
    li.innerHTML =
      `<div class="title">${escapeHtml(finding.title)}</div>` +
      `<div class="path">${finding.cwe} · ${finding.severity} · ${(finding.confidence * 100).toFixed(0)}% · ${finding.engine}` +
      (finding.status !== "open" ? ` · ${finding.status}` : "") +
      `</div>` +
      `<div class="path">${escapeHtml(finding.file)}:${finding.location.start_line}</div>`;
    li.onclick = () => selectFinding(finding.id);
    list.appendChild(li);
  }
}

function selectFinding(id) {
  state.selected = id;
  const finding = state.scan.findings.find((f) => f.id === id);
  if (!finding) return;
  renderFindings();

  $("detail-placeholder").classList.add("hidden");
  $("detail").classList.remove("hidden");
  $("detail-title").textContent = `${finding.cwe} — ${finding.cwe_name}`;
  $("detail-tags").innerHTML =
    `<span class="tag">severity: ${finding.severity}</span>` +
    `<span class="tag">confidence: ${(finding.confidence * 100).toFixed(0)}%</span>` +
    `<span class="tag">engine: ${finding.engine}</span>` +
    `<span class="tag">${finding.owasp || "n/a"}</span>` +
    (finding.location.function ? `<span class="tag">fn: ${finding.location.function}</span>` : "");
  $("detail-rationale").textContent = finding.rationale;
  $("detail-remediation").textContent = finding.remediation ? `Remediation: ${finding.remediation}` : "";

  const attention = $("detail-attention");
  attention.innerHTML = finding.attention
    .slice()
    .sort((a, b) => b.score - a.score)
    .slice(0, 8)
    .map(
      (row) =>
        `<div class="heat-row"><span class="line">L${row.line}</span>` +
        `<span class="bar" style="width:${Math.max(4, row.score * 220)}px"></span>` +
        `<span class="muted">${row.score.toFixed(2)}</span></div>`
    )
    .join("");
  $("detail-nodes").innerHTML = finding.syntax_nodes
    .map((node) => `<span class="tag">${escapeHtml(node)}</span>`)
    .join("");

  const patch = (state.scan.patches || []).find((p) => p.finding_id === finding.id);
  const status = $("patch-status");
  const diff = $("diff");
  if (patch) {
    status.textContent = patch.status.toUpperCase();
    status.className = `badge badge-${patch.status}`;
    $("patch-summary").textContent = `${patch.summary} — source: ${patch.source}`;
    diff.innerHTML = renderDiff(patch.diff);
  } else {
    status.textContent = "NO PATCH";
    status.className = "badge badge-unverified";
    $("patch-summary").textContent = "No patch was generated for this finding.";
    diff.innerHTML = "";
  }
}

function renderDiff(text) {
  const lines = (text || "").split("\n").map((line) => {
    let cls = "";
    if (line.startsWith("+") && !line.startsWith("+++")) cls = "add";
    if (line.startsWith("-") && !line.startsWith("---")) cls = "del";
    return `<span class="${cls}">${escapeHtml(line)}</span>`;
  });
  return `<pre>${lines.join("\n")}</pre>`;
}

async function setLifecycle(status) {
  if (!state.scan || !state.selected) return;
  const response = await api(`/api/scans/${state.scan.id}/findings/${state.selected}/status`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
  if (!response.ok) {
    setStatus(`Update failed: ${response.status}`);
    return;
  }
  const finding = state.scan.findings.find((f) => f.id === state.selected);
  if (finding) finding.status = status;
  renderFindings();
  setStatus(`Finding marked ${status}.`);
}

async function downloadReport(format) {
  if (!state.scan) return;
  const response = await api(`/api/scans/${state.scan.id}/report?format=${format}`);
  if (!response.ok) {
    setStatus(`Export failed: ${response.status}`);
    return;
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `codeshield-${state.scan.id}.${format}`;
  link.click();
  URL.revokeObjectURL(url);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

// ------------------------------------------------------------------ wire ---
$("upload-btn").onclick = startUpload;
$("github-btn").onclick = startGithub;
$("severity-filter").onchange = renderFindings;
$("cwe-filter").onchange = renderFindings;
$("text-filter").oninput = renderFindings;
for (const button of document.querySelectorAll("[data-life]")) {
  button.onclick = () => setLifecycle(button.dataset.life);
}
for (const button of document.querySelectorAll("[data-report]")) {
  button.onclick = () => downloadReport(button.dataset.report);
}
$("token").addEventListener("change", () => {
  try {
    localStorage.setItem("codeshield_token", token());
  } catch (error) {
    /* storage disabled */
  }
  checkHealth();
});

try {
  const saved = localStorage.getItem("codeshield_token");
  if (saved) $("token").value = saved;
} catch (error) {
  /* storage disabled */
}

checkHealth();
