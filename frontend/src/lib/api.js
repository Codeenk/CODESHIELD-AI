const BASE = "/api/v1";

async function handle(res) {
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  return res.json();
}

export async function scanCode(code, filename) {
  const res = await fetch(`${BASE}/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, filename }),
  });
  return handle(res);
}

export async function scanFiles(fileList) {
  const form = new FormData();
  for (const file of fileList) form.append("files", file);
  const res = await fetch(`${BASE}/scans`, { method: "POST", body: form });
  return handle(res);
}

export async function scanRepo(repoUrl, branch) {
  const res = await fetch(`${BASE}/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo_url: repoUrl, branch: branch || null }),
  });
  return handle(res);
}

export async function listScans() {
  return handle(await fetch(`${BASE}/scans`));
}

export async function setFindingStatus(id, status) {
  return handle(
    await fetch(`${BASE}/findings/${id}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    })
  );
}

export async function getKnowledge() {
  return handle(await fetch(`${BASE}/knowledge`));
}

export function reportUrl(scanId, format) {
  return `${BASE}/scans/${scanId}/report?format=${format}`;
}
