import { reportUrl } from "../lib/api.js";

export default function Summary({ scan }) {
  const s = scan.summary || {};
  const sev = s.by_severity || {};
  return (
    <div className="panel">
      <div className="row" style={{ alignItems: "center" }}>
        <div className="grow">
          <h3>{scan.target}</h3>
          <div className="muted">scan {scan.id} · {scan.status}</div>
        </div>
        <div className="actions">
          <a className="tab" href={reportUrl(scan.id, "pdf")} target="_blank" rel="noreferrer">PDF</a>
          <a className="tab" href={reportUrl(scan.id, "sarif")} target="_blank" rel="noreferrer">SARIF</a>
          <a className="tab" href={reportUrl(scan.id, "html")} target="_blank" rel="noreferrer">HTML</a>
          <a className="tab" href={reportUrl(scan.id, "json")} target="_blank" rel="noreferrer">JSON</a>
        </div>
      </div>
      <div className="cards" style={{ marginTop: 12 }}>
        <div className="card"><b>{s.total_findings ?? 0}</b><span>findings</span></div>
        <div className="card"><b className="sev-critical">{sev.critical || 0}</b><span>critical</span></div>
        <div className="card"><b className="sev-high">{sev.high || 0}</b><span>high</span></div>
        <div className="card"><b className="sev-medium">{sev.medium || 0}</b><span>medium</span></div>
        <div className="card"><b className="sev-low">{sev.low || 0}</b><span>low</span></div>
        <div className="card"><b>{s.files_scanned ?? 0}</b><span>files</span></div>
        <div className="card"><b>{s.model_used ? "yes" : "off"}</b><span>model</span></div>
      </div>
    </div>
  );
}
