const ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export default function FindingList({ findings, selected, onSelect }) {
  const sorted = [...findings].sort((a, b) => ORDER[b.severity] - ORDER[a.severity]);
  if (!findings.length) {
    return <div className="panel muted">No findings. 🎉</div>;
  }
  return (
    <div className="panel col">
      <h3>Findings ({findings.length})</h3>
      {sorted.map((f) => (
        <div key={f.id}
             className={`finding sev-border ${selected && selected.id === f.id ? "selected" : ""}`}
             onClick={() => onSelect(f)}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
            <b className={`sev-${f.severity}`}>{f.cwe_title || f.cwe}</b>
            <span className="muted">{f.confidence ? `${Math.round(f.confidence * 100)}%` : ""}</span>
          </div>
          <div className="meta">{f.path} · {f.function} · L{f.start_line}</div>
          <div className="pills">
            <span className="pill">{f.cwe}</span>
            <span className={`pill sev-${f.severity}`}>{f.severity}</span>
            <span className="pill">{f.engine}</span>
            {f.status && f.status !== "open" && <span className="pill">{f.status}</span>}
          </div>
        </div>
      ))}
    </div>
  );
}
