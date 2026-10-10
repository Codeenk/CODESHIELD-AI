import { useEffect, useState } from "react";
import DiffView from "./DiffView.jsx";

const STATUSES = [
  ["open", "Open"],
  ["fixed", "Fixed"],
  ["false_positive", "False positive"],
  ["accepted_risk", "Accepted risk"],
];

export default function FindingDetail({ finding, onStatus, busy }) {
  const [idx, setIdx] = useState(0);
  useEffect(() => setIdx(0), [finding.id]);

  if (!finding) return <div className="panel muted">Select a finding to see details, evidence, and a suggested fix.</div>;

  const candidates = finding.patch_candidates || [];
  const candidate = candidates[idx];
  const explanation = finding.explanation || {};

  return (
    <div className="panel col">
      <div>
        <h2 className={`sev-${finding.severity}`}>{finding.cwe_title || finding.cwe}</h2>
        <div className="muted">{finding.path} :: {finding.function} · lines {finding.start_line}–{finding.end_line}</div>
        <div className="pills">
          <span className="pill">{finding.cwe}</span>
          {finding.owasp && <span className="pill">{finding.owasp}</span>}
          <span className={`pill sev-${finding.severity}`}>{finding.severity}</span>
          <span className="pill">engine: {finding.engine}</span>
          <span className="pill">confidence: {Math.round((finding.confidence || 0) * 100)}%</span>
          {finding.knowledge_ref && <span className="pill">KB: {finding.knowledge_ref}</span>}
        </div>
      </div>

      <div>
        <h3>Why this is risky</h3>
        <p>{explanation.why || finding.message}</p>
        <p className="muted"><b>Fix guidance:</b> {explanation.remediation}</p>
      </div>

      {finding.evidence && finding.evidence.length > 0 && (
        <div>
          <h3>Evidence</h3>
          {finding.evidence.map((e, i) => (
            <pre className="evidence" key={i}>L{e.line} · {e.reason}
{"> "}{e.snippet}</pre>
          ))}
        </div>
      )}

      <div>
        <h3>Suggested patches ({candidates.length})</h3>
        {candidates.length === 0 && <div className="muted">No patch could be generated automatically.</div>}
        {candidates.length > 0 && (
          <>
            <div className="pills" style={{ marginBottom: 10 }}>
              {candidates.map((c, i) => (
                <span key={i} className={`tab ${i === idx ? "active" : ""}`} onClick={() => setIdx(i)}>
                  #{c.rank} {c.summary}
                </span>
              ))}
            </div>
            <div className="pills" style={{ marginBottom: 8 }}>
              <span className={`pill ${candidate.verification}`}>{candidate.verification.replace("_", " ")}</span>
              {candidate.semantic_risk && <span className="pill sev-medium">behaviour change</span>}
            </div>
            <DiffView original={finding.function_source} modified={candidate.source} filename={finding.path} />
            {candidate.checks && (
              <ul className="muted" style={{ fontSize: 12, marginTop: 8 }}>
                {candidate.checks.map((c, i) => (
                  <li key={i}>
                    {c.name}: {c.ok === null ? "⚠ skipped" : c.ok ? "✔ pass" : "✘ fail"} — {c.detail}
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </div>

      <div>
        <h3>Status</h3>
        <div className="actions">
          {STATUSES.map(([value, label]) => (
            <button key={value} className={finding.status === value ? "" : "secondary"}
                    disabled={busy} onClick={() => onStatus(finding.id, value)}>
              {label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
