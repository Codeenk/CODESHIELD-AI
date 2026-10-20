import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import Icon from "../components/Icon";
import SourceView from "../components/SourceView";
import DiffView from "../components/DiffView";
import { Donut, SeverityBar } from "../components/Charts";
import { EmptyState, ErrorBlock, LoadingBlock, Progress, SeverityBadge, StatusBadge } from "../components/ui";
import { api, reportDownload } from "../lib/api";
import { duration, fileName, formatDate, severityMeta, statusLabel, timeAgo, SEVERITIES } from "../lib/format";

const VERIFICATION = {
  verified: { label: "Verified", tone: "ok" },
  partially_verified: { label: "Partially verified", tone: "warn" },
  unverified: { label: "Unverified", tone: "muted" },
  failed: { label: "Failed checks", tone: "bad" },
  rejected: { label: "Rejected", tone: "bad" },
  semantic_risk: { label: "Semantic risk", tone: "warn" },
};

export default function ScanDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [error, setError] = useState("");
  const [tab, setTab] = useState("findings");
  const [selected, setSelected] = useState(null);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [busy, setBusy] = useState(false);
  const timer = useRef(null);

  const load = useCallback(async (quiet = false) => {
    try {
      const data = await api.scan(id);
      setScan(data);
      setError("");
      setSelected((current) => data.findings.find((item) => item.id === current) || data.findings[0] || null);
    } catch (err) {
      if (!quiet) setError(err.message);
    }
  }, [id]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    clearInterval(timer.current);
    if (scan && ["queued", "running"].includes(scan.status)) {
      timer.current = setInterval(() => load(true), 2500);
    }
    return () => clearInterval(timer.current);
  }, [scan?.status, load]);

  const findings = useMemo(() => {
    let list = scan?.findings || [];
    if (severity !== "all") list = list.filter((item) => item.severity === severity);
    const term = query.trim().toLowerCase();
    if (term) {
      list = list.filter((item) =>
        [item.path, item.function, item.cwe, item.cwe_title, item.message].join(" ").toLowerCase().includes(term),
      );
    }
    return list;
  }, [scan, severity, query]);

  async function cancel() {
    setBusy(true);
    try {
      await api.cancelScan(id);
      await load(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!window.confirm("Delete this scan and its findings? This cannot be undone.")) return;
    setBusy(true);
    try {
      await api.deleteScan(id);
      navigate("/history");
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  function statusChanged(updated) {
    setScan((current) => ({
      ...current,
      findings: current.findings.map((item) => (item.id === updated.id ? updated : item)),
    }));
    setSelected(updated);
  }

  if (error && !scan) return <div className="page"><ErrorBlock message={error} onRetry={() => load()} /></div>;
  if (!scan) return <div className="page"><LoadingBlock label="Loading scan" /></div>;

  const running = ["queued", "running"].includes(scan.status);
  const summary = scan.summary || {};
  const counts = summary.by_severity || {};
  const activeFindings = scan.findings.filter((item) => !item.suppressed);

  return (
    <div className="page page--detail">
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/history">History</Link><Icon name="chevron" size={13} /><span>{scan.project_name || "Scan"}</span>
        <span className="crumbs__id">#{scan.id.slice(0, 8)}</span>
      </nav>

      <header className="detail-head">
        <div className="detail-head__title">
          <h1>{scan.project_name || "Scan"}</h1>
          <p><span className="mono">{scan.source_type}</span> · {scan.target}</p>
        </div>
        <div className="detail-head__actions">
          <StatusBadge status={scan.status} stage={scan.stage} />
          {running ? (
            <button type="button" className="btn btn--outline btn--sm" onClick={cancel} disabled={busy}><Icon name="x" size={15} />Cancel</button>
          ) : (
            <>
              <ReportMenu scanId={scan.id} disabled={scan.status !== "completed"} />
              <button type="button" className="btn btn--ghost btn--sm" onClick={remove} disabled={busy} aria-label="Delete scan"><Icon name="trash" size={16} /></button>
            </>
          )}
        </div>
      </header>

      {running && (
        <section className="panel progress-panel">
          <div className="progress-panel__row">
            <span><strong>{scan.stage?.replace(/_/g, " ") || "working"}</strong><small>Queued {timeAgo(scan.created_at)}</small></span>
            <b>{scan.progress}%</b>
          </div>
          <Progress value={scan.progress} label={`Scan progress ${scan.progress}%`} />
          <p className="muted">Ingest, parse, detect, explain, repair, verify. This page updates automatically.</p>
        </section>
      )}

      {scan.error && <ErrorBlock message={scan.error} />}

      <section className="detail-stats">
        <div><span>Findings</span><strong>{summary.total_findings ?? activeFindings.length}</strong></div>
        <div><span>Suppressed</span><strong>{summary.suppressed || 0}</strong></div>
        <div><span>Files</span><strong>{summary.files_scanned || 0}</strong></div>
        <div><span>Units</span><strong>{summary.units_scanned || 0}</strong></div>
        <div><span>Lines</span><strong>{summary.lines_scanned || 0}</strong></div>
        <div><span>Duration</span><strong>{duration(summary.duration_ms)}</strong></div>
      </section>

      {scan.status === "completed" && (
        <div className="detail-tabs" role="tablist" aria-label="Scan views">
          <button type="button" role="tab" aria-selected={tab === "findings"} className={tab === "findings" ? "active" : ""} onClick={() => setTab("findings")}>Findings <b>{activeFindings.length}</b></button>
          <button type="button" role="tab" aria-selected={tab === "coverage"} className={tab === "coverage" ? "active" : ""} onClick={() => setTab("coverage")}>Coverage</button>
          <button type="button" role="tab" aria-selected={tab === "summary"} className={tab === "summary" ? "active" : ""} onClick={() => setTab("summary")}>Summary</button>
        </div>
      )}

      {scan.status === "completed" && tab === "findings" && (
        <section className="findings-layout">
          <div className="findings-list panel">
            <div className="findings-list__filters">
              <div className="search">
                <Icon name="search" size={15} />
                <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter path, function, or CWE" aria-label="Filter findings" />
              </div>
              <div className="sev-chips" role="group" aria-label="Filter by severity">
                <button type="button" className={severity === "all" ? "active" : ""} onClick={() => setSeverity("all")}>All <b>{scan.findings.length}</b></button>
                {SEVERITIES.map((key) => (counts[key] ? (
                  <button type="button" key={key} className={severity === key ? "active" : ""} onClick={() => setSeverity(key)} style={{ "--chip": severityMeta[key].color }}>
                    {severityMeta[key].label} <b>{counts[key]}</b>
                  </button>
                ) : null))}
              </div>
            </div>
            <div className="findings-list__body">
              {findings.length === 0 && (
                <EmptyState icon="check" title={scan.findings.length ? "No matches" : "No findings"} message={scan.findings.length ? "Adjust the filters to widen the result set." : "The deterministic engine found nothing in the scanned units. Absence of findings is not proof of safety."} />
              )}
              {findings.map((finding) => (
                <button
                  type="button" key={finding.id}
                  className={`finding-row ${selected?.id === finding.id ? "active" : ""} ${finding.suppressed ? "finding-row--muted" : ""}`}
                  onClick={() => setSelected(finding)}
                >
                  <span className={`finding-row__sev sev--${finding.severity}`} />
                  <span className="finding-row__main">
                    <strong>{finding.cwe_title || finding.cwe}</strong>
                    <small>{fileName(finding.path)} · {finding.function}</small>
                  </span>
                  <span className="finding-row__meta">
                    <code>{finding.cwe}</code>
                    <small>{Math.round((finding.confidence || 0) * 100)}%</small>
                  </span>
                </button>
              ))}
            </div>
          </div>
          <div className="finding-detail panel">
            {selected ? <FindingPanel finding={selected} onUpdated={statusChanged} /> : (
              <EmptyState icon="scan" title="Select a finding" message="Choose a result to inspect evidence, the data path, and candidate repairs." />
            )}
          </div>
        </section>
      )}

      {scan.status === "completed" && tab === "coverage" && <Coverage scan={scan} />}
      {scan.status === "completed" && tab === "summary" && <SummaryTab scan={scan} />}
    </div>
  );
}

function ReportMenu({ scanId, disabled }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="menu">
      <button type="button" className="btn btn--outline btn--sm" onClick={() => setOpen((v) => !v)} disabled={disabled} aria-expanded={open}>
        <Icon name="download" size={15} />Report<Icon name="chevron" size={13} />
      </button>
      {open && (
        <div className="menu__list" role="menu">
          {[["json", "JSON"], ["sarif", "SARIF 2.1.0"], ["pdf", "PDF"], ["html", "HTML"]].map(([format, label]) => (
            <button key={format} type="button" role="menuitem" onClick={() => { reportDownload(scanId, format); setOpen(false); }}>{label}</button>
          ))}
        </div>
      )}
    </div>
  );
}

function FindingPanel({ finding, onUpdated }) {
  const [tab, setTab] = useState("overview");
  const [events, setEvents] = useState(null);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    setTab("overview");
    setEvents(null);
    setNote("");
    setError("");
  }, [finding.id]);

  useEffect(() => {
    if (tab !== "history" || events) return;
    api.findingEvents(finding.id).then(setEvents).catch((err) => setError(err.message));
  }, [tab, events, finding.id]);

  async function changeStatus(status) {
    setBusy(true);
    setError("");
    try {
      const updated = await api.updateFinding(finding.id, status, note);
      setNote("");
      setEvents(null);
      onUpdated(updated);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const explanation = finding.explanation || {};
  const attribution = explanation.attribution || {};
  const evidence = explanation.evidence?.length ? explanation.evidence : finding.evidence || [];

  return (
    <div className="fp">
      <header className="fp__head">
        <div className="fp__badges">
          <SeverityBadge severity={finding.severity} />
          <span className={`engine engine--${finding.engine}`}>{finding.engine}</span>
          {finding.suppressed && <span className="engine engine--muted">suppressed</span>}
        </div>
        <h2>{finding.cwe_title || finding.cwe}</h2>
        <p className="fp__loc"><code>{finding.path}</code><span>:{finding.evidence?.[0]?.line || finding.start_line}</span> in <strong>{finding.function}</strong></p>
        <div className="fp__meta">
          <span><small>CWE</small><b>{finding.cwe}</b></span>
          <span><small>OWASP</small><b>{finding.owasp || "—"}</b></span>
          <span><small>Confidence</small><b>{Math.round((finding.confidence || 0) * 100)}%</b></span>
          <span><small>Status</small><b>{statusLabel[finding.status] || finding.status}</b></span>
        </div>
      </header>

      <div className="fp__tabs" role="tablist" aria-label="Finding detail">
        {[["overview", "Overview"], ["evidence", "Evidence"], ["repair", `Repair${finding.patch_candidates?.length ? ` (${finding.patch_candidates.length})` : ""}`], ["history", "History"]].map(([key, label]) => (
          <button key={key} type="button" role="tab" aria-selected={tab === key} className={tab === key ? "active" : ""} onClick={() => setTab(key)}>{label}</button>
        ))}
      </div>

      <div className="fp__body">
        {tab === "overview" && (
          <>
            <p className="fp__message">{finding.message}</p>
            <section className="fp__section">
              <h3>Why it matters</h3>
              <p>{explanation.why || "The dangerous operation receives data that is not demonstrably constrained by a security control."}</p>
            </section>
            <section className="fp__section">
              <h3>Attack path</h3>
              <p>{explanation.attack}</p>
            </section>
            <section className="fp__section">
              <h3>Remediation</h3>
              <ul className="bullets">{(explanation.remediation || []).map((item) => <li key={item}>{item}</li>)}</ul>
              {explanation.references?.length > 0 && (
                <p className="fp__refs">{explanation.references.map((ref) => <a key={ref} href={ref} target="_blank" rel="noreferrer noopener">{ref.includes("cwe.mitre.org") ? "CWE definition" : "Reference"}<Icon name="external" size={12} /></a>)}</p>
              )}
            </section>
            <section className="fp__section">
              <h3>{finding.function_source ? "Source" : "Retained evidence"}</h3>
              {finding.function_source ? (
                <SourceView source={finding.function_source} startLine={finding.start_line} highlight={[finding.start_line, finding.end_line]} />
              ) : evidence.length ? (
                <div className="evidence-source">
                  {evidence.map((item, index) => (
                    <div className="evidence-source__row" key={`${item.line}-${index}`}>
                      <span>L{item.line}</span>
                      <code>{item.snippet || "—"}</code>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="muted">Full source was not retained. Enable retention to inspect function bodies.</p>
              )}
            </section>
          </>
        )}

        {tab === "evidence" && (
          <>
            <section className="fp__section">
              <h3>Evidence lines</h3>
              <div className="evidence-list">
                {evidence.map((item, index) => (
                  <div className="evidence" key={`${item.line}-${index}`}>
                    <span className="evidence__line">L{item.line}</span>
                    <div><code>{item.snippet || "—"}</code><p>{item.reason}</p></div>
                    <span className="evidence__weight">{Math.round((item.weight ?? 1) * 100)}</span>
                  </div>
                ))}
              </div>
            </section>
            <section className="fp__section">
              <h3>Attribution <span className="fp__method">{attribution.method?.replace(/-/g, " ")}</span></h3>
              <div className="attribution">
                {(attribution.lines || []).slice(0, 12).map((item) => (
                  <div key={item.line} className="attribution__row">
                    <span>L{item.line}</span>
                    <div><i style={{ width: `${Math.max(3, item.weight * 100)}%` }} /></div>
                    <b>{Math.round(item.weight * 100)}</b>
                  </div>
                ))}
              </div>
              {attribution.model && <p className="muted">Model confidence {Math.round((attribution.model.probability || 0) * 100)}% · rule agreement {Math.round((attribution.model.agreement || 0) * 100)}%.</p>}
            </section>
            <section className="fp__section">
              <h3>AST citations</h3>
              {finding.ast_nodes?.length ? (
                <div className="ast-list">
                  {finding.ast_nodes.map((node, index) => (
                    <div key={`${node.line}-${node.node_type}-${index}`} className="ast-node">
                      <span className={`ast-node__role ast-node__role--${node.role}`}>{node.role}</span>
                      <code>{node.node_type}</code>
                      <span className="ast-node__line">L{node.line}</span>
                      <pre>{node.snippet}</pre>
                    </div>
                  ))}
                </div>
              ) : <p className="muted">No structural citations available for this unit.</p>}
            </section>
          </>
        )}

        {tab === "repair" && (
          <>
            {!finding.patch_candidates?.length && (
              <EmptyState icon="wrench" title="No repair generated" message="This weakness has no safe deterministic template, or repair generation was disabled for the scan." />
            )}
            {finding.patch_candidates?.map((patch, index) => {
              const verification = VERIFICATION[patch.verification] || VERIFICATION.unverified;
              return (
                <article className="patch" key={`${patch.rank}-${index}`}>
                  <header>
                    <span className="patch__rank">#{patch.rank || index + 1}</span>
                    <div><strong>{patch.summary}</strong><small>{patch.generator} · {patch.language || finding.language}</small></div>
                    <span className={`verify verify--${verification.tone}`}><Icon name={verification.tone === "ok" ? "check" : verification.tone === "bad" ? "x" : "alert"} size={13} />{verification.label}</span>
                  </header>
                  {patch.rationale && <p className="patch__rationale">{patch.rationale}</p>}
                  {patch.semantic_risk && <p className="patch__risk"><Icon name="alert" size={14} />Behavior may change. Review the call sites before merging.</p>}
                  <DiffView diff={patch.unified_diff} />
                  <div className="patch__checks">
                    {(patch.checks || []).map((check, checkIndex) => (
                      <span key={checkIndex} className={check.passed === true ? "ok" : check.passed === false ? "bad" : "muted"}>
                        <Icon name={check.passed === true ? "check" : check.passed === false ? "x" : "alert"} size={12} />{check.name || check.check}
                      </span>
                    ))}
                  </div>
                </article>
              );
            })}
            {finding.patch_candidates?.length > 0 && (
              <p className="muted fp__caveat">Verification means the patch parsed, the original signature stayed intact, the vulnerability no longer fires, and no new high-severity finding appeared. It is not a guarantee of semantic equivalence.</p>
            )}
          </>
        )}

        {tab === "history" && (
          <>
            <section className="fp__section">
              <h3>Set status</h3>
              <div className="status-actions">
                {Object.entries(statusLabel).map(([status, label]) => (
                  <button key={status} type="button" className={`btn btn--sm ${finding.status === status ? "btn--primary" : "btn--outline"}`} onClick={() => changeStatus(status)} disabled={busy}>{label}</button>
                ))}
              </div>
              <label className="field">
                <span className="field__label">Note (optional)</span>
                <textarea value={note} onChange={(event) => setNote(event.target.value)} rows={2} placeholder="Why is this being triaged this way?" />
              </label>
              <p className="muted">Suppressing a finding creates a project-level fingerprint so future scans stay quiet.</p>
            </section>
            <section className="fp__section">
              <h3>Event log</h3>
              {!events && <LoadingBlock label="Loading events" />}
              {events?.length === 0 && <p className="muted">No status changes recorded.</p>}
              <div className="timeline">
                {(events || []).map((event, index) => (
                  <div key={index} className="timeline__row">
                    <span className="timeline__dot" />
                    <div><strong>{statusLabel[event.status] || event.status}</strong>{event.note && <p>{event.note}</p>}<small>{formatDate(event.created_at)}</small></div>
                  </div>
                ))}
              </div>
            </section>
          </>
        )}
        {error && <p className="form-error" role="alert">{error}</p>}
      </div>
    </div>
  );
}

function Coverage({ scan }) {
  const summary = scan.summary || {};
  const coverage = summary.coverage || {};
  const byFile = Object.entries(summary.by_file || {}).sort((a, b) => b[1] - a[1]).slice(0, 10);
  const max = Math.max(1, ...byFile.map(([, value]) => value));
  return (
    <div className="coverage-grid">
      <section className="panel">
        <header className="panel__head"><div><span className="eyebrow">Parsed</span><h2>Scan envelope</h2></div></header>
        <dl className="spec-list">
          <div><dt>Languages</dt><dd>{(summary.languages || []).join(", ") || "—"}</dd></div>
          <div><dt>Files</dt><dd>{summary.files_scanned || 0}</dd></div>
          <div><dt>Units</dt><dd>{summary.units_scanned || 0}</dd></div>
          <div><dt>Lines</dt><dd>{summary.lines_scanned || 0}</dd></div>
          <div><dt>Engines</dt><dd>{Object.entries(summary.by_engine || {}).map(([key, value]) => `${key} ${value}`).join(" · ") || "rules"}</dd></div>
          <div><dt>Model</dt><dd>{summary.model_used ? summary.model_id || "loaded" : "not used"}</dd></div>
          <div><dt>Coverage</dt><dd>{coverage.parsed_files != null ? `${coverage.parsed_files} parsed / ${coverage.total_files || summary.files_scanned} files` : "—"}</dd></div>
          <div><dt>Parse failures</dt><dd>{(summary.errors || []).length}</dd></div>
        </dl>
        {summary.engine_notes?.length > 0 && (
          <div className="notes">
            <span className="eyebrow">Engine notes</span>
            {summary.engine_notes.map((note) => <p key={note}>{note}</p>)}
          </div>
        )}
      </section>
      <section className="panel">
        <header className="panel__head"><div><span className="eyebrow">Hot spots</span><h2>Findings per file</h2></div></header>
        {byFile.length === 0 && <p className="muted">No findings to plot.</p>}
        <div className="file-bars">
          {byFile.map(([path, value]) => (
            <div key={path} className="file-bar">
              <span title={path}>{fileName(path)}<small>{path}</small></span>
              <div><i style={{ width: `${(value / max) * 100}%` }} /></div>
              <b>{value}</b>
            </div>
          ))}
        </div>
      </section>
      <section className="panel">
        <header className="panel__head"><div><span className="eyebrow">By class</span><h2>Weakness mix</h2></div></header>
        <SeverityBar counts={summary.by_severity || {}} total={summary.total_findings || 0} />
        <div className="cwe-list">
          {Object.entries(summary.by_cwe || {}).map(([cwe, value]) => (
            <div className="cwe-row" key={cwe}><code>{cwe}</code><div className="cwe-row__bar"><span style={{ width: `${(value / Math.max(1, ...Object.values(summary.by_cwe || {}))) * 100}%` }} /></div><b>{value}</b></div>
          ))}
        </div>
      </section>
      <section className="panel">
        <header className="panel__head"><div><span className="eyebrow">Diagnostics</span><h2>Parse &amp; ingestion errors</h2></div></header>
        {summary.errors?.length ? (
          <ul className="error-list">
            {summary.errors.map((item, index) => <li key={index}><code>{item.path}</code><span>{item.error || item.message}</span></li>)}
          </ul>
        ) : <p className="muted">No ingestion or parse failures recorded.</p>}
      </section>
    </div>
  );
}

function SummaryTab({ scan }) {
  const summary = scan.summary || {};
  const counts = summary.by_severity || {};
  return (
    <div className="coverage-grid">
      <section className="panel panel--summary">
        <header className="panel__head"><div><span className="eyebrow">Scan</span><h2>Report summary</h2></div></header>
        <div className="summary-hero">
          <Donut counts={counts} />
          <div>
            <h3>{summary.total_findings || 0} findings across {summary.files_scanned || 0} files</h3>
            <p>{summary.total_findings ? "Triage each candidate in the findings view. Suppressed results are excluded from project counts." : "No rule or model findings were emitted for this revision."}</p>
            <p className="mono">{formatDate(scan.started_at)} → {formatDate(scan.finished_at)}</p>
          </div>
        </div>
        <SeverityBar counts={counts} total={summary.total_findings || 0} />
      </section>
      <section className="panel">
        <header className="panel__head"><div><span className="eyebrow">Configuration</span><h2>Run parameters</h2></div></header>
        <dl className="spec-list">
          <div><dt>Source</dt><dd>{scan.source_type}</dd></div>
          <div><dt>Target</dt><dd className="mono">{scan.target}</dd></div>
          <div><dt>Repairs</dt><dd>{scan.config?.generate_patches === false ? "disabled" : "enabled"}</dd></div>
          <div><dt>Model mode</dt><dd>{scan.config?.model_mode || "auto"}</dd></div>
          <div><dt>Created</dt><dd>{formatDate(scan.created_at)}</dd></div>
          <div><dt>Finished</dt><dd>{formatDate(scan.finished_at)}</dd></div>
          <div><dt>Suppressed</dt><dd>{summary.suppressed || 0}</dd></div>
          <div><dt>Scan ID</dt><dd className="mono">{scan.id}</dd></div>
        </dl>
        <div className="summary-actions">
          <ReportMenu scanId={scan.id} />
          <Link className="btn btn--ghost btn--sm" to={`/compare?head=${scan.id}`}>Compare revision</Link>
        </div>
      </section>
    </div>
  );
}
