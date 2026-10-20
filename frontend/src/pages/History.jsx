import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import Icon from "../components/Icon";
import { EmptyState, ErrorBlock, LoadingBlock, StatusBadge } from "../components/ui";
import { api } from "../lib/api";
import { duration, fileName, formatDate, timeAgo } from "../lib/format";

const STATUS = [
  ["all", "All"],
  ["completed", "Completed"],
  ["running", "Running"],
  ["failed", "Failed"],
  ["cancelled", "Cancelled"],
];

export default function History() {
  const [params, setParams] = useSearchParams();
  const [data, setData] = useState(null);
  const [projects, setProjects] = useState([]);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [busy, setBusy] = useState("");
  const navigate = useNavigate();
  const projectFilter = params.get("project") || "";

  async function load() {
    setError("");
    try {
      const [list, projectList] = await Promise.all([
        api.scans({ limit: 100, project_id: projectFilter }),
        api.projects(),
      ]);
      setData(list);
      setProjects(projectList);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => { load(); }, [projectFilter]);

  const rows = useMemo(() => {
    let items = data?.items || [];
    if (status !== "all") items = items.filter((item) => item.status === status);
    const term = query.trim().toLowerCase();
    if (term) items = items.filter((item) => `${item.project_name} ${item.target} ${item.source_type}`.toLowerCase().includes(term));
    return items;
  }, [data, status, query]);

  async function remove(scan) {
    if (!window.confirm(`Delete the scan for “${scan.project_name || scan.target}”?`)) return;
    setBusy(scan.id);
    try {
      await api.deleteScan(scan.id);
      setData((current) => ({ ...current, items: current.items.filter((item) => item.id !== scan.id), total: Math.max(0, current.total - 1) }));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  }

  function setProject(value) {
    const next = new URLSearchParams(params);
    if (value) next.set("project", value); else next.delete("project");
    setParams(next, { replace: true });
  }

  return (
    <div className="page">
      <header className="page__head">
        <div>
          <span className="eyebrow">Archive</span>
          <h1>Scan history</h1>
          <p>Every run keeps its envelope, evidence, and verified patches. Suppressed findings remain on record.</p>
        </div>
        <Link className="btn btn--primary" to="/scan"><Icon name="scan" size={17} />New scan</Link>
      </header>

      <div className="toolbar">
        <div className="search search--wide">
          <Icon name="search" size={15} />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search by project, target, or source" aria-label="Search scans" />
        </div>
        <select value={projectFilter} onChange={(event) => setProject(event.target.value)} aria-label="Filter by project">
          <option value="">All projects</option>
          {projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
        </select>
        <div className="segmented" role="group" aria-label="Filter by status">
          {STATUS.map(([key, label]) => (
            <button key={key} type="button" className={status === key ? "active" : ""} onClick={() => setStatus(key)}>{label}</button>
          ))}
        </div>
      </div>

      {error && <ErrorBlock message={error} onRetry={load} />}
      {!data && !error && <LoadingBlock label="Loading scan archive" />}

      {data && rows.length === 0 && (
        <EmptyState
          icon="history"
          title="No scans match"
          message={data.total ? "Clear the search or status filter to see the rest of the archive." : "Run a scan to create the first record."}
          action={<Link className="btn btn--primary btn--sm" to="/scan">Run a scan</Link>}
        />
      )}

      {data && rows.length > 0 && (
        <div className="panel table-panel">
          <div className="table-wrap">
            <table className="table table--scans">
              <thead>
                <tr><th>Project</th><th>Source</th><th>Status</th><th>Findings</th><th>Created</th><th>Duration</th><th aria-label="Actions" /></tr>
              </thead>
              <tbody>
                {rows.map((scan) => {
                  const total = scan.summary?.total_findings || 0;
                  return (
                    <tr key={scan.id}>
                      <td>
                        <button type="button" className="linkish" onClick={() => navigate(`/scans/${scan.id}`)}>
                          <strong>{scan.project_name || "Untitled"}</strong>
                          <small>#{scan.id.slice(0, 8)}</small>
                        </button>
                      </td>
                      <td><span className="tag">{scan.source_type}</span><small className="target">{scan.target}</small></td>
                      <td><StatusBadge status={scan.status} stage={scan.stage} /></td>
                      <td>
                        {total > 0
                          ? <span className="finding-count"><b>{total}</b>{scan.summary?.by_severity?.critical ? <i className="dot dot--accent" title="Critical present" /> : null}</span>
                          : <span className="muted">0</span>}
                      </td>
                      <td className="muted">{timeAgo(scan.created_at)}</td>
                      <td className="muted">{scan.summary?.duration_ms ? duration(scan.summary.duration_ms) : "—"}</td>
                      <td className="row-actions">
                        <button type="button" className="icon-btn" onClick={() => navigate(`/scans/${scan.id}`)} aria-label="Open scan"><Icon name="arrow" size={15} /></button>
                        <button type="button" className="icon-btn" onClick={() => remove(scan)} disabled={busy === scan.id || ["queued", "running"].includes(scan.status)} aria-label="Delete scan"><Icon name="trash" size={15} /></button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <footer className="table-foot"><span>{rows.length} of {data.total} scans</span><span>Retention: snippets and diffs only unless configured</span></footer>
        </div>
      )}
    </div>
  );
}
