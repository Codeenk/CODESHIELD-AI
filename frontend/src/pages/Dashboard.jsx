import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import Icon from "../components/Icon";
import { Donut, SeverityBar, TrendChart } from "../components/Charts";
import { ErrorBlock, LoadingBlock, SeverityBadge, StatusBadge } from "../components/ui";
import { api } from "../lib/api";
import { compact, formatDate, timeAgo, severityMeta, SEVERITIES } from "../lib/format";

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [projects, setProjects] = useState([]);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  async function load() {
    setError("");
    try {
      const [stats, projectList] = await Promise.all([api.stats(14), api.projects()]);
      setData(stats);
      setProjects(projectList.slice(0, 4));
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => { load(); }, []);

  if (error) return <ErrorBlock message={error} onRetry={load} />;
  if (!data) return <LoadingBlock label="Reading security posture" />;

  const critical = data.by_severity?.critical || 0;
  const high = data.by_severity?.high || 0;
  const total = data.findings || 0;
  const topCwes = Object.entries(data.by_cwe || {}).slice(0, 4);
  const maxCwe = Math.max(1, ...topCwes.map(([, value]) => value));

  return (
    <div className="page page--dashboard">
      <header className="page__head">
        <div>
          <span className="eyebrow">Overview · last 14 days</span>
          <h1>Security posture</h1>
          <p>Every finding is a review candidate with a path, evidence, and a verified repair where possible.</p>
        </div>
        <button type="button" className="btn btn--primary" onClick={() => navigate("/scan")}>
          <Icon name="scan" size={17} /> New scan
        </button>
      </header>

      <section className={`posture ${critical ? "posture--critical" : high ? "posture--high" : ""}`}>
        <div className="posture__copy">
          <span className="eyebrow">Current exposure</span>
          <h2>
            {total === 0 ? "No open findings." : `${total} open ${total === 1 ? "finding" : "findings"}`}
            {critical > 0 && <span className="posture__flag">{critical} critical</span>}
          </h2>
          <p>
            {total === 0
              ? "Run a scan to establish a baseline. Suppressed findings stay out of this count."
              : `${critical + high} high-impact ${critical + high === 1 ? "issue needs" : "issues need"} attention across ${data.projects || 0} ${data.projects === 1 ? "project" : "projects"}.`}
          </p>
          <div className="posture__actions">
            <Link className="btn btn--primary btn--sm" to="/history">Review findings <Icon name="arrow" size={15} /></Link>
            <Link className="btn btn--ghost btn--sm" to="/compare">Compare scans</Link>
          </div>
          <div className="posture__strip">
            <span><b>{data.scans || 0}</b> scans</span>
            <span><b>{data.projects || 0}</b> projects</span>
            <span><b>{data.suppressed || 0}</b> suppressed</span>
            <span><b>{data.active_scans || 0}</b> running</span>
          </div>
        </div>
        <div className="posture__chart">
          <Donut counts={data.by_severity || {}} />
          <div className="posture__severity">
            {SEVERITIES.slice(0, 4).map((key) => (
              <span key={key}><i style={{ background: severityMeta[key].color }} />{severityMeta[key].label}<b>{data.by_severity?.[key] || 0}</b></span>
            ))}
          </div>
        </div>
      </section>

      <section className="metrics">
        <Metric label="Open findings" value={compact(total)} foot={`${data.by_status?.fixed || 0} fixed overall`} icon="alert" accent />
        <Metric label="Scans" value={compact(data.scans || 0)} foot={`${data.active_scans || 0} active now`} icon="scan" />
        <Metric label="Projects" value={compact(data.projects || 0)} foot="grouped scan history" icon="folder" />
        <Metric label="Mean time to fix" value={data.mttr_hours ? `${data.mttr_hours}h` : "—"} foot="from first event" icon="clock" />
      </section>

      <div className="dashboard-grid">
        <section className="panel panel--trend">
          <header className="panel__head">
            <div><span className="eyebrow">Signal</span><h2>Findings over time</h2></div>
            <span className="panel__meta">14 day window</span>
          </header>
          <TrendChart data={data.trend || []} />
        </section>

        <section className="panel">
          <header className="panel__head">
            <div><span className="eyebrow">Distribution</span><h2>Severity mix</h2></div>
          </header>
          <SeverityBar counts={data.by_severity || {}} total={total} />
          <div className="cwe-list">
            <span className="eyebrow">Top weakness classes</span>
            {topCwes.length === 0 && <p className="muted">No active findings yet.</p>}
            {topCwes.map(([cwe, value]) => (
              <div className="cwe-row" key={cwe}>
                <code>{cwe}</code>
                <div className="cwe-row__bar"><span style={{ width: `${(value / maxCwe) * 100}%` }} /></div>
                <b>{value}</b>
              </div>
            ))}
          </div>
        </section>
      </div>

      <div className="dashboard-grid dashboard-grid--lower">
        <section className="panel panel--wide">
          <header className="panel__head">
            <div><span className="eyebrow">Recent activity</span><h2>Latest scans</h2></div>
            <Link className="text-link" to="/history">All scans <Icon name="arrow" size={14} /></Link>
          </header>
          {data.recent_scans?.length ? (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Scan</th><th>Status</th><th>Findings</th><th>Engine</th><th>Started</th></tr></thead>
                <tbody>
                  {data.recent_scans.map((scan) => (
                    <tr key={scan.id} onClick={() => navigate(`/scans/${scan.id}`)} tabIndex={0} onKeyDown={(event) => event.key === "Enter" && navigate(`/scans/${scan.id}`)}>
                      <td><strong>{scan.project_name || scan.target}</strong><small>{scan.source_type} · {scan.target}</small></td>
                      <td><StatusBadge status={scan.status} stage={scan.stage} /></td>
                      <td>{scan.summary?.total_findings ?? 0}</td>
                      <td className="muted">{scan.summary?.model_used ? "rules + model" : "rules"}</td>
                      <td className="muted">{timeAgo(scan.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="inline-empty">No scans yet. <Link to="/scan">Run your first scan</Link>.</div>
          )}
        </section>

        <section className="panel">
          <header className="panel__head">
            <div><span className="eyebrow">Coverage</span><h2>Projects</h2></div>
          </header>
          <div className="project-list">
            {projects.length === 0 && <p className="muted">Projects appear after the first scan.</p>}
            {projects.map((project) => (
              <Link className="project-row" key={project.id} to={`/history?project=${project.id}`}>
                <span className="project-row__icon"><Icon name="folder" size={17} /></span>
                <span><strong>{project.name}</strong><small>{project.scan_count} scans · {project.open_findings} open</small></span>
                <span className="project-row__time">{project.last_scan_at ? formatDate(project.last_scan_at, false) : "—"}</span>
              </Link>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}

function Metric({ label, value, foot, icon, accent }) {
  return (
    <div className={`metric-card ${accent ? "metric-card--accent" : ""}`}>
      <span className="metric-card__icon"><Icon name={icon} size={17} /></span>
      <span className="metric-card__label">{label}</span>
      <strong>{value}</strong>
      <small>{foot}</small>
    </div>
  );
}
