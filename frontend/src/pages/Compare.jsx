import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import Icon from "../components/Icon";
import { EmptyState, ErrorBlock, LoadingBlock, SeverityBadge } from "../components/ui";
import { api } from "../lib/api";
import { fileName, formatDate } from "../lib/format";

export default function Compare() {
  const [params, setParams] = useSearchParams();
  const [scans, setScans] = useState([]);
  const [base, setBase] = useState(params.get("base") || "");
  const [head, setHead] = useState(params.get("head") || "");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.scans({ limit: 100, status: "completed" }).then((data) => {
      setScans(data.items);
      if (!base && !head) {
        const ordered = data.items;
        if (ordered.length >= 2) {
          setHead(ordered[0].id);
          setBase(ordered[1].id);
        }
      }
    }).catch((err) => setError(err.message));
  }, []);

  useEffect(() => {
    if (!base || !head || base === head) {
      setResult(null);
      return;
    }
    setLoading(true);
    setError("");
    const next = new URLSearchParams(params);
    next.set("base", base);
    next.set("head", head);
    setParams(next, { replace: true });
    api.compare(base, head)
      .then(setResult)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [base, head]);

  const baseScan = useMemo(() => scans.find((item) => item.id === base), [scans, base]);
  const headScan = useMemo(() => scans.find((item) => item.id === head), [scans, head]);

  return (
    <div className="page">
      <header className="page__head">
        <div>
          <span className="eyebrow">Revision diff</span>
          <h1>Compare scans</h1>
          <p>Fingerprints are stable across revisions, so a renamed line does not appear as a new finding.</p>
        </div>
      </header>

      {scans.length < 2 ? (
        <EmptyState icon="code" title="Two completed scans needed" message="Complete two scans in the same project to compare their attack surface." action={<Link className="btn btn--primary btn--sm" to="/scan">Run a scan</Link>} />
      ) : (
        <>
          <section className="panel compare-picker">
            <div className="compare-picker__side">
              <span className="eyebrow">Base</span>
              <select value={base} onChange={(event) => setBase(event.target.value)} aria-label="Base scan">
                <option value="">Choose a baseline</option>
                {scans.filter((item) => item.id !== head).map((scan) => (
                  <option key={scan.id} value={scan.id}>{scan.project_name} · {formatDate(scan.created_at, false)} · {scan.summary?.total_findings || 0} findings</option>
                ))}
              </select>
              {baseScan && <small>{baseScan.target}</small>}
            </div>
            <span className="compare-picker__arrow"><Icon name="arrow" size={18} /></span>
            <div className="compare-picker__side">
              <span className="eyebrow">Head</span>
              <select value={head} onChange={(event) => setHead(event.target.value)} aria-label="Head scan">
                <option value="">Choose a revision</option>
                {scans.filter((item) => item.id !== base).map((scan) => (
                  <option key={scan.id} value={scan.id}>{scan.project_name} · {formatDate(scan.created_at, false)} · {scan.summary?.total_findings || 0} findings</option>
                ))}
              </select>
              {headScan && <small>{headScan.target}</small>}
            </div>
          </section>

          {loading && <LoadingBlock label="Diffing findings" />}
          {error && <ErrorBlock message={error} />}
          {base === head && base && <p className="inline-note">Choose two different scans.</p>}

          {result && !loading && (
            <>
              <section className="compare-metrics">
                <div className="compare-metric compare-metric--bad"><span>Introduced</span><strong>{result.introduced}</strong><small>new fingerprints</small></div>
                <div className="compare-metric compare-metric--good"><span>Resolved</span><strong>{result.resolved}</strong><small>no longer present</small></div>
                <div className="compare-metric"><span>Recurring</span><strong>{result.unchanged}</strong><small>same fingerprint</small></div>
              </section>

              <div className="compare-columns">
                <CompareList title="New in head" tone="bad" icon="alert" items={result.new} scanId={head} />
                <CompareList title="Fixed in head" tone="good" icon="check" items={result.fixed} scanId={base} />
              </div>

              <section className="panel">
                <header className="panel__head">
                  <div><span className="eyebrow">Carried forward</span><h2>Recurring findings</h2></div>
                  <span className="panel__meta">{result.recurring.length} unchanged</span>
                </header>
                {result.recurring.length === 0 ? <p className="muted">No fingerprint appears in both scans.</p> : (
                  <div className="compare-table">
                    {result.recurring.map((item) => (
                      <div key={item.fingerprint} className="compare-row">
                        <SeverityBadge severity={item.severity} />
                        <span><strong>{item.cwe_title || item.cwe}</strong><small>{item.path}:{item.line} · {item.function}</small></span>
                        <code>{item.cwe}</code>
                      </div>
                    ))}
                  </div>
                )}
              </section>
            </>
          )}
        </>
      )}
    </div>
  );
}

function CompareList({ title, tone, icon, items, scanId }) {
  return (
    <section className={`panel compare-list compare-list--${tone}`}>
      <header className="panel__head">
        <div><span className="eyebrow">{tone === "bad" ? "Regression" : "Improvement"}</span><h2>{title}</h2></div>
        <span className="compare-list__count"><Icon name={icon} size={14} />{items.length}</span>
      </header>
      {items.length === 0 && <p className="muted">Nothing in this category.</p>}
      <div className="compare-table">
        {items.map((item) => (
          <Link key={item.fingerprint} className="compare-row compare-row--link" to={`/scans/${scanId}`}>
            <SeverityBadge severity={item.severity} />
            <span><strong>{item.cwe_title || item.cwe}</strong><small>{fileName(item.path)}:{item.line} · {item.function}</small></span>
            <code>{item.cwe}</code>
          </Link>
        ))}
      </div>
    </section>
  );
}
