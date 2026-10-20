import { useEffect, useMemo, useState } from "react";
import Icon from "../components/Icon";
import { EmptyState, ErrorBlock, LoadingBlock, SeverityBadge } from "../components/ui";
import { api } from "../lib/api";

export default function Knowledge() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [tab, setTab] = useState("library");

  useEffect(() => {
    api.knowledge().then((payload) => {
      setData(payload);
      setSelected(payload.items[0]?.slug || null);
    }).catch((err) => setError(err.message));
  }, []);

  useEffect(() => {
    if (!selected) return;
    setDetail(null);
    api.knowledgeItem(selected).then(setDetail).catch((err) => setError(err.message));
  }, [selected]);

  const items = useMemo(() => {
    if (!data) return [];
    const term = query.trim().toLowerCase();
    if (!term) return data.items;
    return data.items.filter((item) => [item.name, item.cwe, item.cwe_title, item.owasp, item.description].join(" ").toLowerCase().includes(term));
  }, [data, query]);

  if (error && !data) return <div className="page"><ErrorBlock message={error} /></div>;
  if (!data) return <div className="page"><LoadingBlock label="Loading knowledge base" /></div>;

  return (
    <div className="page">
      <header className="page__head">
        <div>
          <span className="eyebrow">Reference</span>
          <h1>Security knowledge</h1>
          <p>Explanations cite this library. Open a module to read the attack path and remediation guidance behind a rule.</p>
        </div>
        <div className="kb-stats">
          <span><b>{data.items.length}</b> modules</span>
          <span><b>{data.rules.length}</b> rules</span>
        </div>
      </header>

      <div className="detail-tabs" role="tablist" aria-label="Knowledge views">
        <button type="button" role="tab" aria-selected={tab === "library"} className={tab === "library" ? "active" : ""} onClick={() => setTab("library")}>Library</button>
        <button type="button" role="tab" aria-selected={tab === "rules"} className={tab === "rules" ? "active" : ""} onClick={() => setTab("rules")}>Rule catalog <b>{data.rules.length}</b></button>
      </div>

      {tab === "library" && (
        <section className="kb-layout">
          <div className="panel kb-list">
            <div className="search">
              <Icon name="search" size={15} />
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search CWE, OWASP, or weakness" aria-label="Search knowledge" />
            </div>
            <div className="kb-list__body">
              {items.length === 0 && <p className="muted kb-list__empty">No modules match that search.</p>}
              {items.map((item) => (
                <button type="button" key={item.slug} className={`kb-row ${selected === item.slug ? "active" : ""}`} onClick={() => setSelected(item.slug)}>
                  <span><strong>{item.name}</strong><small>{item.cwe_title}</small></span>
                  <code>{item.cwe}</code>
                </button>
              ))}
            </div>
          </div>
          <article className="panel kb-detail">
            {!detail && <LoadingBlock label="Opening module" />}
            {detail && (
              <>
                <header className="kb-detail__head">
                  <div className="kb-detail__badges"><SeverityBadge severity={detail.severity} /><code>{detail.cwe}</code>{detail.owasp && <span className="tag">{detail.owasp}</span>}</div>
                  <h2>{detail.name}</h2>
                  <p>{detail.description}</p>
                </header>
                {detail.attack && (
                  <section className="kb-section">
                    <h3>Attack path</h3>
                    <p>{detail.attack}</p>
                  </section>
                )}
                {detail.remediation?.length > 0 && (
                  <section className="kb-section">
                    <h3>Remediation</h3>
                    <ul className="bullets">{detail.remediation.map((line) => <li key={line}>{line}</li>)}</ul>
                  </section>
                )}
                <section className="kb-section kb-section--markdown">
                  <h3>Guidance</h3>
                  <Markdown text={detail.markdown} />
                </section>
                {detail.references?.length > 0 && (
                  <section className="kb-section">
                    <h3>References</h3>
                    <div className="kb-refs">
                      {detail.references.map((ref) => <a key={ref} href={ref} target="_blank" rel="noreferrer noopener">{ref.replace(/^https?:\/\//, "").slice(0, 64)}<Icon name="external" size={12} /></a>)}
                    </div>
                  </section>
                )}
              </>
            )}
          </article>
        </section>
      )}

      {tab === "rules" && (
        <section className="panel">
          <header className="panel__head"><div><span className="eyebrow">Deterministic</span><h2>Detection catalog</h2></div></header>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Rule</th><th>CWE</th><th>OWASP</th><th>Severity</th></tr></thead>
              <tbody>
                {data.rules.map((rule) => (
                  <tr key={rule.slug}>
                    <td><strong>{rule.slug.replace(/_/g, " ")}</strong><small>{rule.cwe_title}</small></td>
                    <td><code>{rule.cwe}</code></td>
                    <td className="muted">{rule.owasp || "—"}</td>
                    <td><SeverityBadge severity={rule.severity} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}

function Markdown({ text }) {
  if (!text) return <p className="muted">No additional guidance stored.</p>;
  const blocks = [];
  let code = null;
  let list = null;
  text.split("\n").forEach((raw, index) => {
    const line = raw.trimEnd();
    if (line.startsWith("```")) {
      if (code !== null) { blocks.push(<pre key={`c${index}`}><code>{code.join("\n")}</code></pre>); code = null; }
      else code = [];
      return;
    }
    if (code !== null) { code.push(line); return; }
    if (/^\s*[-*]\s+/.test(line)) {
      list = list || [];
      list.push(line.replace(/^\s*[-*]\s+/, ""));
      return;
    }
    if (list) { blocks.push(<ul key={`l${index}`} className="bullets">{list.map((item) => <li key={item}>{item.replace(/\*\*/g, "")}</li>)}</ul>); list = null; }
    if (/^#{1,3}\s/.test(line)) { blocks.push(<h4 key={index}>{line.replace(/^#+\s/, "")}</h4>); return; }
    if (line.trim()) blocks.push(<p key={index}>{line.replace(/\*\*/g, "").replace(/`([^`]+)`/g, "$1")}</p>);
  });
  if (code !== null) blocks.push(<pre key="clast"><code>{code.join("\n")}</code></pre>);
  if (list) blocks.push(<ul key="llast" className="bullets">{list.map((item) => <li key={item}>{item.replace(/\*\*/g, "")}</li>)}</ul>);
  return <div className="markdown">{blocks}</div>;
}
