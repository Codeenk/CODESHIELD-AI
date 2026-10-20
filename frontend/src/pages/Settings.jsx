import { useEffect, useState } from "react";
import Icon from "../components/Icon";
import { ErrorBlock, LoadingBlock } from "../components/ui";
import { useAuth } from "../lib/auth";
import { api } from "../lib/api";
import { formatDate } from "../lib/format";

export default function Settings() {
  const { user, logout, authEnabled } = useAuth();
  const [meta, setMeta] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.meta().then(setMeta).catch((err) => setError(err.message));
  }, []);

  const initials = (user?.name || user?.email || "CS").split(/\s+/).map((part) => part[0]).slice(0, 2).join("").toUpperCase();

  return (
    <div className="page">
      <header className="page__head">
        <div>
          <span className="eyebrow">Workspace</span>
          <h1>Settings</h1>
          <p>Account identity and the effective server configuration for this instance.</p>
        </div>
      </header>

      {error && <ErrorBlock message={error} />}

      <div className="settings-grid">
        <section className="panel">
          <header className="panel__head"><div><span className="eyebrow">Account</span><h2>Signed-in analyst</h2></div></header>
          {user ? (
            <>
              <div className="account-card">
                <span className="avatar avatar--lg">{initials}</span>
                <div><strong>{user.name}</strong><p>{user.email}</p><small>{user.role} · since {formatDate(user.created_at, false)}</small></div>
              </div>
              <dl className="spec-list">
                <div><dt>User ID</dt><dd className="mono">{user.id}</dd></div>
                <div><dt>Authentication</dt><dd>{authEnabled ? "Local accounts" : "Disabled — local analyst"}</dd></div>
                <div><dt>Session</dt><dd>Opaque HttpOnly cookie</dd></div>
              </dl>
              <button type="button" className="btn btn--outline btn--sm" onClick={logout}><Icon name="logout" size={15} />Sign out</button>
            </>
          ) : <p className="muted">Authentication is disabled for this instance.</p>}
        </section>

        <section className="panel">
          <header className="panel__head"><div><span className="eyebrow">Detection</span><h2>Engine</h2></div></header>
          {!meta && <LoadingBlock label="Reading configuration" />}
          {meta && (
            <dl className="spec-list">
              <div><dt>Version</dt><dd>{meta.version}</dd></div>
              <div><dt>Rule catalog</dt><dd>{meta.capabilities.rules} checks</dd></div>
              <div><dt>Knowledge modules</dt><dd>{meta.capabilities.knowledge_modules}</dd></div>
              <div><dt>Languages</dt><dd>{meta.capabilities.languages.join(", ")}</dd></div>
              <div><dt>Model mode</dt><dd>{meta.model.mode} · {meta.model.used ? meta.model.id || "ready" : "not loaded"}</dd></div>
              <div><dt>Download weights</dt><dd>{meta.model.download_allowed ? "allowed" : "disabled"}</dd></div>
              <div><dt>Repair provider</dt><dd>{meta.repair.provider}{meta.repair.provider !== "none" ? ` · ${meta.repair.model}` : ""}</dd></div>
              <div><dt>Max repair candidates</dt><dd>{meta.repair.max_candidates}</dd></div>
            </dl>
          )}
        </section>

        <section className="panel">
          <header className="panel__head"><div><span className="eyebrow">Execution</span><h2>Sandbox &amp; limits</h2></div></header>
          {!meta && <LoadingBlock label="Reading configuration" />}
          {meta && (
            <dl className="spec-list">
              <div><dt>Sandbox mode</dt><dd>{meta.sandbox.mode}</dd></div>
              <div><dt>Sandbox image</dt><dd className="mono">{meta.sandbox.image}</dd></div>
              <div><dt>Test execution</dt><dd>{meta.sandbox.tests_enabled ? "enabled" : "disabled"}</dd></div>
              <div><dt>Max file</dt><dd>{Math.round(meta.limits.max_file_bytes / 1024 / 1024)} MB</dd></div>
              <div><dt>Max archive</dt><dd>{Math.round(meta.limits.max_archive_bytes / 1024 / 1024)} MB</dd></div>
              <div><dt>Max files</dt><dd>{meta.limits.max_files}</dd></div>
              <div><dt>Concurrent scans</dt><dd>{meta.limits.max_active_scans}</dd></div>
            </dl>
          )}
        </section>

        <section className="panel">
          <header className="panel__head"><div><span className="eyebrow">Privacy</span><h2>Data handling</h2></div></header>
          {!meta && <LoadingBlock label="Reading configuration" />}
          {meta && (
            <>
              <dl className="spec-list">
                <div><dt>Source retention</dt><dd>{meta.privacy.retain_code ? "Full retained" : "Off"}</dd></div>
                <div><dt>Evidence stored</dt><dd>Snippets, line refs, patch diffs</dd></div>
                <div><dt>Secret masking</dt><dd>{meta.privacy.mask_secrets ? "Before persistence" : "Off"}</dd></div>
                <div><dt>Reports</dt><dd>{meta.capabilities.reports.join(", ")}</dd></div>
              </dl>
              <p className="settings-note"><Icon name="lock" size={14} />Retention is a server setting. When off, only bounded evidence snippets and repair diffs are written to the database.</p>
            </>
          )}
        </section>

        <section className="panel settings-wide">
          <header className="panel__head"><div><span className="eyebrow">Operations</span><h2>Runtime notes</h2></div></header>
          <div className="runtime-grid">
            <div><Icon name="shield" size={18} /><h3>Single process</h3><p>Scans run in an in-process worker pool. Run one Uvicorn worker per database; horizontal scaling needs an external queue.</p></div>
            <div><Icon name="code" size={18} /><h3>Deterministic first</h3><p>The model never runs alone. Model-only findings are gated because they lack a structural data path.</p></div>
            <div><Icon name="check" size={18} /><h3>Verified repairs</h3><p>A patch is verified only after parse, rescan, signature preservation, and new-finding checks pass.</p></div>
            <div><Icon name="alert" size={18} /><h3>Human review</h3><p>Findings remain review candidates. Verification is not proof of semantic equivalence or absence of other flaws.</p></div>
          </div>
        </section>
      </div>
    </div>
  );
}
