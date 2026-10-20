import Icon from "./Icon";
import { severityMeta } from "../lib/format";

export function Spinner({ label = "Loading" }) {
  return (
    <span className="spinner" role="status" aria-label={label}>
      <span className="spinner__ring" />
    </span>
  );
}

export function LoadingBlock({ label = "Loading" }) {
  return (
    <div className="loading-block">
      <Spinner label={label} />
      <span>{label}</span>
    </div>
  );
}

export function ErrorBlock({ message, onRetry }) {
  return (
    <div className="error-block" role="alert">
      <Icon name="alert" size={18} />
      <div>
        <strong>Something went wrong</strong>
        <p>{message}</p>
      </div>
      {onRetry && (
        <button type="button" className="btn btn--ghost btn--sm" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyState({ icon = "scan", title, message, action }) {
  return (
    <div className="empty">
      <span className="empty__icon"><Icon name={icon} size={24} /></span>
      <h3>{title}</h3>
      <p>{message}</p>
      {action}
    </div>
  );
}

export function SeverityBadge({ severity, count }) {
  const meta = severityMeta[severity] || severityMeta.info;
  return (
    <span className={`sev-badge sev-badge--${severity}`}>
      <span className="sev-badge__dot" style={{ background: meta.color }} />
      {meta.label}
      {count !== undefined && <b>{count}</b>}
    </span>
  );
}

export function StatusBadge({ status, stage }) {
  const label = status === "running" ? stage || "running" : status;
  return <span className={`status status--${status}`}>{label}</span>;
}

export function Field({ label, hint, children, htmlFor }) {
  return (
    <label className="field" htmlFor={htmlFor}>
      <span className="field__label">{label}</span>
      {children}
      {hint && <span className="field__hint">{hint}</span>}
    </label>
  );
}

export function Progress({ value, label }) {
  return (
    <div className="progress" aria-label={label || "Progress"} role="progressbar" aria-valuenow={value} aria-valuemin={0} aria-valuemax={100}>
      <span style={{ width: `${Math.max(2, value || 0)}%` }} />
    </div>
  );
}

export function Modal({ title, children, onClose }) {
  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title} onMouseDown={(event) => event.stopPropagation()}>
        <header><h2>{title}</h2><button type="button" className="icon-btn" onClick={onClose} aria-label="Close"><Icon name="x" /></button></header>
        {children}
      </div>
    </div>
  );
}
