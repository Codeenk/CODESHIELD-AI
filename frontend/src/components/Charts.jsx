import { severityMeta, SEVERITIES } from "../lib/format";

export function TrendChart({ data = [], height = 190 }) {
  const points = data.length ? data : [];
  const width = 640;
  const max = Math.max(1, ...points.map((item) => item.findings), ...points.map((item) => item.scans));
  const step = points.length > 1 ? width / (points.length - 1) : width;
  const y = (value) => height - 22 - (value / max) * (height - 40);
  const line = points.map((item, index) => `${index === 0 ? "M" : "L"}${(index * step).toFixed(1)},${y(item.findings).toFixed(1)}`).join(" ");
  const area = points.length
    ? `${line} L${width},${height - 22} L0,${height - 22} Z`
    : "";
  const scanLine = points.map((item, index) => `${index === 0 ? "M" : "L"}${(index * step).toFixed(1)},${y(item.scans).toFixed(1)}`).join(" ");

  return (
    <div className="chart">
      <div className="chart__legend">
        <span><i className="dot dot--accent" />Findings</span>
        <span><i className="dot dot--muted" />Scans</span>
      </div>
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Findings and scans over time" preserveAspectRatio="none">
        <defs>
          <linearGradient id="trend-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#f97316" stopOpacity="0.28" />
            <stop offset="100%" stopColor="#f97316" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0.25, 0.5, 0.75, 1].map((tick) => (
          <line key={tick} x1="0" x2={width} y1={y(max * tick)} y2={y(max * tick)} className="chart__grid" />
        ))}
        {area && <path d={area} fill="url(#trend-fill)" />}
        {line && <path d={line} className="chart__line" />}
        {scanLine && <path d={scanLine} className="chart__line chart__line--muted" />}
        {points.map((item, index) => (
          <g key={item.day}>
            <circle cx={index * step} cy={y(item.findings)} r="2.4" className="chart__point" />
            <title>{`${item.day}: ${item.findings} findings, ${item.scans} scans`}</title>
          </g>
        ))}
      </svg>
      <div className="chart__axis">
        {points.map((item, index) => (
          index % Math.ceil(points.length / 7) === 0 ? <span key={item.day}>{item.day.slice(5)}</span> : null
        ))}
      </div>
    </div>
  );
}

export function SeverityBar({ counts = {}, total = 0 }) {
  const safeTotal = total || SEVERITIES.reduce((sum, key) => sum + (counts[key] || 0), 0);
  return (
    <div className="severity-bar">
      <div className="severity-bar__track" aria-hidden="true">
        {SEVERITIES.map((key) => {
          const value = counts[key] || 0;
          if (!value) return null;
          return (
            <span
              key={key}
              style={{ width: `${(value / Math.max(1, safeTotal)) * 100}%`, background: severityMeta[key].color }}
              title={`${severityMeta[key].label}: ${value}`}
            />
          );
        })}
      </div>
      <div className="severity-bar__legend">
        {SEVERITIES.map((key) => (
          <span key={key}><i style={{ background: severityMeta[key].color }} />{severityMeta[key].label}<b>{counts[key] || 0}</b></span>
        ))}
      </div>
    </div>
  );
}

export function Donut({ counts = {}, size = 148 }) {
  const total = Object.values(counts).reduce((sum, value) => sum + value, 0);
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  return (
    <div className="donut">
      <svg width={size} height={size} viewBox="0 0 128 128" role="img" aria-label="Findings by severity">
        <circle cx="64" cy="64" r={radius} className="donut__track" />
        {SEVERITIES.map((key) => {
          const value = counts[key] || 0;
          if (!value) return null;
          const length = (value / Math.max(1, total)) * circumference;
          const dash = `${length} ${circumference - length}`;
          const element = (
            <circle
              key={key} cx="64" cy="64" r={radius} fill="none" stroke={severityMeta[key].color}
              strokeWidth="10" strokeDasharray={dash} strokeDashoffset={-offset}
              transform="rotate(-90 64 64)" strokeLinecap="butt"
            />
          );
          offset += length;
          return element;
        })}
      </svg>
      <div className="donut__label"><strong>{total}</strong><span>active</span></div>
    </div>
  );
}
