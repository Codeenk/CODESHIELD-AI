export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export const severityMeta = {
  critical: { label: "Critical", color: "#f97316" },
  high: { label: "High", color: "#ef4444" },
  medium: { label: "Medium", color: "#eab308" },
  low: { label: "Low", color: "#38bdf8" },
  info: { label: "Info", color: "#94a3b8" },
};

export const statusLabel = {
  open: "Open",
  fixed: "Fixed",
  false_positive: "False positive",
  accepted_risk: "Accepted risk",
};

export function formatDate(value, withTime = true) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    ...(withTime ? { hour: "2-digit", minute: "2-digit" } : {}),
  });
}

export function timeAgo(value) {
  if (!value) return "—";
  const date = new Date(value);
  const diff = Date.now() - date.getTime();
  if (Number.isNaN(diff)) return "—";
  const minute = 60_000;
  if (diff < minute) return "just now";
  if (diff < 60 * minute) return `${Math.floor(diff / minute)}m ago`;
  if (diff < 24 * 60 * minute) return `${Math.floor(diff / (60 * minute))}h ago`;
  if (diff < 30 * 24 * 60 * minute) return `${Math.floor(diff / (24 * 60 * minute))}d ago`;
  return formatDate(value, false);
}

export function compact(value) {
  if (value === null || value === undefined) return "0";
  return Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

export function duration(ms) {
  if (!ms) return "0s";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
}

export function fileName(path) {
  return path?.split("/").pop() || path;
}

export function scanTitle(scan) {
  return scan?.project_name || scan?.target || "Scan";
}
