export default function Logo({ compact = false }) {
  return (
    <div className={`brand ${compact ? "brand--compact" : ""}`}>
      <span className="brand__mark" aria-hidden="true">
        <svg viewBox="0 0 32 32" fill="none">
          <path d="M16 3.3 5.8 7.2v6.1c0 6.1 4.2 10.6 10.2 12.9 6-2.3 10.2-6.8 10.2-12.9V7.2L16 3.3Z" stroke="currentColor" strokeWidth="1.6" />
          <path d="M10.5 15.6h4.2l2.1-5.1 2.5 10.1 2.1-5H22" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </span>
      {!compact && (
        <span className="brand__text">
          <strong>CodeShield</strong>
          <span>AI review console</span>
        </span>
      )}
    </div>
  );
}
