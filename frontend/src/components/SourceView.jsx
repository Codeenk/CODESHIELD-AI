export default function SourceView({ source, startLine = 1, highlight = [0, 0], maxHeight = 360 }) {
  if (!source) return <p className="muted">No source snippet retained for this finding.</p>;
  const lines = source.split("\n");
  const [from, to] = highlight;
  return (
    <div className="source" style={{ maxHeight }}>
      <pre>
        {lines.map((line, index) => {
          const number = startLine + index;
          const hot = from && to && number >= from && number <= to;
          return (
            <div key={`${number}-${index}`} className={`source__line ${hot ? "source__line--hot" : ""}`}>
              <span className="source__num">{number}</span>
              <code>{line || " "}</code>
            </div>
          );
        })}
      </pre>
    </div>
  );
}
