export default function DiffView({ diff, maxHeight = 380 }) {
  if (!diff) return <p className="muted">No diff available for this patch.</p>;
  const lines = diff.split("\n");
  return (
    <div className="diff" style={{ maxHeight }}>
      <pre>
        {lines.map((line, index) => {
          let kind = "ctx";
          if (line.startsWith("@@")) kind = "hunk";
          else if (line.startsWith("+++") || line.startsWith("---")) kind = "file";
          else if (line.startsWith("+")) kind = "add";
          else if (line.startsWith("-")) kind = "del";
          return (
            <div key={index} className={`diff__line diff__line--${kind}`}>
              <span className="diff__sign">{kind === "add" ? "+" : kind === "del" ? "-" : " "}</span>
              <code>{line.replace(/^[+-](?![+-]{2})/, "") || " "}</code>
            </div>
          );
        })}
      </pre>
    </div>
  );
}
