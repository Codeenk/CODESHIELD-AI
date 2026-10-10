import { DiffEditor } from "@monaco-editor/react";

function languageOf(name = "") {
  if (name.endsWith(".py")) return "python";
  if (name.endsWith(".java")) return "java";
  if (name.endsWith(".js") || name.endsWith(".jsx")) return "javascript";
  if (name.endsWith(".ts") || name.endsWith(".tsx")) return "typescript";
  return "plaintext";
}

export default function DiffView({ original, modified, filename }) {
  return (
    <div className="diff">
      <DiffEditor
        original={original || ""}
        modified={modified || ""}
        language={languageOf(filename)}
        theme="vs-dark"
        options={{
          readOnly: true,
          renderSideBySide: true,
          minimap: { enabled: false },
          fontSize: 12,
          scrollBeyondLastLine: false,
        }}
      />
    </div>
  );
}
