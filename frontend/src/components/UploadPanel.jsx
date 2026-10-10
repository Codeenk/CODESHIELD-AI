import { useState } from "react";

const SAMPLE = `import os, pickle, hashlib

def get_user(q):
    cur.execute("SELECT * FROM users WHERE id = " + q)

def run(cmd):
    os.system("ls " + cmd)

def load(data):
    return pickle.loads(data)
`;

const FILENAMES = ["snippet.py", "snippet.js", "Snippet.java"];
const SAMPLES = {
  "snippet.py": SAMPLE,
  "snippet.js": `function login(user) {\n  db.query("SELECT * FROM users WHERE name = '" + user + "'");\n}\nconst render = (name) => { el.innerHTML = name; };\n`,
  "Snippet.java": `public class Snippet {\n  public ResultSet getUser(String id) throws Exception {\n    return stmt.executeQuery("SELECT * FROM users WHERE id = " + id);\n  }\n}\n`,
};

export default function UploadPanel({ onScanCode, onScanFiles, onScanRepo, busy }) {
  const [tab, setTab] = useState("paste");
  const [filename, setFilename] = useState(FILENAMES[0]);
  const [code, setCode] = useState(SAMPLES[FILENAMES[0]]);
  const [files, setFiles] = useState([]);
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("");

  function changeFilename(name) {
    setFilename(name);
    setCode(SAMPLES[name] || "");
  }

  return (
    <div className="panel">
      <div className="tabbar">
        <div className={`tab ${tab === "paste" ? "active" : ""}`} onClick={() => setTab("paste")}>Paste / sample</div>
        <div className={`tab ${tab === "files" ? "active" : ""}`} onClick={() => setTab("files")}>Upload files</div>
        <div className={`tab ${tab === "repo" ? "active" : ""}`} onClick={() => setTab("repo")}>GitHub repo</div>
      </div>

      {tab === "paste" && (
        <div className="col">
          <div className="row">
            <select value={filename} onChange={(e) => changeFilename(e.target.value)} style={{ maxWidth: 180 }}>
              {FILENAMES.map((f) => <option key={f} value={f}>{f}</option>)}
            </select>
            <button disabled={busy} onClick={() => onScanCode(code, filename)}>Scan code</button>
          </div>
          <textarea value={code} onChange={(e) => setCode(e.target.value)} spellCheck={false} />
        </div>
      )}

      {tab === "files" && (
        <div className="col">
          <input type="file" multiple accept=".py,.js,.jsx,.ts,.tsx,.java,.zip"
                 onChange={(e) => setFiles([...e.target.files])} />
          <div className="muted">{files.length} file(s) selected. .zip archives are expanded automatically.</div>
          <div>
            <button disabled={busy || !files.length} onClick={() => onScanFiles(files)}>Scan files</button>
          </div>
        </div>
      )}

      {tab === "repo" && (
        <div className="col">
          <input type="text" placeholder="https://github.com/org/repo" value={repoUrl}
                 onChange={(e) => setRepoUrl(e.target.value)} />
          <input type="text" placeholder="branch (optional, default: repository HEAD)" value={branch}
                 onChange={(e) => setBranch(e.target.value)} />
          <div>
            <button disabled={busy || !repoUrl} onClick={() => onScanRepo(repoUrl, branch)}>Clone & scan</button>
          </div>
          <div className="muted">The repository is cloned read-only into a temporary directory and deleted after the scan.</div>
        </div>
      )}
    </div>
  );
}
