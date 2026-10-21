import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import Icon from "../components/Icon";
import { Field, ErrorBlock } from "../components/ui";
import { api } from "../lib/api";

const MODES = [
  { id: "repo", label: "Repository", icon: "repo", hint: "Clone a public GitHub, GitLab, or Bitbucket repository." },
  { id: "upload", label: "Files", icon: "file", hint: "Upload source files or folders for a focused review." },
  { id: "zip", label: "Archive", icon: "folder", hint: "Scan a .zip archive without cloning." },
  { id: "snippet", label: "Snippet", icon: "code", hint: "Paste a function or file to inspect immediately." },
];

async function getFilesFromDataTransfer(dataTransfer) {
  const items = dataTransfer.items;
  if (!items || items.length === 0) {
    return Array.from(dataTransfer.files || []);
  }

  const results = [];
  const queue = [];

  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    if (item.kind === "file") {
      if (typeof item.webkitGetAsEntry === "function") {
        const entry = item.webkitGetAsEntry();
        if (entry) {
          queue.push(traverseEntry(entry, ""));
          continue;
        }
      }
      const file = item.getAsFile();
      if (file) results.push(file);
    }
  }

  if (queue.length > 0) {
    const nested = await Promise.all(queue);
    for (const arr of nested) {
      results.push(...arr);
    }
  }

  return results.length > 0 ? results : Array.from(dataTransfer.files || []);
}

function traverseEntry(entry, pathSoFar) {
  return new Promise((resolve) => {
    if (entry.isFile) {
      entry.file(
        (file) => {
          const relativePath = pathSoFar ? `${pathSoFar}/${file.name}` : file.name;
          Object.defineProperty(file, "customRelativePath", {
            value: relativePath,
            writable: true,
          });
          resolve([file]);
        },
        () => resolve([])
      );
    } else if (entry.isDirectory) {
      const dirPath = pathSoFar ? `${pathSoFar}/${entry.name}` : entry.name;
      const dirReader = entry.createReader();
      readAllEntries(dirReader)
        .then(async (entries) => {
          const promises = entries.map((e) => traverseEntry(e, dirPath));
          const subFiles = await Promise.all(promises);
          resolve(subFiles.flat());
        })
        .catch(() => resolve([]));
    } else {
      resolve([]);
    }
  });
}

function readAllEntries(dirReader) {
  return new Promise((resolve) => {
    const all = [];
    function readBatch() {
      dirReader.readEntries(
        (entries) => {
          if (!entries || entries.length === 0) {
            resolve(all);
          } else {
            all.push(...entries);
            readBatch();
          }
        },
        () => resolve(all)
      );
    }
    readBatch();
  });
}

function getFilePath(file) {
  return file.customRelativePath || file.webkitRelativePath || file.name;
}

export default function NewScan() {
  const navigate = useNavigate();
  const [meta, setMeta] = useState(null);
  const [projects, setProjects] = useState([]);
  const [mode, setMode] = useState("repo");
  const [form, setForm] = useState({
    repo_url: "",
    branch: "",
    commit: "",
    filename: "snippet.py",
    code: "",
    project_id: "",
    project_name: "",
    model_mode: "auto",
    generate_patches: true,
  });
  const [files, setFiles] = useState([]);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const fileInputRef = useRef(null);
  const folderInputRef = useRef(null);

  useEffect(() => {
    api.meta().then(setMeta).catch(() => {});
    api.projects().then(setProjects).catch(() => {});
  }, []);

  function update(key, value) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  function addFiles(list) {
    const incoming = Array.from(list || []);
    setFiles((current) => {
      if (mode === "zip") return incoming.slice(0, 1);
      const seen = new Set(current.map(getFilePath));
      return [...current, ...incoming.filter((file) => !seen.has(getFilePath(file)))];
    });
  }

  async function handleDrop(event) {
    event.preventDefault();
    setDragging(false);
    const extracted = await getFilesFromDataTransfer(event.dataTransfer);
    addFiles(extracted);
  }

  async function submit(event) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      const payload = new FormData();
      payload.set("source_type", mode);
      payload.set("project_id", form.project_id);
      payload.set("project_name", form.project_name);
      payload.set("model_mode", form.model_mode);
      payload.set("generate_patches", String(form.generate_patches));
      if (mode === "repo") {
        if (!form.repo_url.trim()) throw new Error("Enter a repository URL");
        payload.set("repo_url", form.repo_url.trim());
        payload.set("branch", form.branch.trim());
        payload.set("commit", form.commit.trim());
      } else if (mode === "snippet") {
        if (!form.code.trim()) throw new Error("Paste some code first");
        payload.set("filename", form.filename || "snippet.py");
        payload.set("code", form.code);
      } else {
        if (!files.length) {
          throw new Error(mode === "zip" ? "Choose a .zip archive" : "Choose at least one source file or folder");
        }
        files.forEach((file) => {
          const relativePath = getFilePath(file);
          payload.append("files", file, relativePath);
        });
      }
      const scan = await api.createScan(payload);
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const maxMb = Math.round((meta?.limits?.max_file_bytes || 5 * 1024 * 1024) / (1024 * 1024));
  const current = MODES.find((item) => item.id === mode);

  return (
    <div className="page">
      <header className="page__head">
        <div>
          <span className="eyebrow">New assessment</span>
          <h1>Scan source code</h1>
          <p>Choose a scope. Rules run first; the learned detector is optional and never required.</p>
        </div>
      </header>

      <div className="scan-layout">
        <form className="panel scan-form" onSubmit={submit}>
          <div className="scan-modes" role="tablist" aria-label="Scan source">
            {MODES.map((item) => (
              <button
                key={item.id}
                type="button"
                role="tab"
                aria-selected={mode === item.id}
                className={mode === item.id ? "active" : ""}
                onClick={() => {
                  setMode(item.id);
                  setFiles([]);
                  setError("");
                }}
              >
                <Icon name={item.icon} size={17} />
                <span>{item.label}</span>
              </button>
            ))}
          </div>
          <p className="scan-form__hint">{current.hint}</p>

          {mode === "repo" && (
            <div className="form-grid">
              <Field
                label="Repository URL"
                htmlFor="repo"
                hint="HTTPS only. Public repositories from github.com, gitlab.com, or bitbucket.org."
              >
                <input
                  id="repo"
                  value={form.repo_url}
                  onChange={(event) => update("repo_url", event.target.value)}
                  placeholder="https://github.com/owner/repository"
                  autoComplete="off"
                />
              </Field>
              <div className="form-grid form-grid--two">
                <Field label="Branch" htmlFor="branch" hint="Leave empty for default branch (or auto-detected from URL).">
                  <input
                    id="branch"
                    value={form.branch}
                    onChange={(event) => update("branch", event.target.value)}
                    placeholder="main"
                    autoComplete="off"
                  />
                </Field>
                <Field label="Commit" htmlFor="commit" hint="Optional 7–40 character SHA.">
                  <input
                    id="commit"
                    value={form.commit}
                    onChange={(event) => update("commit", event.target.value)}
                    placeholder="a1b2c3d"
                    autoComplete="off"
                  />
                </Field>
              </div>
            </div>
          )}

          {mode === "snippet" && (
            <div className="form-grid">
              <Field
                label="Filename"
                htmlFor="filename"
                hint="The extension selects the parser: .py, .js, .ts, .tsx, .jsx, or .java."
              >
                <input
                  id="filename"
                  value={form.filename}
                  onChange={(event) => update("filename", event.target.value)}
                  placeholder="app.py"
                />
              </Field>
              <Field
                label="Source"
                htmlFor="code"
                hint="Paste a complete function for the strongest evidence and repair."
              >
                <textarea
                  id="code"
                  className="code-input"
                  value={form.code}
                  onChange={(event) => update("code", event.target.value)}
                  rows={16}
                  spellCheck={false}
                  placeholder={"def handler(request):\n    ..."}
                />
              </Field>
            </div>
          )}

          {(mode === "upload" || mode === "zip") && (
            <div
              className={`dropzone ${dragging ? "dropzone--active" : ""}`}
              onDragOver={(event) => {
                event.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={handleDrop}
            >
              <input
                ref={fileInputRef}
                type="file"
                hidden
                multiple={mode === "upload"}
                accept={mode === "zip" ? ".zip" : ".py,.js,.jsx,.ts,.tsx,.java,.cjs,.mjs,.zip"}
                onChange={(event) => addFiles(event.target.files)}
              />
              <input
                ref={folderInputRef}
                type="file"
                hidden
                webkitdirectory=""
                directory=""
                multiple
                onChange={(event) => addFiles(event.target.files)}
              />
              <span className="dropzone__icon">
                <Icon name={mode === "zip" ? "folder" : "upload"} size={22} />
              </span>
              <strong>
                {dragging
                  ? "Drop to attach"
                  : mode === "zip"
                  ? "Drop a .zip archive"
                  : "Drop source files or a project folder"}
              </strong>
              <p>
                {mode === "zip"
                  ? "One archive, up to 4,000 entries."
                  : `Up to ${meta?.limits?.max_files || 4000} files, ${maxMb} MB each.`}
              </p>
              <div style={{ display: "flex", gap: "0.5rem", justifyContent: "center", marginTop: "0.5rem" }}>
                <button
                  type="button"
                  className="btn btn--outline btn--sm"
                  onClick={() => fileInputRef.current?.click()}
                >
                  Browse files
                </button>
                {mode === "upload" && (
                  <button
                    type="button"
                    className="btn btn--outline btn--sm"
                    onClick={() => folderInputRef.current?.click()}
                  >
                    Browse folder
                  </button>
                )}
              </div>
            </div>
          )}

          {files.length > 0 && (
            <div style={{ marginTop: "1rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
                <span className="muted" style={{ fontSize: "0.85rem" }}>
                  {files.length} {files.length === 1 ? "file" : "files"} selected
                </span>
                <button
                  type="button"
                  className="btn btn--outline btn--sm"
                  style={{ padding: "0.2rem 0.5rem", fontSize: "0.75rem" }}
                  onClick={() => setFiles([])}
                >
                  Clear all
                </button>
              </div>
              <ul className="file-list" style={{ maxHeight: "240px", overflowY: "auto" }}>
                {files.map((file) => {
                  const displayPath = getFilePath(file);
                  return (
                    <li key={displayPath}>
                      <Icon name="file" size={15} />
                      <span title={displayPath}>{displayPath}</span>
                      <small>{Math.max(1, Math.round(file.size / 1024))} KB</small>
                      <button
                        type="button"
                        className="icon-btn"
                        onClick={() =>
                          setFiles((current) => current.filter((item) => getFilePath(item) !== displayPath))
                        }
                        aria-label={`Remove ${displayPath}`}
                      >
                        <Icon name="x" size={14} />
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}

          <div className="panel__divider" />

          <div className="form-grid form-grid--two">
            <Field label="Existing project" htmlFor="project" hint="Group scans to compare revisions and carry suppressions.">
              <select id="project" value={form.project_id} onChange={(event) => update("project_id", event.target.value)}>
                <option value="">Create from this scan</option>
                {projects.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.name}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Project name" htmlFor="project_name" hint="Used only when no existing project is selected.">
              <input
                id="project_name"
                value={form.project_name}
                onChange={(event) => update("project_name", event.target.value)}
                placeholder="Payments API"
                disabled={Boolean(form.project_id)}
              />
            </Field>
          </div>

          <div className="form-grid form-grid--two">
            <Field label="Detection model" htmlFor="model" hint="Auto uses local weights when present; it never downloads silently.">
              <select id="model" value={form.model_mode} onChange={(event) => update("model_mode", event.target.value)}>
                <option value="auto">Auto · local if available</option>
                <option value="off">Rules only</option>
                <option value="on">Require model</option>
              </select>
            </Field>
            <label className="check-field">
              <input
                type="checkbox"
                checked={form.generate_patches}
                onChange={(event) => update("generate_patches", event.target.checked)}
              />
              <span>
                <strong>Generate repairs</strong>
                <small>Verify templates and optional LLM fixes against tests when enabled.</small>
              </span>
            </label>
          </div>

          {error && <ErrorBlock message={error} />}
          <div className="scan-form__actions">
            <button type="submit" className="btn btn--primary" disabled={busy}>
              {busy ? <span className="spinner spinner--on-accent" /> : <Icon name="scan" size={17} />}
              {busy ? "Queueing scan" : "Start scan"}
            </button>
            <span className="muted">You can leave this page; the scan runs in the background.</span>
          </div>
        </form>

        <aside className="scan-aside">
          <section className="panel panel--aside">
            <span className="eyebrow">Scope</span>
            <h2>What gets checked</h2>
            <ul className="check-list">
              <li><Icon name="check" size={15} />Injection, traversal, secrets, crypto, TLS, deserialization</li>
              <li><Icon name="check" size={15} />Python AST and Tree-sitter units for JS/TS/Java</li>
              <li><Icon name="check" size={15} />Scoped taint from request, env, argv, stdin, forms</li>
              <li><Icon name="check" size={15} />CWE/OWASP mapping with KB-grounded explanations</li>
              <li><Icon name="check" size={15} />Patch verification: parse, rescan, signature, tests</li>
            </ul>
          </section>
          <section className="panel panel--aside">
            <span className="eyebrow">Privacy</span>
            <h2>Source handling</h2>
            <dl className="spec-list">
              <div><dt>Retention</dt><dd>{meta?.privacy?.retain_code ? "Full function bodies" : "Off — snippets and diffs only"}</dd></div>
              <div><dt>Secret masking</dt><dd>{meta?.privacy?.mask_secrets ? "Enabled before persistence" : "Disabled"}</dd></div>
              <div><dt>Sandbox</dt><dd>{meta?.sandbox?.mode || "auto"} · tests {meta?.sandbox?.tests_enabled ? "on" : "off"}</dd></div>
              <div><dt>Rule catalog</dt><dd>{meta?.capabilities?.rules || 39} checks · {meta?.capabilities?.knowledge_modules || 29} modules</dd></div>
            </dl>
          </section>
          <section className="panel panel--aside panel--note">
            <Icon name="alert" size={18} />
            <p>Findings are candidates for human review. A finding is not proof of exploitability, and a verified patch still needs code review.</p>
          </section>
        </aside>
      </div>
    </div>
  );
}
