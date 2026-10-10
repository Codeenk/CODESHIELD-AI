import { useEffect, useState } from "react";
import UploadPanel from "./components/UploadPanel.jsx";
import Summary from "./components/Summary.jsx";
import FindingList from "./components/FindingList.jsx";
import FindingDetail from "./components/FindingDetail.jsx";
import { scanCode, scanFiles, scanRepo, setFindingStatus } from "./lib/api.js";

export default function App() {
  const [scan, setScan] = useState(null);
  const [selected, setSelected] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [health, setHealth] = useState(null);

  useEffect(() => {
    fetch("/health").then((r) => r.json()).then(setHealth).catch(() => {});
  }, []);

  async function run(fn) {
    setBusy(true);
    setError("");
    try {
      const result = await fn();
      setScan(result);
      setSelected(result.findings?.[0] || null);
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onStatus(id, status) {
    setBusy(true);
    try {
      await setFindingStatus(id, status);
      setScan((prev) => ({
        ...prev,
        findings: prev.findings.map((f) => (f.id === id ? { ...f, status } : f)),
      }));
      setSelected((prev) => (prev && prev.id === id ? { ...prev, status } : prev));
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <header className="top">
        <h1>🛡️ CodeShield AI</h1>
        <span className="badge">MVP</span>
        <div className="spacer" />
        {health && (
          <>
            <span className="badge">model: {health.model_loaded ? "loaded" : health.model_mode}</span>
            <span className="badge">KB: {health.knowledge?.vulnerability_count} modules</span>
          </>
        )}
      </header>
      <main className="col" style={{ gap: 16 }}>
        {error && <div className="error">{error}</div>}
        <UploadPanel
          busy={busy}
          onScanCode={(code, filename) => run(() => scanCode(code, filename))}
          onScanFiles={(files) => run(() => scanFiles(files))}
          onScanRepo={(url, branch) => run(() => scanRepo(url, branch))}
        />
        {busy && <div className="panel muted">Scanning… this may take a moment.</div>}
        {scan && (
          <>
            <Summary scan={scan} />
            <div className="row">
              <div style={{ flex: "0 0 340px" }}>
                <FindingList findings={scan.findings} selected={selected} onSelect={setSelected} />
              </div>
              <div className="grow">
                <FindingDetail finding={selected} onStatus={onStatus} busy={busy} />
              </div>
            </div>
          </>
        )}
      </main>
    </>
  );
}
