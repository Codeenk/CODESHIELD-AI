import { useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import Icon from "../components/Icon";
import Logo from "../components/Logo";
import { useAuth } from "../lib/auth";
import { api } from "../lib/api";

export default function Auth() {
  const { user, loading, authEnabled, oauthEnabled, login, register } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  if (!loading && user) return <Navigate to="/dashboard" replace />;

  function update(key, value) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  async function submit(event) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      if (mode === "login") await login(form.email, form.password);
      else await register(form.name, form.email, form.password);
      navigate("/dashboard");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth">
      <section className="auth__visual">
        <div className="auth__visual-inner">
          <Logo />
          <div className="auth__pitch">
            <span className="eyebrow">Secure code review, grounded</span>
            <h1>Find the flaw.<br />Understand the path.<br /><em>Verify the fix.</em></h1>
            <p>
              CodeShield combines deterministic rules, scoped taint analysis, and optional learned
              detection — then proves every repair before you ship it.
            </p>
          </div>
          <div className="auth__proof">
            <span><b>0</b> noise on its own codebase</span>
            <span><b>5</b> languages · 4 report formats</span>
            <span><b>100%</b> explainable findings</span>
          </div>
          <div className="auth__orb" aria-hidden="true">
            <span className="auth__orb-ring auth__orb-ring--one" />
            <span className="auth__orb-ring auth__orb-ring--two" />
            <span className="auth__orb-ring auth__orb-ring--three" />
            <span className="auth__orb-core"><Icon name="shield" size={34} strokeWidth={1.3} /></span>
            <span className="auth__orb-scan" />
          </div>
        </div>
      </section>
      <section className="auth__panel">
        <div className="auth__form-wrap">
          <div className="auth__panel-head">
            <span className="eyebrow">{mode === "login" ? "Welcome back" : "Create an account"}</span>
            <h2>{mode === "login" ? "Sign in to the console" : "Start your first scan"}</h2>
            <p>{authEnabled ? "Local accounts stay on this server." : "Authentication is disabled; you are signed in as the local analyst."}</p>
          </div>

          {authEnabled && (
            <div className="auth__tabs" role="tablist" aria-label="Authentication mode">
              <button type="button" role="tab" aria-selected={mode === "login"} className={mode === "login" ? "active" : ""} onClick={() => { setMode("login"); setError(""); }}>Sign in</button>
              <button type="button" role="tab" aria-selected={mode === "register"} className={mode === "register" ? "active" : ""} onClick={() => { setMode("register"); setError(""); }}>Register</button>
            </div>
          )}

          <form onSubmit={submit} className="auth__form">
            {mode === "register" && (
              <label className="field">
                <span className="field__label">Name</span>
                <input value={form.name} onChange={(event) => update("name", event.target.value)} autoComplete="name" required minLength={1} placeholder="Ada Lovelace" />
              </label>
            )}
            <label className="field">
              <span className="field__label">Email</span>
              <input type="email" value={form.email} onChange={(event) => update("email", event.target.value)} autoComplete="email" required placeholder="you@company.com" />
            </label>
            <label className="field">
              <span className="field__label">Password</span>
              <input type="password" value={form.password} onChange={(event) => update("password", event.target.value)} autoComplete={mode === "login" ? "current-password" : "new-password"} required minLength={8} placeholder="At least 8 characters" />
            </label>
            {error && <p className="form-error" role="alert"><Icon name="alert" size={15} />{error}</p>}
            <button type="submit" className="btn btn--primary btn--wide" disabled={busy}>
              {busy ? <span className="spinner spinner--on-accent" /> : <Icon name="arrow" size={17} />}
              {mode === "login" ? "Sign in" : "Create account"}
            </button>
          </form>

          {oauthEnabled && (
            <>
              <div className="auth__divider"><span>or</span></div>
              <a className="btn btn--outline btn--wide" href={api.githubUrl()}><Icon name="repo" size={17} />Continue with GitHub</a>
            </>
          )}

          <p className="auth__fineprint">
            <Icon name="lock" size={13} /> Sessions are opaque, HttpOnly cookies. Passwords use scrypt.
          </p>
        </div>
      </section>
    </div>
  );
}
