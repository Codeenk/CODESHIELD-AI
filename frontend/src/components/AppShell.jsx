import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import Icon from "./Icon";
import Logo from "./Logo";
import { useAuth } from "../lib/auth";
import { api } from "../lib/api";

const nav = [
  { to: "/dashboard", label: "Overview", icon: "grid" },
  { to: "/scan", label: "New scan", icon: "scan" },
  { to: "/history", label: "History", icon: "history" },
  { to: "/compare", label: "Compare", icon: "code" },
  { to: "/knowledge", label: "Knowledge", icon: "book" },
  { to: "/settings", label: "Settings", icon: "settings" },
];

export default function AppShell() {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const [meta, setMeta] = useState(null);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    setOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    api.meta().then(setMeta).catch(() => {});
  }, []);

  const initials = (user?.name || user?.email || "CS")
    .split(/\s+/).map((part) => part[0]).slice(0, 2).join("").toUpperCase();

  async function handleLogout() {
    await logout();
    navigate("/login");
  }

  return (
    <div className="shell">
      <a className="skip-link" href="#main">Skip to content</a>
      <header className="topbar">
        <button type="button" className="icon-btn topbar__menu" onClick={() => setOpen((v) => !v)} aria-label="Toggle navigation" aria-expanded={open}>
          <Icon name={open ? "x" : "filter"} />
        </button>
        <Logo compact />
        <span className="topbar__status"><i className={meta ? "dot dot--ok" : "dot"} />{meta ? `${meta.capabilities?.rules || 0} rules · ${meta.model?.used ? "model ready" : "rules only"}` : "connecting"}</span>
      </header>

      <aside className={`rail ${open ? "rail--open" : ""}`}>
        <div className="rail__top">
          <Logo />
          <p className="rail__tag">Precision-first code review</p>
        </div>
        <nav className="rail__nav" aria-label="Main">
          {nav.map((item) => (
            <NavLink key={item.to} to={item.to} className={({ isActive }) => `rail__link ${isActive ? "active" : ""}`}>
              <Icon name={item.icon} />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="rail__bottom">
          <div className="rail__system">
            <span className="rail__system-label">Engine</span>
            <span className="rail__system-value">
              <i className={meta?.model?.used ? "dot dot--ok" : "dot dot--accent"} />
              {meta?.model?.used ? "Rules + model" : "Deterministic rules"}
            </span>
            <span className="rail__system-note">{meta?.privacy?.retain_code ? "Source retention on" : "Snippets only"}</span>
          </div>
          <button type="button" className="rail__user" onClick={() => navigate("/settings")}>
            <span className="avatar">{initials}</span>
            <span className="rail__user-meta"><strong>{user?.name || "Demo analyst"}</strong><small>{user?.email}</small></span>
            <Icon name="chevron" size={14} />
          </button>
          <button type="button" className="rail__logout" onClick={handleLogout}><Icon name="logout" size={16} />Sign out</button>
          <span className="rail__version">CodeShield {meta?.version || "3.0.0"}</span>
        </div>
      </aside>
      {open && <button type="button" className="rail-scrim" aria-label="Close navigation" onClick={() => setOpen(false)} />}
      <main className="main" id="main">
        <Outlet />
      </main>
    </div>
  );
}
