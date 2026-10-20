import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { api } from "./api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [state, setState] = useState({ user: null, authEnabled: true, oauthEnabled: false, loading: true });

  const refresh = useCallback(async () => {
    try {
      const data = await api.me();
      setState({
        user: data.user || null,
        authEnabled: data.auth_enabled !== false,
        oauthEnabled: Boolean(data.oauth_enabled),
        loading: false,
      });
      return data;
    } catch {
      setState((current) => ({ ...current, user: null, loading: false }));
      return null;
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const login = useCallback(async (email, password) => {
    const data = await api.login(email, password);
    setState({ user: data.user, authEnabled: data.auth_enabled, oauthEnabled: data.oauth_enabled, loading: false });
    return data;
  }, []);

  const register = useCallback(async (name, email, password) => {
    const data = await api.register(name, email, password);
    setState({ user: data.user, authEnabled: data.auth_enabled, oauthEnabled: data.oauth_enabled, loading: false });
    return data;
  }, []);

  const logout = useCallback(async () => {
    await api.logout().catch(() => {});
    setState((current) => ({ ...current, user: null }));
  }, []);

  const value = useMemo(
    () => ({ ...state, login, register, logout, refresh }),
    [state, login, register, logout, refresh],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
}
