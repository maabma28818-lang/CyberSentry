import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import apiService, { getApiAccessToken, setApiAccessToken } from '../services/apiService';

const USER_STORAGE_KEY = 'cybersentry-user-data';

const AuthContext = createContext({
  user: null,
  token: null,
  isAuthenticated: false,
  isLoading: true,
  signin: async () => {},
  signup: async () => {},
  logout: () => {},
});

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    try {
      const storedUser = localStorage.getItem(USER_STORAGE_KEY) || sessionStorage.getItem(USER_STORAGE_KEY);
      return storedUser ? JSON.parse(storedUser) : null;
    } catch {
      return null;
    }
  });
  const [token, setToken] = useState(() => getApiAccessToken());
  const [isLoading, setIsLoading] = useState(() => {
    try {
      const storedUser = localStorage.getItem(USER_STORAGE_KEY) || sessionStorage.getItem(USER_STORAGE_KEY);
      const currentToken = getApiAccessToken();
      return !(storedUser && currentToken);
    } catch {
      return true;
    }
  });

  const persistUser = (userData, persistent = true) => {
    if (userData) {
      if (persistent) {
        localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(userData));
        sessionStorage.removeItem(USER_STORAGE_KEY);
      } else {
        sessionStorage.setItem(USER_STORAGE_KEY, JSON.stringify(userData));
        localStorage.removeItem(USER_STORAGE_KEY);
      }
    } else {
      localStorage.removeItem(USER_STORAGE_KEY);
      sessionStorage.removeItem(USER_STORAGE_KEY);
    }
  };

  // Verify session on initial mount
  useEffect(() => {
    const initAuth = async () => {
      const currentToken = getApiAccessToken();
      if (!currentToken) {
        setUser(null);
        setToken(null);
        setIsLoading(false);
        return;
      }

      try {
        const response = await apiService.authGetMe();
        if (response && response.user) {
          setUser(response.user);
          setToken(currentToken);
          persistUser(response.user, !!localStorage.getItem(USER_STORAGE_KEY));
        } else if (!user) {
          logout();
        }
      } catch (err) {
        // Only log out on explicit 401 or when no local cached user exists
        if (err?.response?.status === 401 || err?.status === 401 || (!user && !localStorage.getItem(USER_STORAGE_KEY))) {
          logout();
        }
      } finally {
        setIsLoading(false);
      }
    };

    initAuth();
  }, []);

  const signin = async (credentials) => {
    const { account, password, rememberMe = true } = credentials;
    const response = await apiService.authSignin({ account, password });
    if (response && response.token && response.user) {
      setApiAccessToken(response.token, rememberMe);
      persistUser(response.user, rememberMe);
      setToken(response.token);
      setUser(response.user);
      return response.user;
    }
    throw new Error(response?.error || 'Failed to sign in');
  };

  const signup = async (userData) => {
    const { username, email, password, role = 'analyst', rememberMe = true } = userData;
    const response = await apiService.authSignup({ username, email, password, role });
    if (response && response.token && response.user) {
      setApiAccessToken(response.token, rememberMe);
      persistUser(response.user, rememberMe);
      setToken(response.token);
      setUser(response.user);
      return response.user;
    }
    throw new Error(response?.error || 'Failed to create account');
  };

  const logout = useCallback(() => {
    try {
      apiService.authLogout().catch(() => {});
    } finally {
      setApiAccessToken(null);
      persistUser(null);
      setToken(null);
      setUser(null);
    }
  }, []);

  const value = {
    user,
    token,
    isAuthenticated: Boolean(user && token),
    isLoading,
    signin,
    signup,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export default AuthContext;
