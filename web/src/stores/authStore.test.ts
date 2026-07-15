import { describe, it, expect, beforeEach } from 'vitest';
import { useAuthStore } from './authStore';

// Reset zustand store between tests
beforeEach(() => {
  useAuthStore.setState({
    token: null,
    username: null,
    role: null,
    isAuthenticated: false,
  });
});

describe('authStore', () => {
  it('starts unauthenticated', () => {
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.token).toBeNull();
    expect(state.username).toBeNull();
    expect(state.role).toBeNull();
  });

  it('setAuth stores credentials and marks authenticated', () => {
    useAuthStore.getState().setAuth('tok_abc123', 'admin_user', 'admin');
    const state = useAuthStore.getState();
    expect(state.token).toBe('tok_abc123');
    expect(state.username).toBe('admin_user');
    expect(state.role).toBe('admin');
    expect(state.isAuthenticated).toBe(true);
  });

  it('clearAuth resets all fields', () => {
    useAuthStore.getState().setAuth('tok_abc123', 'admin_user', 'admin');
    useAuthStore.getState().clearAuth();
    const state = useAuthStore.getState();
    expect(state.token).toBeNull();
    expect(state.username).toBeNull();
    expect(state.role).toBeNull();
    expect(state.isAuthenticated).toBe(false);
  });

  it('persists username and role (but not token) to localStorage', () => {
    useAuthStore.getState().setAuth('tok_secret', 'persist_user', 'operator');

    // The persist middleware writes to localStorage
    const raw = localStorage.getItem('ndns-auth');
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(raw!);
    expect(parsed.state.username).toBe('persist_user');
    expect(parsed.state.role).toBe('operator');
    // Token must NOT be persisted (security requirement — LOW-005)
    expect(parsed.state.token).toBeUndefined();
  });
});
