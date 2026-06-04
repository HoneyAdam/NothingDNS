import { useMutation, useQueryClient } from '@tanstack/react-query';

import { useAuthStore } from '@/stores/authStore';

// Helper to get auth token from the in-memory Zustand store only (LOW-005).
// Never read from document.cookie — the backend cookie is HttpOnly.
function getToken(): string | null {
  return useAuthStore.getState().token;
}

// API fetch wrapper with auth.
async function fetchApi<T>(path: string, options?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const resp = await fetch(path, { ...options, headers });

  if (!resp.ok) {
    const contentType = resp.headers.get('content-type');
    if (contentType?.includes('application/json')) {
      const data = await resp.json();
      throw new Error(data.error || `HTTP ${resp.status}: ${resp.statusText}`);
    }
    throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
  }

  const contentType = resp.headers.get('content-type');
  if (contentType?.includes('application/json')) {
    return resp.json() as Promise<T>;
  }
  return {} as T;
}

// NOTE: read-only data hooks (zones, users, query-log, etc.) were removed —
// every page calls the `api()`/`fetchApi()` helpers directly. Only the
// config-mutation hooks below are consumed (by settings.tsx). Re-add a
// typed query hook here only when a page actually adopts it.

// Update Logging Config Mutation
interface LoggingConfigRequest { level: string }

export function useUpdateLoggingConfig() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: LoggingConfigRequest) =>
      fetchApi<{ message: string }>('/api/v1/config/logging', {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['server-config'] });
    },
  });
}

// Update RRL Config Mutation
interface RRLConfigRequest { enabled: boolean; rate: number; burst: number }

export function useUpdateRRLConfig() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: RRLConfigRequest) =>
      fetchApi<{ message: string }>('/api/v1/config/rrl', {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['server-config'] });
    },
  });
}

// Update Cache Config Mutation
interface CacheConfigRequest {
  enabled: boolean;
  size: number;
  default_ttl: number;
  max_ttl: number;
  min_ttl: number;
  negative_ttl: number;
  prefetch: boolean;
  prefetch_threshold: number;
  serve_stale: boolean;
  stale_grace_secs: number;
}

export function useUpdateCacheConfig() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CacheConfigRequest) =>
      fetchApi<{ message: string }>('/api/v1/config/cache', {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['server-config'] });
    },
  });
}
