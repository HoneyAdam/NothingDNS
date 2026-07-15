import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import {
  useUpdateLoggingConfig,
  useUpdateRRLConfig,
  useUpdateCacheConfig,
} from './useApi';
import { useAuthStore } from '@/stores/authStore';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        {children}
      </QueryClientProvider>
    );
  };
}

beforeEach(() => {
  mockFetch.mockReset();
  useAuthStore.setState({
    token: null,
    username: null,
    role: null,
    isAuthenticated: false,
  });
});

function mockJsonResponse(data: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
}

describe('useUpdateLoggingConfig', () => {
  it('sends PUT to /api/v1/config/logging', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ message: 'updated' }));
    const { result } = renderHook(() => useUpdateLoggingConfig(), {
      wrapper: createWrapper(),
    });

    result.current.mutate({ level: 'debug' });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockFetch).toHaveBeenCalledWith('/api/v1/config/logging', {
      method: 'PUT',
      body: JSON.stringify({ level: 'debug' }),
      headers: expect.objectContaining({ 'Content-Type': 'application/json' }),
    });
  });

  it('includes Bearer token when authenticated', async () => {
    useAuthStore.getState().setAuth('tok_config', 'admin', 'admin');
    mockFetch.mockResolvedValue(mockJsonResponse({ message: 'ok' }));

    const { result } = renderHook(() => useUpdateLoggingConfig(), {
      wrapper: createWrapper(),
    });
    result.current.mutate({ level: 'info' });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    const callHeaders = mockFetch.mock.calls[0][1].headers;
    expect(callHeaders.Authorization).toBe('Bearer tok_config');
  });
});

describe('useUpdateRRLConfig', () => {
  it('sends PUT to /api/v1/config/rrl', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ message: 'updated' }));
    const { result } = renderHook(() => useUpdateRRLConfig(), {
      wrapper: createWrapper(),
    });

    result.current.mutate({ enabled: true, rate: 10, burst: 20 });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockFetch).toHaveBeenCalledWith('/api/v1/config/rrl', {
      method: 'PUT',
      body: JSON.stringify({ enabled: true, rate: 10, burst: 20 }),
      headers: expect.objectContaining({ 'Content-Type': 'application/json' }),
    });
  });
});

describe('useUpdateCacheConfig', () => {
  const cacheConfig = {
    enabled: true,
    size: 10000,
    default_ttl: 3600,
    max_ttl: 86400,
    min_ttl: 60,
    negative_ttl: 300,
    prefetch: true,
    prefetch_threshold: 0.5,
    serve_stale: true,
    stale_grace_secs: 3600,
  };

  it('sends PUT to /api/v1/config/cache with full payload', async () => {
    mockFetch.mockResolvedValue(mockJsonResponse({ message: 'updated' }));
    const { result } = renderHook(() => useUpdateCacheConfig(), {
      wrapper: createWrapper(),
    });

    result.current.mutate(cacheConfig);
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(mockFetch).toHaveBeenCalledWith('/api/v1/config/cache', {
      method: 'PUT',
      body: JSON.stringify(cacheConfig),
      headers: expect.objectContaining({ 'Content-Type': 'application/json' }),
    });
  });

  it('handles API error', async () => {
    mockFetch.mockResolvedValue(
      mockJsonResponse({ error: 'invalid cache size' }, 400),
    );
    const { result } = renderHook(() => useUpdateCacheConfig(), {
      wrapper: createWrapper(),
    });

    result.current.mutate(cacheConfig);
    await waitFor(() => expect(result.current.isError).toBe(true));

    expect(result.current.error).toBeDefined();
  });
});
