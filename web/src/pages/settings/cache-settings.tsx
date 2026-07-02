import { useEffect, useState } from 'react';
import { Database, Zap } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { toast } from 'sonner';
import { useUpdateCacheConfig } from '@/hooks/useApi';
import { type ServerConfig } from './types';
import { Card, CardContent, SectionHeader, SaveBar } from './shared';

// Parse an integer, falling back to `def` only when the input is not a number.
// A legitimate 0 must be preserved (a plain `parseInt(x) || def` coerces 0 → def).
const intOr = (x: string, def: number): number => {
  const n = parseInt(x, 10);
  return Number.isNaN(n) ? def : n;
};

export function CacheSettings({ config, onReload }: { config: ServerConfig; onReload: () => Promise<void> }) {
  const cache = config.Cache;
  const updateCache = useUpdateCacheConfig();
  const [cacheEnabled, setCacheEnabled] = useState(cache?.Enabled ?? true);
  const [cacheSize, setCacheSize] = useState(String(cache?.Size ?? 10000));
  const [defaultTTL, setDefaultTTL] = useState(String(cache?.DefaultTTL ?? 300));
  const [maxTTL, setMaxTTL] = useState(String(cache?.MaxTTL ?? 86400));
  const [minTTL, setMinTTL] = useState(String(cache?.MinTTL ?? 5));
  const [negativeTTL, setNegativeTTL] = useState(String(cache?.NegativeTTL ?? 60));
  const [prefetch, setPrefetch] = useState(cache?.Prefetch ?? false);
  const [prefetchThreshold, setPrefetchThreshold] = useState(String(cache?.PrefetchThreshold ?? 60));
  const [serveStale, setServeStale] = useState(cache?.ServeStale ?? false);
  const [staleGrace, setStaleGrace] = useState(String(cache?.StaleGraceSecs ?? 86400));

  useEffect(() => {
    setCacheEnabled(cache?.Enabled ?? true);
    setCacheSize(String(cache?.Size ?? 10000));
    setDefaultTTL(String(cache?.DefaultTTL ?? 300));
    setMaxTTL(String(cache?.MaxTTL ?? 86400));
    setMinTTL(String(cache?.MinTTL ?? 5));
    setNegativeTTL(String(cache?.NegativeTTL ?? 60));
    setPrefetch(cache?.Prefetch ?? false);
    setPrefetchThreshold(String(cache?.PrefetchThreshold ?? 60));
    setServeStale(cache?.ServeStale ?? false);
    setStaleGrace(String(cache?.StaleGraceSecs ?? 86400));
  }, [cache]);

  const resetCacheForm = () => {
    setCacheEnabled(cache?.Enabled ?? true);
    setCacheSize(String(cache?.Size ?? 10000));
    setDefaultTTL(String(cache?.DefaultTTL ?? 300));
    setMaxTTL(String(cache?.MaxTTL ?? 86400));
    setMinTTL(String(cache?.MinTTL ?? 5));
    setNegativeTTL(String(cache?.NegativeTTL ?? 60));
    setPrefetch(cache?.Prefetch ?? false);
    setPrefetchThreshold(String(cache?.PrefetchThreshold ?? 60));
    setServeStale(cache?.ServeStale ?? false);
    setStaleGrace(String(cache?.StaleGraceSecs ?? 86400));
  };

  const cacheDirty =
    cacheEnabled !== (cache?.Enabled ?? true) ||
    cacheSize !== String(cache?.Size ?? 10000) ||
    defaultTTL !== String(cache?.DefaultTTL ?? 300) ||
    maxTTL !== String(cache?.MaxTTL ?? 86400) ||
    minTTL !== String(cache?.MinTTL ?? 5) ||
    negativeTTL !== String(cache?.NegativeTTL ?? 60) ||
    prefetch !== (cache?.Prefetch ?? false) ||
    prefetchThreshold !== String(cache?.PrefetchThreshold ?? 60) ||
    serveStale !== (cache?.ServeStale ?? false) ||
    staleGrace !== String(cache?.StaleGraceSecs ?? 86400);

  const handleSave = async () => {
    const min = intOr(minTTL, 5);
    const max = intOr(maxTTL, 86400);
    if (min > max) {
      toast.error('Min TTL cannot be greater than Max TTL');
      return;
    }
    try {
      await updateCache.mutateAsync({
        enabled: cacheEnabled,
        size: intOr(cacheSize, 10000),
        default_ttl: intOr(defaultTTL, 300),
        max_ttl: max,
        min_ttl: min,
        negative_ttl: intOr(negativeTTL, 60),
        prefetch: prefetch,
        prefetch_threshold: intOr(prefetchThreshold, 60),
        serve_stale: serveStale,
        stale_grace_secs: intOr(staleGrace, 86400),
      });
      await onReload();
      toast.success('Cache settings saved');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to save cache settings');
    }
  };

  return (
    <div className="space-y-4">
      <Card>
        <SectionHeader title="Cache Configuration" description="DNS response caching" icon={<Database className="h-4 w-4" />} badge="Live edit" />
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <Label>Enabled</Label>
            <Switch checked={cacheEnabled} onCheckedChange={setCacheEnabled} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Max Size</Label>
              <Input type="number" min="0" value={cacheSize} onChange={(e) => setCacheSize(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label>Default TTL (seconds)</Label>
              <Input type="number" min="0" value={defaultTTL} onChange={(e) => setDefaultTTL(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label>Max TTL (seconds)</Label>
              <Input type="number" min="0" value={maxTTL} onChange={(e) => setMaxTTL(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label>Min TTL (seconds)</Label>
              <Input type="number" min="0" value={minTTL} onChange={(e) => setMinTTL(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label>Negative TTL (seconds)</Label>
              <Input type="number" min="0" value={negativeTTL} onChange={(e) => setNegativeTTL(e.target.value)} />
            </div>
          </div>
        </CardContent>
      </Card>
      <Card>
        <SectionHeader title="Prefetch & Stale" description="Cache optimization features" icon={<Zap className="h-4 w-4" />} badge="Live edit" />
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <Label>Prefetch</Label>
            <Switch checked={prefetch} onCheckedChange={setPrefetch} />
          </div>
          <div className="space-y-2">
            <Label>Prefetch Threshold (seconds)</Label>
            <Input type="number" min="0" value={prefetchThreshold} onChange={(e) => setPrefetchThreshold(e.target.value)} disabled={!prefetch} />
          </div>
          <div className="flex items-center justify-between">
            <Label>Serve Stale</Label>
            <Switch checked={serveStale} onCheckedChange={setServeStale} />
          </div>
          <div className="space-y-2">
            <Label>Stale Grace Period (seconds)</Label>
            <Input type="number" min="0" value={staleGrace} onChange={(e) => setStaleGrace(e.target.value)} disabled={!serveStale} />
          </div>
          <SaveBar dirty={cacheDirty} saving={updateCache.isPending} onSave={handleSave} onReset={resetCacheForm} />
        </CardContent>
      </Card>
    </div>
  );
}
