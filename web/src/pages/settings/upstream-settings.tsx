import { Network, Globe } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { type ServerConfig } from './types';
import { Card, CardContent, SectionHeader, ReadOnlyNotice, KVRow } from './shared';

export function UpstreamSettings({ config }: { config: ServerConfig }) {
  const upstream = config.Upstream;
  return (
    <div className="space-y-4">
      <ReadOnlyNotice title="File-backed upstream settings" />
      <Card>
        <SectionHeader title="Upstream Servers" description="Recursive resolution upstreams" icon={<Network className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Strategy" value={upstream?.Strategy || 'random'} />
          <KVRow label="Health Check" value={upstream?.HealthCheck || '30s'} />
          <KVRow label="Failover Timeout" value={upstream?.FailoverTimeout || '5s'} />
          {upstream?.Servers?.map((s, i) => <KVRow key={i} label={`Server ${i + 1}`} value={s} mono />)}
        </CardContent>
      </Card>
      {upstream?.AnycastGroups && upstream.AnycastGroups.length > 0 && (
        <Card>
          <SectionHeader title="Anycast Groups" description="Geographic load balancing" icon={<Globe className="h-4 w-4" />} />
          <CardContent className="space-y-4">
            {upstream.AnycastGroups.map((ag, i) => (
              <div key={i} className="p-3 rounded-lg bg-muted/50 space-y-2">
                <div className="font-medium text-sm flex items-center gap-2">
                  <Badge variant="outline">{ag.AnycastIP}</Badge>
                </div>
                {ag.Backends?.map((b, j) => (
                  <div key={j} className="pl-3 border-l-2 border-border space-y-0.5">
                    <KVRow label="Backend" value={`${b.PhysicalIP}:${b.Port}`} mono />
                    <KVRow label="Region/Zone" value={`${b.Region || '-'}/${b.Zone || '-'}`} />
                    <KVRow label="Weight" value={b.Weight} />
                  </div>
                ))}
              </div>
            ))}
          </CardContent>
        </Card>
      )}
      {upstream?.Topology && (
        <Card>
          <SectionHeader title="Topology" description="This node's location" icon={<Globe className="h-4 w-4" />} />
          <CardContent className="space-y-1">
            <KVRow label="Region" value={upstream.Topology.Region || '-'} />
            <KVRow label="Zone" value={upstream.Topology.Zone || '-'} />
            <KVRow label="Weight" value={upstream.Topology.Weight} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
