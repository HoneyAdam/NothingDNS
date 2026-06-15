import { Users, Network } from 'lucide-react';
import { type ServerConfig } from './types';
import { Card, CardContent, SectionHeader, ReadOnlyNotice, KVRow } from './shared';

export function ClusterSettings({ config }: { config: ServerConfig }) {
  const cluster = config.Cluster;
  return (
    <div className="space-y-4">
      <ReadOnlyNotice title="File-backed cluster settings" />
      <Card>
        <SectionHeader title="Cluster" description="Gossip-based clustering" icon={<Users className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Enabled" value={cluster?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Node ID" value={cluster?.NodeID || 'auto'} mono />
          <KVRow label="Bind Address" value={cluster?.BindAddr || '-'} mono />
          <KVRow label="Gossip Port" value={cluster?.GossipPort || 7946} />
          <KVRow label="Region" value={cluster?.Region || '-'} />
          <KVRow label="Zone" value={cluster?.Zone || '-'} />
          <KVRow label="Weight" value={cluster?.Weight || 100} />
          <KVRow label="Cache Sync" value={cluster?.CacheSync ? 'Enabled' : 'Disabled'} />
          <KVRow label="Encryption" value={cluster?.EncryptionKey ? 'Enabled (AES-256-GCM)' : 'Disabled'} />
        </CardContent>
      </Card>
      {cluster?.SeedNodes && cluster.SeedNodes.length > 0 && (
        <Card>
          <SectionHeader title="Seed Nodes" description="Initial cluster peers" icon={<Network className="h-4 w-4" />} />
          <CardContent className="space-y-1">
            {cluster.SeedNodes.map((n, i) => <KVRow key={i} label={`Node ${i + 1}`} value={n} mono />)}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
