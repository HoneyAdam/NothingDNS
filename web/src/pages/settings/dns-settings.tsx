import { Globe, Activity, Network, FileText } from 'lucide-react';
import { type ServerConfig } from './types';
import { Card, CardContent, SectionHeader, ReadOnlyNotice, KVRow } from './shared';

export function DNSSettings({ config }: { config: ServerConfig }) {
  const resolution = config.Resolution;
  return (
    <div className="space-y-4">
      <ReadOnlyNotice title="File-backed DNS settings" />
      <Card>
        <SectionHeader title="Resolution" description="DNS resolution behavior" icon={<Globe className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Recursive" value={resolution?.Recursive ? 'Enabled' : 'Disabled'} />
          <KVRow label="Root Hints" value={resolution?.RootHints || '-'} mono />
          <KVRow label="Max Depth" value={resolution?.MaxDepth || 10} />
          <KVRow label="Timeout" value={resolution?.Timeout || '5s'} />
          <KVRow label="EDNS0 Buffer Size" value={resolution?.EDNS0BufferSize || 4096} />
          <KVRow label="QNAME Minimization" value={resolution?.QnameMinimization ? 'Enabled' : 'Disabled'} />
          <KVRow label="0x20 Encoding" value={resolution?.Use0x20 ? 'Enabled' : 'Disabled'} />
        </CardContent>
      </Card>
      <Card>
        <SectionHeader title="Metrics" description="Prometheus metrics endpoint" icon={<Activity className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Status" value={config.Metrics?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Bind" value={config.Metrics?.Bind || '-'} mono />
          <KVRow label="Path" value={config.Metrics?.Path || '/metrics'} mono />
        </CardContent>
      </Card>
      {config.Views && config.Views.length > 0 && (
        <Card>
          <SectionHeader title="Split-Horizon Views" description="Client-based zone routing" icon={<Network className="h-4 w-4" />} />
          <CardContent className="space-y-3">
            {config.Views.map((view, i) => (
              <div key={i} className="p-3 rounded-lg bg-muted/50 space-y-1">
                <div className="font-medium text-sm">{view.Name}</div>
                <KVRow label="Match Clients" value={view.MatchClients?.join(', ') || '-'} mono />
                <KVRow label="Zone Files" value={view.ZoneFiles?.join(', ') || '-'} mono />
              </div>
            ))}
          </CardContent>
        </Card>
      )}
      {config.SlaveZones && config.SlaveZones.length > 0 && (
        <Card>
          <SectionHeader title="Slave Zones" description="Zone transfer from masters" icon={<FileText className="h-4 w-4" />} />
          <CardContent className="space-y-3">
            {config.SlaveZones.map((sz, i) => (
              <div key={i} className="p-3 rounded-lg bg-muted/50 space-y-1">
                <div className="font-medium text-sm">{sz.ZoneName}</div>
                <KVRow label="Masters" value={sz.Masters?.join(', ') || '-'} mono />
                <KVRow label="Transfer Type" value={sz.TransferType || 'ixfr'} />
                <KVRow label="TSIG" value={sz.TSIGKeyName ? 'Enabled' : 'Disabled'} />
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
