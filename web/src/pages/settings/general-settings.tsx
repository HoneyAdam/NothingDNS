import { Server, Lock, Zap, Globe, FileText, HardDrive } from 'lucide-react';
import { type ServerConfig } from './types';
import { Card, CardContent, SectionHeader, ReadOnlyNotice, KVRow } from './shared';

export function GeneralSettings({ config }: { config: ServerConfig }) {
  const server = config.Server;
  return (
    <div className="space-y-4">
      <ReadOnlyNotice title="File-backed server settings" />
      <Card>
        <SectionHeader title="Server Bind" description="DNS server listen addresses" icon={<Server className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Bind Addresses" value={server?.Bind?.join(', ') || '-'} mono />
          <KVRow label="TCP Bind" value={server?.TCPBind?.join(', ') || 'default'} mono />
          <KVRow label="UDP Bind" value={server?.UDPBind?.join(', ') || 'default'} mono />
          <KVRow label="Port" value={server?.Port || 53} />
          <KVRow label="UDP Workers" value={server?.UDPWorkers || 'auto'} />
          <KVRow label="TCP Workers" value={server?.TCPWorkers || 'auto'} />
        </CardContent>
      </Card>
      <Card>
        <SectionHeader title="TLS (DoT)" description="DNS over TLS configuration" icon={<Lock className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Status" value={server?.TLS?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Bind" value={server?.TLS?.Bind || '-'} mono />
          <KVRow label="Cert File" value={server?.TLS?.CertFile || '-'} mono />
          <KVRow label="Key File" value={server?.TLS?.KeyFile ? '(set)' : '-'} mono />
        </CardContent>
      </Card>
      <Card>
        <SectionHeader title="QUIC (DoQ)" description="DNS over QUIC (RFC 9250)" icon={<Zap className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Status" value={server?.QUIC?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Bind" value={server?.QUIC?.Bind || '-'} mono />
        </CardContent>
      </Card>
      <Card>
        <SectionHeader title="HTTP API & DoH" description="REST API and DNS over HTTPS" icon={<Globe className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="HTTP API" value={server?.HTTP?.Enabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="Bind" value={server?.HTTP?.Bind || '-'} mono />
          <KVRow label="DoH" value={server?.HTTP?.DoHEnabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="DoH Path" value={server?.HTTP?.DoHPath || '/dns-query'} mono />
          <KVRow label="DoWS" value={server?.HTTP?.DoWSEnabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="DoWS Path" value={server?.HTTP?.DoWSPath || '/dns-ws'} mono />
          <KVRow label="ODoH" value={server?.HTTP?.ODoHEnabled ? 'Enabled' : 'Disabled'} />
          <KVRow label="ODoH Path" value={server?.HTTP?.ODoHPath || '/odoh'} mono />
        </CardContent>
      </Card>
      <Card>
        <SectionHeader title="Zones" description="Zone file configuration" icon={<FileText className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Zone Directory" value={config.ZoneDir || './zones/'} mono />
          <KVRow label="Zone Files" value={config.Zones?.length || 0} />
          {config.Zones?.map((z, i) => <KVRow key={i} label={`  ${i + 1}.`} value={z} mono />)}
        </CardContent>
      </Card>
      <Card>
        <SectionHeader title="Resource Limits" description="Memory and shutdown settings" icon={<HardDrive className="h-4 w-4" />} />
        <CardContent className="space-y-1">
          <KVRow label="Memory Limit" value={config.MemoryLimitMB ? `${config.MemoryLimitMB} MB` : 'Unlimited'} />
          <KVRow label="Shutdown Timeout" value={config.ShutdownTimeout || '30s'} />
        </CardContent>
      </Card>
    </div>
  );
}
