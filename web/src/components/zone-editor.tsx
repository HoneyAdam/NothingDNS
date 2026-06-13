import { useState, useCallback, useRef, useEffect, type ReactNode } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogTitle } from '@/components/ui/dialog';
import { Textarea } from '@/components/ui/textarea';
import { api, type DnsRecord } from '@/lib/api';
import { Plus, Pencil, Trash2, Undo, Redo, GripVertical, Search, X, Check, AlertTriangle, Network, Database, Settings2 } from 'lucide-react';

export interface EditableRecord extends DnsRecord {
  selected?: boolean;
  edited?: boolean;
  original?: DnsRecord;
}

interface ZoneEditorProps {
  zoneName: string;
  initialRecords: DnsRecord[];
  onRefresh: () => void;
}

interface HistoryState {
  records: EditableRecord[];
  description: string;
}

type RecordFormFields = Record<string, string>;

interface RecordEditValue {
  name: string;
  ttl: number;
  data: string;
}

const recordTypeGroups = [
  { label: 'Address', types: ['A', 'AAAA', 'PTR'] },
  { label: 'Routing', types: ['CNAME', 'MX', 'NS', 'SRV'] },
  { label: 'Policy', types: ['TXT', 'CAA', 'NAPTR'] },
  { label: 'DNSSEC', types: ['DNSKEY', 'DS'] },
];
const recordTypePalette = ['SOA', ...recordTypeGroups.flatMap(group => group.types)];

const recordTypeDescriptions: Record<string, string> = {
  A: 'IPv4 host address',
  AAAA: 'IPv6 host address',
  CNAME: 'Alias to canonical name',
  MX: 'Mail routing with priority and exchanger',
  NS: 'Authoritative nameserver',
  TXT: 'Quoted text value',
  SRV: 'Service priority, weight, port, and target',
  CAA: 'Certificate authority authorization',
  DNSKEY: 'DNSSEC public key material',
  DS: 'Delegation signer digest',
  PTR: 'Reverse DNS target',
  NAPTR: 'Rewrite rule for service discovery',
};

const defaultRecordFields: RecordFormFields = {
  address: '',
  target: '',
  priority: '10',
  exchange: '',
  text: '',
  weight: '5',
  port: '',
  flags: '0',
  tag: 'issue',
  value: '',
  order: '100',
  preference: '10',
  service: '',
  regexp: '',
  replacement: '.',
  keyTag: '',
  algorithm: '13',
  digestType: '2',
  digest: '',
  protocol: '3',
  publicKey: '',
  raw: '',
};

function cleanValue(value: string): string {
  return value.trim();
}

function isReverseIPv4Zone(zoneName: string): boolean {
  const normalized = zoneName.trim().toLowerCase().replace(/\.$/, '');
  return normalized === 'in-addr.arpa' || normalized.endsWith('.in-addr.arpa');
}

function stripOuterQuotes(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  return trimmed;
}

function quoteDNSString(value: string): string {
  const trimmed = value.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed;
  }
  return `"${trimmed.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function fieldsFromRecordData(type: string, data: string): RecordFormFields {
  const fields: RecordFormFields = { ...defaultRecordFields, raw: data };
  const parts = data.trim().split(/\s+/).filter(Boolean);

  switch (type) {
    case 'A':
    case 'AAAA':
      fields.address = data.trim();
      break;
    case 'CNAME':
    case 'NS':
    case 'PTR':
      fields.target = data.trim();
      break;
    case 'MX':
      fields.priority = parts[0] || '10';
      fields.exchange = parts.slice(1).join(' ');
      break;
    case 'TXT':
      fields.text = stripOuterQuotes(data);
      break;
    case 'SRV':
      fields.priority = parts[0] || '10';
      fields.weight = parts[1] || '5';
      fields.port = parts[2] || '';
      fields.target = parts.slice(3).join(' ');
      break;
    case 'CAA':
      fields.flags = parts[0] || '0';
      fields.tag = parts[1] || 'issue';
      fields.value = stripOuterQuotes(parts.slice(2).join(' '));
      break;
    case 'DS':
      fields.keyTag = parts[0] || '';
      fields.algorithm = parts[1] || '13';
      fields.digestType = parts[2] || '2';
      fields.digest = parts.slice(3).join('');
      break;
    case 'DNSKEY':
      fields.flags = parts[0] || '256';
      fields.protocol = parts[1] || '3';
      fields.algorithm = parts[2] || '13';
      fields.publicKey = parts.slice(3).join('');
      break;
    case 'NAPTR':
      fields.order = parts[0] || '100';
      fields.preference = parts[1] || '10';
      fields.flags = stripOuterQuotes(parts[2] || '');
      fields.service = stripOuterQuotes(parts[3] || '');
      fields.regexp = stripOuterQuotes(parts[4] || '');
      fields.replacement = parts[5] || '.';
      break;
    default:
      break;
  }

  return fields;
}

function requireField(label: string, value: string): string | null {
  return value.trim() ? null : `${label} is required`;
}

function buildRecordData(type: string, fields: RecordFormFields): { data: string } | { error: string } {
  const f = (key: string) => cleanValue(fields[key] || '');
  let missing: string | null;

  switch (type) {
    case 'A':
    case 'AAAA':
      missing = requireField('Address', f('address'));
      return missing ? { error: missing } : { data: f('address') };
    case 'CNAME':
    case 'NS':
    case 'PTR':
      missing = requireField('Target', f('target'));
      return missing ? { error: missing } : { data: f('target') };
    case 'MX':
      missing = requireField('Mail exchanger', f('exchange'));
      return missing ? { error: missing } : { data: `${f('priority') || '10'} ${f('exchange')}` };
    case 'TXT':
      missing = requireField('Text', f('text'));
      return missing ? { error: missing } : { data: quoteDNSString(f('text')) };
    case 'SRV':
      missing = requireField('Target', f('target')) || requireField('Port', f('port'));
      return missing ? { error: missing } : { data: `${f('priority') || '10'} ${f('weight') || '5'} ${f('port')} ${f('target')}` };
    case 'CAA':
      missing = requireField('Value', f('value'));
      return missing ? { error: missing } : { data: `${f('flags') || '0'} ${f('tag') || 'issue'} ${quoteDNSString(f('value'))}` };
    case 'DS':
      missing = requireField('Key tag', f('keyTag')) || requireField('Digest', f('digest'));
      return missing ? { error: missing } : { data: `${f('keyTag')} ${f('algorithm') || '13'} ${f('digestType') || '2'} ${f('digest')}` };
    case 'DNSKEY':
      missing = requireField('Public key', f('publicKey'));
      return missing ? { error: missing } : { data: `${f('flags') || '256'} ${f('protocol') || '3'} ${f('algorithm') || '13'} ${f('publicKey')}` };
    case 'NAPTR':
      missing = requireField('Service', f('service')) || requireField('Replacement', f('replacement'));
      return missing ? { error: missing } : { data: `${f('order') || '100'} ${f('preference') || '10'} ${quoteDNSString(f('flags'))} ${quoteDNSString(f('service'))} ${quoteDNSString(f('regexp'))} ${f('replacement') || '.'}` };
    default:
      missing = requireField('Raw data', f('raw'));
      return missing ? { error: missing } : { data: f('raw') };
  }
}

function recordDataParts(type: string, data: string): { label: string; value: string }[] {
  const fields = fieldsFromRecordData(type, data);
  switch (type) {
    case 'MX':
      return [
        { label: 'Priority', value: fields.priority },
        { label: 'Exchange', value: fields.exchange },
      ];
    case 'SRV':
      return [
        { label: 'Priority', value: fields.priority },
        { label: 'Weight', value: fields.weight },
        { label: 'Port', value: fields.port },
        { label: 'Target', value: fields.target },
      ];
    case 'CAA':
      return [
        { label: 'Flags', value: fields.flags },
        { label: 'Tag', value: fields.tag },
        { label: 'Value', value: fields.value },
      ];
    case 'DS':
      return [
        { label: 'Key tag', value: fields.keyTag },
        { label: 'Algorithm', value: fields.algorithm },
        { label: 'Digest type', value: fields.digestType },
        { label: 'Digest', value: fields.digest },
      ];
    case 'DNSKEY':
      return [
        { label: 'Flags', value: fields.flags },
        { label: 'Protocol', value: fields.protocol },
        { label: 'Algorithm', value: fields.algorithm },
        { label: 'Public key', value: fields.publicKey },
      ];
    case 'NAPTR':
      return [
        { label: 'Order', value: fields.order },
        { label: 'Preference', value: fields.preference },
        { label: 'Flags', value: fields.flags },
        { label: 'Service', value: fields.service },
        { label: 'Regexp', value: fields.regexp },
        { label: 'Replacement', value: fields.replacement },
      ];
    case 'A':
    case 'AAAA':
      return [{ label: 'Address', value: fields.address }];
    case 'CNAME':
    case 'NS':
    case 'PTR':
      return [{ label: 'Target', value: fields.target }];
    case 'TXT':
      return [{ label: 'Text', value: fields.text }];
    default:
      return [{ label: 'Data', value: data }];
  }
}

export function ZoneEditor({ zoneName, initialRecords, onRefresh }: ZoneEditorProps) {
  const [records, setRecords] = useState<EditableRecord[]>(
    initialRecords.map(r => ({ ...r, selected: false }))
  );
  const [history, setHistory] = useState<HistoryState[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const [addRecordType, setAddRecordType] = useState('A');
  const [showBulkPTR, setShowBulkPTR] = useState(false);
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [selectedRecords, setSelectedRecords] = useState<Set<number>>(new Set());
  const dragItem = useRef<number | null>(null);
  const dragOverItem = useRef<number | null>(null);
  const canBulkPTR = isReverseIPv4Zone(zoneName);

  const saveToHistory = useCallback((desc: string) => {
    const newHistory = history.slice(0, historyIndex + 1);
    newHistory.push({ records: JSON.parse(JSON.stringify(records)), description: desc });
    setHistory(newHistory);
    setHistoryIndex(newHistory.length - 1);
  }, [history, historyIndex, records]);

  const undo = useCallback(() => {
    if (historyIndex > 0) {
      setHistoryIndex(historyIndex - 1);
      setRecords(history[historyIndex - 1].records.map(r => ({ ...r, selected: false })));
    }
  }, [history, historyIndex]);

  const redo = useCallback(() => {
    if (historyIndex < history.length - 1) {
      setHistoryIndex(historyIndex + 1);
      setRecords(history[historyIndex + 1].records.map(r => ({ ...r, selected: false })));
    }
  }, [history, historyIndex]);

  const updateRecord = useCallback((index: number, field: keyof DnsRecord, value: string | number) => {
    setRecords(prev => {
      const updated = [...prev];
      updated[index] = { ...updated[index], [field]: value, edited: true };
      return updated;
    });
  }, []);

  const saveEdit = useCallback((index: number) => {
    const record = records[index];
    if (!record.edited) return;
    saveToHistory(`Edited ${record.name} ${record.type}`);
    api('PUT', `/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
      name: record.name,
      type: record.type,
      old_data: record.original?.data || record.data,
      ttl: record.ttl,
      data: record.data
    }).then(() => {
      setRecords(prev => prev.map((r, i) => i === index ? { ...r, edited: false } : r));
    }).catch(e => {
      console.error('Failed to save record:', e);
      // Revert the edited flag on failure
      setRecords(prev => prev.map((r, i) => i === index ? { ...r, edited: true } : r));
    });
  }, [records, saveToHistory, zoneName]);

  const saveStructuredEdit = useCallback(async (index: number, next: RecordEditValue) => {
    const record = records[index];
    if (!record) return;
    saveToHistory(`Edited ${record.name} ${record.type}`);
    try {
      await api('PUT', `/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
        name: next.name,
        type: record.type,
        old_data: record.original?.data || record.data,
        ttl: next.ttl,
        data: next.data
      });
      setRecords(prev => prev.map((r, i) => i === index ? {
        ...r,
        name: next.name,
        ttl: next.ttl,
        data: next.data,
        edited: false,
        original: undefined,
      } : r));
      onRefresh();
    } catch (e) {
      alert(e instanceof Error ? e.message : `Failed to save ${record.type} record`);
    }
  }, [records, saveToHistory, zoneName, onRefresh]);

  const deleteRecord = useCallback((record: EditableRecord) => {
    if (!confirm(`Delete ${record.type} ${record.name}?`)) return;
    saveToHistory(`Deleted ${record.name} ${record.type}`);
    // Optimistic delete - remove first, revert on failure
    setRecords(prev => prev.filter(r => !(r.name === record.name && r.type === record.type && r.data === record.data)));
    api('DELETE', `/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
      name: record.name,
      type: record.type,
      data: record.data
    }).catch(e => {
      console.error('Delete failed:', e);
      // Revert on failure
      setRecords(prev => [record, ...prev]);
      alert(`Failed to delete ${record.type} ${record.name}`);
    });
  }, [saveToHistory, zoneName]);

  const deleteSelected = useCallback(async () => {
    if (selectedRecords.size === 0) return;
    if (!confirm(`Delete ${selectedRecords.size} selected records?`)) return;
    saveToHistory(`Deleted ${selectedRecords.size} records`);
    const selected = records.filter((_, i) => selectedRecords.has(i));
    const failures: string[] = [];
    for (const r of selected) {
      try {
        await api('DELETE', `/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
          name: r.name, type: r.type, data: r.data
        });
      } catch {
        failures.push(`${r.type} ${r.name}`);
      }
    }
    if (failures.length > 0) {
      alert(`Failed to delete: ${failures.join(', ')}`);
    }
    onRefresh();
    setSelectedRecords(new Set());
  }, [selectedRecords, records, saveToHistory, zoneName, onRefresh]);

  const toggleSelect = useCallback((index: number) => {
    setSelectedRecords(prev => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }, []);

  const filteredRecords = records.filter(r => {
    const matchesSearch = !search ||
      r.name.toLowerCase().includes(search.toLowerCase()) ||
      r.data.toLowerCase().includes(search.toLowerCase());
    const matchesType = !typeFilter || r.type === typeFilter;
    return matchesSearch && matchesType;
  });

  const selectAll = useCallback(() => {
    if (selectedRecords.size === filteredRecords.length) {
      setSelectedRecords(new Set());
    } else {
      // Select all VISIBLE rows by their real index into `records` (not the
      // filtered-loop index), so selection stays correct under search/filter.
      setSelectedRecords(new Set(filteredRecords.map(r => records.indexOf(r))));
    }
  }, [filteredRecords, selectedRecords, records]);

  const handleDragStart = (index: number) => {
    dragItem.current = index;
  };

  const handleDragEnter = (index: number) => {
    dragOverItem.current = index;
  };

  const handleDragEnd = () => {
    if (dragItem.current === null || dragOverItem.current === null) return;
    if (dragItem.current === dragOverItem.current) return;

    setRecords(prev => {
      const updated = [...prev];
      const [removed] = updated.splice(dragItem.current!, 1);
      updated.splice(dragOverItem.current!, 0, removed);
      return updated;
    });

    dragItem.current = null;
    dragOverItem.current = null;
  };

  const types = [...new Set(records.map(r => r.type))].sort();
  const tc: Record<string, 'success' | 'warning' | 'secondary' | 'default' | 'outline'> = {
    SOA: 'warning', NS: 'secondary', A: 'success', AAAA: 'success',
    CNAME: 'default', MX: 'outline', TXT: 'outline', SRV: 'outline',
    DNSKEY: 'warning', DS: 'warning', RRSIG: 'secondary', NSEC: 'secondary'
  };
  const editedCount = records.filter(r => r.edited).length;
  const typeCounts = records.reduce<Record<string, number>>((acc, record) => {
    acc[record.type] = (acc[record.type] || 0) + 1;
    return acc;
  }, {});
  const addressCount = (typeCounts.A || 0) + (typeCounts.AAAA || 0) + (typeCounts.PTR || 0);
  const routingCount = (typeCounts.CNAME || 0) + (typeCounts.MX || 0) + (typeCounts.NS || 0) + (typeCounts.SRV || 0);
  const policyCount = (typeCounts.TXT || 0) + (typeCounts.CAA || 0) + (typeCounts.NAPTR || 0);
  const securityCount = (typeCounts.DNSKEY || 0) + (typeCounts.DS || 0) + (typeCounts.RRSIG || 0) + (typeCounts.NSEC || 0);

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-lg border bg-surface p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Addressing</span>
            <Badge variant="success">{addressCount}</Badge>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">A, AAAA, and PTR records</p>
        </div>
        <div className="rounded-lg border bg-surface p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Routing</span>
            <Badge variant="outline">{routingCount}</Badge>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">NS, MX, CNAME, and SRV records</p>
        </div>
        <div className="rounded-lg border bg-surface p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Policy</span>
            <Badge variant="secondary">{policyCount}</Badge>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">TXT, CAA, and NAPTR records</p>
        </div>
        <div className="rounded-lg border bg-surface p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Security</span>
            <Badge variant="warning">{securityCount}</Badge>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">DNSSEC-related records</p>
        </div>
      </div>

      {/* Toolbar */}
      <div className="rounded-lg border bg-surface p-3 shadow-sm">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
          <div className="relative min-w-0 flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search records..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="pl-9 pr-9"
            />
            {search && (
              <button onClick={() => setSearch('')} className="absolute right-3 top-1/2 -translate-y-1/2">
                <X className="h-4 w-4 text-muted-foreground hover:text-foreground" />
              </button>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              value={typeFilter}
              onChange={e => setTypeFilter(e.target.value)}
              className="h-10 min-w-[130px] rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="">All Types</option>
              {types.map(t => <option key={t} value={t}>{t}</option>)}
            </select>

            <div className="flex items-center gap-1 rounded-md border bg-background p-1">
              <Button variant="ghost" size="icon" className="h-8 w-8" onClick={undo} disabled={historyIndex <= 0}>
                <Undo className="h-4 w-4" />
              </Button>
              <Button variant="ghost" size="icon" className="h-8 w-8" onClick={redo} disabled={historyIndex >= history.length - 1}>
                <Redo className="h-4 w-4" />
              </Button>
            </div>

            <Button size="sm" onClick={() => { setAddRecordType('A'); setShowAdd(true); }}>
              <Plus className="h-4 w-4" /> Add Record
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                if (canBulkPTR) {
                  setShowBulkPTR(true);
                } else {
                  setAddRecordType('PTR');
                  setShowAdd(true);
                }
              }}
            >
              <Network className="h-4 w-4" /> {canBulkPTR ? 'Bulk PTR' : 'Add PTR'}
            </Button>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
          <Badge variant="secondary" className="gap-1"><Database className="h-3.5 w-3.5" /> {filteredRecords.length} shown</Badge>
          <Badge variant="outline">{records.length} total</Badge>
          {editedCount > 0 && <Badge variant="warning">{editedCount} edited</Badge>}
          {search && <Badge variant="secondary">Filtered</Badge>}
          <button onClick={selectAll} className="ml-auto hover:text-foreground underline underline-offset-2">
            {selectedRecords.size > 0 && selectedRecords.size === filteredRecords.length ? 'Deselect all' : 'Select all'}
          </button>
        </div>

        {selectedRecords.size > 0 && (
          <div className="mt-3 flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/5 p-2">
            <Badge variant="secondary">{selectedRecords.size} selected</Badge>
            <Button variant="destructive" size="sm" onClick={deleteSelected}>
              <Trash2 className="h-4 w-4" /> Delete
            </Button>
          </div>
        )}
      </div>

      <div className="rounded-lg border bg-surface p-3 shadow-sm">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div>
            <div className="text-sm font-medium">Record type palette</div>
            <div className="text-xs text-muted-foreground">Filter the zone by record family without losing table context.</div>
          </div>
          {typeFilter && (
            <Button variant="ghost" size="sm" onClick={() => setTypeFilter('')}>
              <X className="h-4 w-4" /> Clear
            </Button>
          )}
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => setTypeFilter('')}
            className={`inline-flex items-center gap-2 rounded-md border px-3 py-2 text-sm transition-colors ${typeFilter === '' ? 'border-primary bg-primary/10 text-primary' : 'bg-background hover:bg-muted/50'}`}
          >
            <span className="font-medium">All</span>
            <Badge variant="secondary">{records.length}</Badge>
          </button>
          {recordTypePalette.map(typeName => (
            <button
              key={typeName}
              type="button"
              onClick={() => setTypeFilter(typeName)}
              className={`inline-flex items-center gap-2 rounded-md border px-3 py-2 text-sm transition-colors ${typeFilter === typeName ? 'border-primary bg-primary/10 text-primary' : 'bg-background hover:bg-muted/50'}`}
            >
              <span className="font-medium">{typeName}</span>
              <Badge variant={tc[typeName] || 'outline'}>{typeCounts[typeName] || 0}</Badge>
            </button>
          ))}
        </div>
      </div>

      {/* Records Table */}
      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="sticky top-0 z-10">
              <tr className="border-b bg-muted/50">
                <th className="w-10 px-3 py-3"></th>
                <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3">Name</th>
                <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3 w-24">Type</th>
                <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3 w-24">TTL</th>
                <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3">Data</th>
                <th className="text-right text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3 w-32">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredRecords.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-12 text-muted-foreground">
                    {records.length === 0 ? 'No records in this zone' : 'No matching records'}
                  </td>
                </tr>
              ) : filteredRecords.map((r) => {
                // Map the visible row back to its real index into `records`.
                // `filteredRecords` holds the same object references, so
                // indexOf is exact — this keeps edit/select/delete/drag aligned
                // with the unfiltered array even when a search/type filter is active.
                const i = records.indexOf(r);
                return (
                <tr
                  key={`${r.name}-${r.type}-${i}`}
                  className={`border-b align-top hover:bg-muted/30 transition-colors cursor-grab active:cursor-grabbing ${r.edited ? 'bg-warning/5' : ''} ${selectedRecords.has(i) ? 'bg-primary/5' : ''}`}
                  draggable
                  onDragStart={() => handleDragStart(i)}
                  onDragEnter={() => handleDragEnter(i)}
                  onDragEnd={handleDragEnd}
                  onDragOver={e => e.preventDefault()}
                >
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={selectedRecords.has(i)}
                        onChange={() => toggleSelect(i)}
                        className="h-4 w-4 rounded border-input"
                      />
                      <GripVertical className="h-4 w-4 text-muted-foreground" />
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <InlineEdit
                      value={r.name}
                      onSave={v => updateRecord(i, 'name', v)}
                      onFinish={() => saveEdit(i)}
                      edited={r.edited}
                    />
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant={tc[r.type] || 'outline'}>{r.type}</Badge>
                  </td>
                  <td className="px-4 py-3">
                    <InlineEdit
                      value={String(r.ttl)}
                      onSave={v => updateRecord(i, 'ttl', parseInt(v) || 3600)}
                      onFinish={() => saveEdit(i)}
                      edited={r.edited}
                      type="number"
                    />
                  </td>
                  <td className="px-4 py-3">
                    <RecordDataDisplay type={r.type} data={r.data} />
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-1">
                      {r.edited && (
                        <Button variant="ghost" size="icon" className="h-8 w-8 text-success" onClick={() => saveEdit(i)}>
                          <Check className="h-4 w-4" />
                        </Button>
                      )}
                      {r.type !== 'SOA' && !r.edited && (
                        <>
                          <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => {
                            setEditingIndex(i);
                          }}>
                            <Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive hover:text-destructive" onClick={() => deleteRecord(r)}>
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>

      <AddRecordDialog
        open={showAdd}
        onClose={() => setShowAdd(false)}
        zoneName={zoneName}
        initialType={addRecordType}
        onSaved={() => { onRefresh(); setShowAdd(false); saveToHistory('Added record'); }}
      />

      <EditRecordDialog
        open={editingIndex !== null}
        record={editingIndex === null ? null : records[editingIndex] || null}
        onClose={() => setEditingIndex(null)}
        onSave={async (next) => {
          if (editingIndex === null) return;
          await saveStructuredEdit(editingIndex, next);
          setEditingIndex(null);
        }}
      />

      <BulkPTRDialog
        open={showBulkPTR}
        onClose={() => setShowBulkPTR(false)}
        zoneName={zoneName}
        onSaved={() => { onRefresh(); setShowBulkPTR(false); saveToHistory('Added bulk PTR records'); }}
      />
    </div>
  );
}

function InlineEdit({ value, onSave, onFinish, edited, type = 'text' }: {
  value: string;
  onSave: (v: string) => void;
  onFinish: () => void;
  edited?: boolean;
  type?: string;
}) {
  const [editing, setEditing] = useState(edited || false);
  const [val, setVal] = useState(value);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => { setVal(value); }, [value]);
  useEffect(() => { if (editing) inputRef.current?.focus(); }, [editing]);

  if (!editing) {
    return (
      <span className="font-mono text-sm cursor-pointer hover:bg-muted px-2 py-1 rounded" onClick={() => setEditing(true)}>
        {value}
      </span>
    );
  }

  return (
    <input
      ref={inputRef}
      type={type}
      value={val}
      onChange={e => { setVal(e.target.value); onSave(e.target.value); }}
      onBlur={onFinish}
      onKeyDown={e => { if (e.key === 'Enter') onFinish(); if (e.key === 'Escape') { setVal(value); setEditing(false); } }}
      className="font-mono text-sm w-full bg-background border border-primary rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-primary"
    />
  );
}

function FormField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-1.5">
      <label className="block text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</label>
      {children}
    </div>
  );
}

function RecordDataDisplay({ type, data }: { type: string; data: string }) {
  const parts = recordDataParts(type, data);
  return (
    <div className="flex min-w-[280px] flex-wrap gap-1.5">
      {parts.map((part) => (
        <span key={part.label} className="inline-flex max-w-full items-center gap-1 rounded-md border bg-muted/40 px-2 py-1 text-xs">
          <span className="text-muted-foreground">{part.label}</span>
          <span className="font-mono truncate">{part.value || '-'}</span>
        </span>
      ))}
    </div>
  );
}

function RecordTypePanel({ type, children }: { type: string; children: ReactNode }) {
  return (
    <div className="rounded-lg border bg-muted/20 p-4">
      <div className="mb-4 flex items-start gap-3">
        <div className="rounded-md bg-primary/10 p-2 text-primary">
          <Settings2 className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline">{type}</Badge>
            <span className="text-sm font-medium">Record data</span>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">{recordTypeDescriptions[type] || 'Raw DNS record data'}</p>
        </div>
      </div>
      {children}
    </div>
  );
}

function RecordDataForm({ type, fields, onFieldChange }: {
  type: string;
  fields: RecordFormFields;
  onFieldChange: (key: string, value: string) => void;
}) {
  const input = (key: string, placeholder: string, inputType = 'text') => (
    <Input
      type={inputType}
      placeholder={placeholder}
      value={fields[key] || ''}
      onChange={e => onFieldChange(key, e.target.value)}
    />
  );

  switch (type) {
    case 'A':
      return <RecordTypePanel type={type}><FormField label="IPv4 address">{input('address', '192.0.2.10')}</FormField></RecordTypePanel>;
    case 'AAAA':
      return <RecordTypePanel type={type}><FormField label="IPv6 address">{input('address', '2001:db8::10')}</FormField></RecordTypePanel>;
    case 'CNAME':
      return <RecordTypePanel type={type}><FormField label="Canonical target">{input('target', 'app.example.com.')}</FormField></RecordTypePanel>;
    case 'NS':
      return <RecordTypePanel type={type}><FormField label="Nameserver">{input('target', 'ns1.example.com.')}</FormField></RecordTypePanel>;
    case 'PTR':
      return <RecordTypePanel type={type}><FormField label="PTR target">{input('target', 'host.example.com.')}</FormField></RecordTypePanel>;
    case 'MX':
      return (
        <RecordTypePanel type={type}>
          <div className="grid gap-4 sm:grid-cols-[120px_1fr]">
            <FormField label="Priority">{input('priority', '10', 'number')}</FormField>
            <FormField label="Mail exchanger">{input('exchange', 'mail.example.com.')}</FormField>
          </div>
        </RecordTypePanel>
      );
    case 'TXT':
      return (
        <RecordTypePanel type={type}>
          <FormField label="Text value">
            <Textarea
              rows={3}
              placeholder="v=spf1 mx ~all"
              value={fields.text || ''}
              onChange={e => onFieldChange('text', e.target.value)}
            />
          </FormField>
        </RecordTypePanel>
      );
    case 'SRV':
      return (
        <RecordTypePanel type={type}>
          <div className="grid gap-4 sm:grid-cols-2">
            <FormField label="Priority">{input('priority', '10', 'number')}</FormField>
            <FormField label="Weight">{input('weight', '5', 'number')}</FormField>
            <FormField label="Port">{input('port', '443', 'number')}</FormField>
            <FormField label="Target">{input('target', 'service.example.com.')}</FormField>
          </div>
        </RecordTypePanel>
      );
    case 'CAA':
      return (
        <RecordTypePanel type={type}>
          <div className="grid gap-4 sm:grid-cols-[100px_150px_1fr]">
            <FormField label="Flags">{input('flags', '0', 'number')}</FormField>
            <FormField label="Tag">
              <select
                value={fields.tag || 'issue'}
                onChange={e => onFieldChange('tag', e.target.value)}
                className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="issue">issue</option>
                <option value="issuewild">issuewild</option>
                <option value="iodef">iodef</option>
                <option value="accounturi">accounturi</option>
                <option value="validationmethods">validationmethods</option>
              </select>
            </FormField>
            <FormField label="Value">{input('value', 'letsencrypt.org')}</FormField>
          </div>
        </RecordTypePanel>
      );
    case 'DS':
      return (
        <RecordTypePanel type={type}>
          <div className="grid gap-4 sm:grid-cols-3">
            <FormField label="Key tag">{input('keyTag', '60485', 'number')}</FormField>
            <FormField label="Algorithm">{input('algorithm', '13', 'number')}</FormField>
            <FormField label="Digest type">{input('digestType', '2', 'number')}</FormField>
            <div className="sm:col-span-3">
              <FormField label="Digest">{input('digest', 'hex digest')}</FormField>
            </div>
          </div>
        </RecordTypePanel>
      );
    case 'DNSKEY':
      return (
        <RecordTypePanel type={type}>
          <div className="grid gap-4 sm:grid-cols-3">
            <FormField label="Flags">{input('flags', '256', 'number')}</FormField>
            <FormField label="Protocol">{input('protocol', '3', 'number')}</FormField>
            <FormField label="Algorithm">{input('algorithm', '13', 'number')}</FormField>
            <div className="sm:col-span-3">
              <FormField label="Public key">
                <Textarea
                  rows={3}
                  placeholder="base64 public key"
                  value={fields.publicKey || ''}
                  onChange={e => onFieldChange('publicKey', e.target.value)}
                />
              </FormField>
            </div>
          </div>
        </RecordTypePanel>
      );
    case 'NAPTR':
      return (
        <RecordTypePanel type={type}>
          <div className="grid gap-4 sm:grid-cols-2">
            <FormField label="Order">{input('order', '100', 'number')}</FormField>
            <FormField label="Preference">{input('preference', '10', 'number')}</FormField>
            <FormField label="Flags">{input('flags', 'U')}</FormField>
            <FormField label="Service">{input('service', 'E2U+sip')}</FormField>
            <FormField label="Regexp">{input('regexp', '!^.*$!sip:info@example.com!')}</FormField>
            <FormField label="Replacement">{input('replacement', '.')}</FormField>
          </div>
        </RecordTypePanel>
      );
    default:
      return <RecordTypePanel type={type}><FormField label="Raw data">{input('raw', 'record data')}</FormField></RecordTypePanel>;
  }
}

function AddRecordDialog({ open, onClose, zoneName, initialType, onSaved }: {
  open: boolean;
  onClose: () => void;
  zoneName: string;
  initialType: string;
  onSaved: () => void;
}) {
  const [name, setName] = useState('');
  const [type, setType] = useState('A');
  const [ttl, setTtl] = useState('3600');
  const [fields, setFields] = useState<RecordFormFields>(() => ({ ...defaultRecordFields }));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const built = buildRecordData(type, fields);

  useEffect(() => {
    if (!open) return;
    setType(initialType);
    setFields(fieldsFromRecordData(initialType, ''));
    setError('');
  }, [open, initialType]);

  const handleTypeChange = (nextType: string) => {
    setType(nextType);
    setFields(fieldsFromRecordData(nextType, ''));
  };

  const handleFieldChange = (key: string, value: string) => {
    setFields(prev => ({ ...prev, [key]: value }));
  };

  const handleSave = async () => {
    setError('');
    if (!name.trim()) {
      setError('Name is required');
      return;
    }
    const nextData = buildRecordData(type, fields);
    if ('error' in nextData) {
      setError(nextData.error);
      return;
    }
    setSaving(true);
    try {
      await api('POST', `/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
        name: name.trim(),
        type,
        ttl: parseInt(ttl) || 3600,
        data: nextData.data
      });
      setName(''); setType('A'); setTtl('3600'); setFields({ ...defaultRecordFields });
      onSaved();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to add record');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose}>
      <DialogTitle>Add Record</DialogTitle>
      <div className="space-y-4 mt-5">
        {error && (
          <div className="text-sm text-destructive bg-destructive/10 px-3 py-2 rounded-lg flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" /> {error}
          </div>
        )}

        <div className="grid gap-4 sm:grid-cols-[1fr_150px]">
          <div className="space-y-1.5">
            <label className="block text-xs font-medium uppercase tracking-wide text-muted-foreground">Name</label>
            <Input
              placeholder="@ or subdomain"
              value={name}
              onChange={e => setName(e.target.value)}
              autoFocus
            />
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium uppercase tracking-wide text-muted-foreground">TTL</label>
            <Input type="number" value={ttl} onChange={e => setTtl(e.target.value)} />
          </div>
        </div>

        <div className="rounded-lg border bg-muted/20 p-3">
          <div className="mb-3 flex items-center justify-between gap-3">
            <div>
              <div className="text-sm font-medium">Record type</div>
              <div className="text-xs text-muted-foreground">{recordTypeDescriptions[type]}</div>
            </div>
            <Badge variant="outline">{type}</Badge>
          </div>
          <div className="space-y-3">
            {recordTypeGroups.map(group => (
              <div key={group.label} className="space-y-2">
                <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{group.label}</div>
                <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {group.types.map(typeName => (
                    <button
                      key={typeName}
                      type="button"
                      onClick={() => handleTypeChange(typeName)}
                      className={`rounded-md border p-3 text-left transition-colors ${type === typeName ? 'border-primary bg-primary/10 text-primary' : 'bg-background hover:bg-muted/50'}`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-medium">{typeName}</span>
                        {type === typeName && <Check className="h-4 w-4" />}
                      </div>
                      <div className="mt-1 line-clamp-2 text-xs text-muted-foreground">{recordTypeDescriptions[typeName]}</div>
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        <RecordDataForm type={type} fields={fields} onFieldChange={handleFieldChange} />

        {'data' in built && built.data && (
          <div className="rounded-md border bg-muted/30 px-3 py-2 text-xs">
            <span className="text-muted-foreground">Will save as </span>
            <span className="break-all font-mono">{built.data}</span>
          </div>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={handleSave} disabled={saving}>
            {saving ? 'Adding...' : 'Add Record'}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

function EditRecordDialog({ open, record, onClose, onSave }: {
  open: boolean;
  record: EditableRecord | null;
  onClose: () => void;
  onSave: (next: RecordEditValue) => Promise<void>;
}) {
  const [name, setName] = useState('');
  const [ttl, setTtl] = useState('3600');
  const [fields, setFields] = useState<RecordFormFields>(() => ({ ...defaultRecordFields }));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const built = record ? buildRecordData(record.type, fields) : { data: '' };

  useEffect(() => {
    if (!record) return;
    setName(record.name);
    setTtl(String(record.ttl));
    setFields(fieldsFromRecordData(record.type, record.data));
    setError('');
  }, [record]);

  const handleFieldChange = (key: string, value: string) => {
    setFields(prev => ({ ...prev, [key]: value }));
  };

  const handleSave = async () => {
    if (!record) return;
    setError('');
    if (!name.trim()) {
      setError('Name is required');
      return;
    }
    const nextData = buildRecordData(record.type, fields);
    if ('error' in nextData) {
      setError(nextData.error);
      return;
    }
    setSaving(true);
    try {
      await onSave({
        name: name.trim(),
        ttl: parseInt(ttl) || 3600,
        data: nextData.data,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to save record');
    } finally {
      setSaving(false);
    }
  };

  if (!record) return null;

  return (
    <Dialog open={open} onClose={onClose}>
      <DialogTitle>Edit {record.type} Record</DialogTitle>
      <div className="space-y-4 mt-5">
        {error && (
          <div className="text-sm text-destructive bg-destructive/10 px-3 py-2 rounded-lg flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" /> {error}
          </div>
        )}

        <div className="grid gap-4 sm:grid-cols-[1fr_120px]">
          <FormField label="Name">
            <Input value={name} onChange={e => setName(e.target.value)} autoFocus />
          </FormField>
          <FormField label="TTL">
            <Input type="number" value={ttl} onChange={e => setTtl(e.target.value)} />
          </FormField>
        </div>

        <div className="flex items-center gap-2 rounded-lg border bg-muted/20 px-3 py-2">
          <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Type</span>
          <Badge variant="outline">{record.type}</Badge>
          <span className="text-xs text-muted-foreground">{recordTypeDescriptions[record.type] || 'Raw DNS record data'}</span>
        </div>

        <RecordDataForm type={record.type} fields={fields} onFieldChange={handleFieldChange} />

        {'data' in built && built.data && (
          <div className="rounded-md border bg-muted/30 px-3 py-2 text-xs">
            <span className="text-muted-foreground">Will save as </span>
            <span className="break-all font-mono">{built.data}</span>
          </div>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={handleSave} disabled={saving}>
            {saving ? 'Saving...' : 'Save Record'}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

function BulkPTRDialog({ open, onClose, zoneName, onSaved }: {
  open: boolean;
  onClose: () => void;
  zoneName: string;
  onSaved: () => void;
}) {
  const [cidr, setCidr] = useState('');
  const [pattern, setPattern] = useState('ip-[A]-[B]-[C]-[D].example.com');
  const [override, setOverride] = useState(false);
  const [addA, setAddA] = useState(true);
  const [saving, setSaving] = useState(false);
  const [previewing, setPreviewing] = useState(false);
  const [error, setError] = useState('');
  const [preview, setPreview] = useState<{
    total: number;
    willAdd: number;
    willAddA: number;
    willSkip: number;
    willOverride: number;
    changes: { ip: string; ptrName: string; aName?: string; action: string; ptrExist: boolean; aExist?: boolean; oldPtr?: string; oldA?: string }[];
  } | null>(null);
  const [result, setResult] = useState<{ added: number; addedA: number; exists: number; existsA: number; skipped: number } | null>(null);

  const handlePreview = async () => {
    setError('');
    if (!cidr.trim()) {
      setError('CIDR is required');
      return;
    }
    if (!pattern.includes('[A]') || !pattern.includes('[B]') ||
        !pattern.includes('[C]') || !pattern.includes('[D]')) {
      setError('Pattern must contain [A], [B], [C], [D] placeholders');
      return;
    }
    setPreviewing(true);
    try {
      const res = await api<typeof preview>(
        'POST',
        `/api/v1/zones/${encodeURIComponent(zoneName)}/ptr-bulk`,
        { cidr: cidr.trim(), pattern: pattern.trim(), override, addA, preview: true }
      );
      setPreview(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to preview');
    } finally {
      setPreviewing(false);
    }
  };

  const handleSave = async () => {
    setError('');
    if (!cidr.trim()) {
      setError('CIDR is required');
      return;
    }
    if (!pattern.includes('[A]') || !pattern.includes('[B]') ||
        !pattern.includes('[C]') || !pattern.includes('[D]')) {
      setError('Pattern must contain [A], [B], [C], [D] placeholders');
      return;
    }
    setSaving(true);
    try {
      const res = await api<{ added: number; addedA: number; exists: number; existsA: number; skipped: number }>(
        'POST',
        `/api/v1/zones/${encodeURIComponent(zoneName)}/ptr-bulk`,
        { cidr: cidr.trim(), pattern: pattern.trim(), override, addA, preview: false }
      );
      setResult(res);
      setPreview(null);
      if (res.added > 0 || res.skipped > 0 || res.addedA > 0) {
        setCidr('');
        onSaved();
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to add PTR records');
    } finally {
      setSaving(false);
    }
  };

  const reset = () => {
    setPreview(null);
    setResult(null);
    setError('');
  };

  return (
    <Dialog open={open} onClose={onClose}>
      <DialogTitle>Bulk PTR Records</DialogTitle>
      <div className="space-y-4 mt-5">
        {error && (
          <div className="text-sm text-destructive bg-destructive/10 px-3 py-2 rounded-lg flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" /> {error}
          </div>
        )}

        {result && (
          <div className="text-sm bg-success/10 text-success px-3 py-2 rounded-lg space-y-1">
            <div>PTR: +{result.added} / {result.exists} exists / {result.skipped} skipped</div>
            {result.addedA > 0 && <div>A: +{result.addedA} / {result.existsA} exists</div>}
            <button onClick={reset} className="text-xs underline mt-1">Clear</button>
          </div>
        )}

        {!result && preview && (
          <div className="text-sm bg-primary/10 px-3 py-2 rounded-lg">
            <div className="flex justify-between mb-2">
              <span className="text-primary font-medium">Preview: {preview.total} IPs</span>
              <button onClick={() => setPreview(null)} className="text-xs underline">Edit</button>
            </div>
            <div className="grid grid-cols-3 gap-2 text-xs mb-2">
              <div className="text-success">+{preview.willAdd} add</div>
              {preview.willAddA > 0 && <div className="text-success">+{preview.willAddA} A</div>}
              {preview.willSkip > 0 && <div className="text-warning">~{preview.willSkip} skip</div>}
              {preview.willOverride > 0 && <div className="text-destructive">!{preview.willOverride} override</div>}
            </div>
            <div className="max-h-48 overflow-y-auto space-y-1">
              {preview.changes.slice(0, 20).map((ch, i) => (
                <div key={i} className={`text-xs font-mono flex items-center gap-1 ${
                  ch.action === 'skip' ? 'text-warning' : ch.action === 'override' ? 'text-destructive' : 'text-success'
                }`}>
                  <span>{ch.ip}</span>
                  <span>→</span>
                  <span className="truncate">{ch.ptrName}</span>
                  {ch.action === 'skip' && <span className="text-muted-foreground">exists</span>}
                  {ch.action === 'override' && <span className="text-destructive">→ {ch.oldPtr}</span>}
                </div>
              ))}
              {preview.changes.length > 20 && (
                <div className="text-xs text-muted-foreground text-center">
                  +{preview.changes.length - 20} more...
                </div>
              )}
            </div>
          </div>
        )}

        <div>
          <label className="text-sm font-medium mb-1.5 block">CIDR Range</label>
          <Input
            placeholder="192.168.1.0/24"
            value={cidr}
            onChange={e => { setCidr(e.target.value); setPreview(null); }}
            autoFocus
          />
          <p className="text-xs text-muted-foreground mt-1">IPv4 range (max /16)</p>
        </div>

        <div>
          <label className="text-sm font-medium mb-1.5 block">Pattern</label>
          <Input
            placeholder="ip-[A]-[B]-[C]-[D].example.com"
            value={pattern}
            onChange={e => { setPattern(e.target.value); setPreview(null); }}
          />
          <p className="text-xs text-muted-foreground mt-1">Use [A], [B], [C], [D] for IP octets</p>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="checkbox"
            id="addA"
            checked={addA}
            onChange={e => { setAddA(e.target.checked); setPreview(null); }}
            className="h-4 w-4 rounded border-input"
          />
          <label htmlFor="addA" className="text-sm">Also add A records (pattern name → IP)</label>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="checkbox"
            id="override"
            checked={override}
            onChange={e => { setOverride(e.target.checked); setPreview(null); }}
            className="h-4 w-4 rounded border-input"
          />
          <label htmlFor="override" className="text-sm">Override existing records</label>
        </div>

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={onClose}>Close</Button>
          {!preview ? (
            <Button variant="outline" onClick={handlePreview} disabled={previewing || !cidr.trim()}>
              {previewing ? 'Preview...' : 'Preview'}
            </Button>
          ) : null}
          <Button onClick={handleSave} disabled={saving}>
            {saving ? 'Adding...' : preview ? 'Confirm & Add' : 'Add PTR Records'}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
