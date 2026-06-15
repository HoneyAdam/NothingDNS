import { useState, useCallback, useRef, useEffect } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { api, type DnsRecord } from '@/lib/api';
import { Plus, Pencil, Trash2, Undo, Redo, GripVertical, Search, X, Check, Network, Database } from 'lucide-react';
import {
  type EditableRecord,
  type HistoryState,
  type RecordEditValue,
  recordTypePalette,
  recordTypeBadgeVariants,
  isReverseIPv4Zone,
} from './record-utils';
import { RecordDataDisplay } from './record-form';
import { AddRecordDialog, EditRecordDialog, BulkPTRDialog } from './record-dialogs';

export type { EditableRecord } from './record-utils';

interface ZoneEditorProps {
  zoneName: string;
  initialRecords: DnsRecord[];
  onRefresh: () => void;
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
    setRecords(prev => prev.filter(r => !(r.name === record.name && r.type === record.type && r.data === record.data)));
    api('DELETE', `/api/v1/zones/${encodeURIComponent(zoneName)}/records`, {
      name: record.name,
      type: record.type,
      data: record.data
    }).catch(e => {
      console.error('Delete failed:', e);
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
              <Badge variant={recordTypeBadgeVariants[typeName] || 'outline'}>{typeCounts[typeName] || 0}</Badge>
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
                    <Badge variant={recordTypeBadgeVariants[r.type] || 'outline'}>{r.type}</Badge>
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
