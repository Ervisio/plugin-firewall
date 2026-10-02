import { useEffect, useState, type ReactNode } from 'react';
import { errorText } from '../../api';
import { useSshPort } from '../../data';
import { deleteClosesSsh } from '../../guard';
import { t, tn } from '../../i18n';
import { Badge, Button, ConfirmDialog, IconButton, Input, toast } from '../../kit';
import type { Rule } from '../../model';
import { useSettings } from '../../settings';
import { ActionBadge, addrLabel, DataTable, fmtBytes, fmtCount, portLabel, type DataColumn } from '../../ui/parts';

export interface RuleTableProps {
  rules: Rule[];
  /** Every incoming rule of the firewall, for the SSH guard. */
  inbound: Rule[];
  /** Deletes the rules (already confirmed). */
  onDelete?(rules: Rule[]): Promise<void>;
  counters?: boolean;
  where?: boolean;
  empty?: ReactNode;
  /** Text: "#3 ALLOW IN 22/tcp" style, for rules the parser keeps raw (nftables). */
  raw?: boolean;
}

/** Rules with search, selection, delete and the SSH guard. */
export function RuleTable({ rules, inbound, onDelete, counters, where, empty, raw }: RuleTableProps) {
  const [settings] = useSettings();
  const sshPort = useSshPort();
  const [q, setQ] = useState('');
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [pending, setPending] = useState<Rule[] | null>(null);
  const [busy, setBusy] = useState(false);
  // Keys can be positions (ufw and iptables renumber after a change): a new list clears the selection.
  const signature = rules.map((r) => `${r.key}=${r.text}`).join('\n');
  useEffect(() => setSel(new Set()), [signature]);

  const shown = rules.filter((r) => (settings.showV6 || !r.v6) && (!q || `${r.text} ${r.comment ?? ''} ${r.source} ${r.dest} ${r.port} ${r.service ?? ''}`.toLowerCase().includes(q.toLowerCase())));
  const ask = (list: Rule[]) => {
    // Would the rules left keep SSH open?
    const left = inbound.filter((r) => !list.some((x) => x.key === r.key));
    const breaks = list.some((r) => deleteClosesSsh(r, [...left, r], sshPort));
    if (breaks && settings.sshGuard) {
      toast.err(t('guard.deleteBlocked', { port: sshPort }), t('guard.howToOverride'));
      return;
    }
    setPending(list);
  };
  const confirm = async () => {
    if (!pending || !onDelete) return;
    setBusy(true);
    try {
      await onDelete(pending);
      toast.ok(tn('rules.deleted', { n: pending.length }));
      setSel(new Set());
    } catch (e) {
      toast.err(t('rules.deleteFail'), errorText(e));
    } finally {
      setBusy(false);
      setPending(null);
    }
  };

  const cols: DataColumn<Rule>[] = [
    { key: 'action', header: t('col.action'), render: (r) => <span className="fw-act">{r.action === 'other' && r.target ? <Badge>{t('action.jump', { to: r.target })}</Badge> : <ActionBadge action={r.action} />}{r.direction && r.direction !== 'in' && <Badge>{t(`dir.${r.direction}`)}</Badge>}</span>, width: 120 },
    ...(raw
      ? [{ key: 'text', header: t('col.rule'), render: (r: Rule) => <code className="fw-mono fw-wrap">{r.text}</code> }]
      : [
          { key: 'port', header: t('col.port'), render: (r: Rule) => <span className="fw-mono">{portLabel(r)}</span> },
          { key: 'src', header: t('col.source'), render: (r: Rule) => <span className="fw-mono">{addrLabel(r.source)}</span> },
          { key: 'dst', header: t('col.dest'), render: (r: Rule) => <span className="fw-mono">{addrLabel(r.dest)}</span>, hideBelow: 'md' as const },
          { key: 'if', header: t('col.iface'), render: (r: Rule) => <span className="fw-mono">{r.iface ?? ''}</span>, hideBelow: 'md' as const },
        ]),
    { key: 'note', header: t('col.comment'), render: (r) => <span className="fw-note">{r.comment}{r.v6 && <Badge>IPv6</Badge>}{r.managedBy && <Badge tone="info">{r.managedBy}</Badge>}</span>, hideBelow: 'sm' },
    ...(where ? [{ key: 'where', header: t('col.where'), render: (r: Rule) => <span className="fw-mono fw-muted">{r.where}</span>, hideBelow: 'md' as const }] : []),
    ...(counters ? [{ key: 'cnt', header: t('col.hits'), align: 'right' as const, render: (r: Rule) => r.packets !== undefined ? <span title={`${r.packets} ${t('col.packets')}, ${fmtBytes(r.bytes)}`}>{fmtCount(r.packets)}</span> : '', hideBelow: 'sm' as const }] : []),
    ...(onDelete ? [{ key: 'del', header: '', width: 44, render: (r: Rule) => r.ref ? <IconButton icon="trash" size="sm" variant="ghost" label={t('rules.delete')} onClick={() => ask([r])} /> : null }] : []),
  ];

  const selectedRules = shown.filter((r) => sel.has(r.key) && r.ref);
  return (
    <div className="fw-rt">
      {(rules.length > 8 || selectedRules.length > 0) && <div className="fw-toolbar">
        <Input compact icon="search" fieldClassName="fw-search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('rules.search')} aria-label={t('rules.search')} />
        <span className="fw-muted">{tn('rules.count', { n: shown.length })}</span>
        {onDelete && selectedRules.length > 0 && <Button size="sm" variant="danger" icon="trash" onClick={() => ask(selectedRules)}>{tn('rules.deleteN', { n: selectedRules.length })}</Button>}
      </div>}
      <DataTable columns={cols} rows={shown} rowKey={(r) => r.key} selectable={!!onDelete} selected={sel} onSelectedChange={setSel}
        rowClass={(r) => (r.managedBy ? 'fw-managed' : r.action === 'deny' || r.action === 'reject' ? 'fw-bad' : undefined)}
        empty={empty ?? <p className="fw-empty">{q ? t('rules.noMatch') : t('rules.none')}</p>} />
      {pending && (
        <ConfirmDialog open danger onClose={() => setPending(null)} onConfirm={() => confirm()} confirmLabel={busy ? t('common.working') : tn('rules.deleteN', { n: pending.length })}
          title={tn('rules.confirmTitle', { n: pending.length })}
          description={pending.some((r) => r.managedBy) ? t('rules.managedWarn', { by: pending.find((r) => r.managedBy)!.managedBy! }) : t('rules.confirmText')}>
          <pre className="fw-pre">{pending.map((r) => r.text).join('\n')}</pre>
        </ConfirmDialog>
      )}
    </div>
  );
}

/** A confirm that asks to type a word when the settings say so. */
export function TypedConfirm({ open, word, title, description, label, onClose, onConfirm }: { open: boolean; word: string; title: string; description: ReactNode; label: string; onClose(): void; onConfirm(): unknown }) {
  const [settings] = useSettings();
  if (!open) return null;
  return <ConfirmDialog open danger onClose={onClose} onConfirm={onConfirm} title={title} description={description} confirmLabel={label} confirmText={settings.typedConfirm ? word : undefined} />;
}
