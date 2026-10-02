/** The changes made through this plugin, from Ervisio's activity log (sdk.audit). */
import { useEffect, useState } from 'react';
import { errorText } from '../api';
import { t } from '../i18n';
import { Badge, Button, Input, Skeleton, Switch } from '../kit';
import { getSdk, type AuditEntry } from '../sdk';
import { DataTable, ErrorState, Hint, PageHeader } from '../ui/parts';

/** Commands that only read: Ervisio logs them too, but they are noise here. */
const READS = /^(detect|listening|state|ufw-status|ufw-apps|fwd-info|nft-list|ipt-list|f2b-status|log-journal|log-journal-follow|log-file|log-file-follow)(\s|$)/;
const isChange = (e: AuditEntry) => e.action !== 'command' || !READS.test(e.target ?? '');

export function ActivityPage() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [next, setNext] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [error, setError] = useState<unknown>();
  const [text, setText] = useState('');
  const [query, setQuery] = useState('');
  const [busy, setBusy] = useState(false);
  const [changesOnly, setChangesOnly] = useState(true);

  const load = async (cursor?: string) => {
    setBusy(true);
    try {
      const r = await getSdk().audit.list({ limit: 100, cursor, text: query || undefined });
      setEntries((cur) => (cursor ? [...(cur ?? []), ...r.entries] : r.entries));
      setNext(r.next);
      setEnabled(r.enabled);
      setError(undefined);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    void load();
  }, [query]);

  return (
    <>
      <PageHeader icon="clock" title={t('nav.activity')} subtitle={t('activity.sub')} actions={<Button variant="ghost" icon="refresh" loading={busy} onClick={() => void load()}>{t('common.refresh')}</Button>} />
      {!enabled && <Hint tone="warn" icon="alert">{t('activity.off')}</Hint>}
      <form className="fw-toolbar" onSubmit={(e) => { e.preventDefault(); setQuery(text.trim()); }}>
        <Input compact icon="search" fieldClassName="fw-search" value={text} onChange={(e) => setText(e.target.value)} placeholder={t('activity.search')} aria-label={t('activity.search')} />
        <Button type="submit" size="sm" variant="secondary">{t('activity.find')}</Button>
        <Switch checked={changesOnly} onChange={setChangesOnly} label={t('activity.changesOnly')} aria-label={t('activity.changesOnly')} />
      </form>
      {error ? <ErrorState error={error} onRetry={() => void load()} /> : null}
      {!entries && !error && <Skeleton height={240} style={{ borderRadius: 18 }} />}
      {entries && (
        <DataTable rows={changesOnly ? entries.filter(isChange) : entries} rowKey={(e) => `${e.time}-${e.target}-${e.user}`} empty={<p className="fw-empty">{t('activity.none')}</p>}
          rowClass={(e) => (e.result !== 'ok' ? 'fw-bad' : undefined)}
          columns={[
            { key: 'time', header: t('col.time'), render: (e) => <span className="fw-mono fw-muted">{new Date(e.time).toLocaleString()}</span>, width: 170 },
            { key: 'user', header: t('col.user'), render: (e) => <b>{e.user}</b>, hideBelow: 'sm' },
            { key: 'target', header: t('col.command'), render: (e) => <span className="fw-mono fw-wrap">{e.target}{e.origin && <Badge>{e.origin}</Badge>}</span> },
            { key: 'res', header: t('col.result'), render: (e) => <Badge tone={e.result === 'ok' ? 'ok' : e.result === 'denied' ? 'warn' : 'err'}>{t(`result.${e.result}`)}</Badge>, width: 110 },
            { key: 'detail', header: '', render: (e) => <span className="fw-muted fw-wrap">{e.detail ?? (e.admin ? t('activity.admin') : '')}</span>, hideBelow: 'md' },
          ]} />
      )}
      {next && <Button variant="ghost" loading={busy} onClick={() => void load(next)}>{t('activity.more')}</Button>}
      {error && <p className="fw-muted">{errorText(error)}</p>}
    </>
  );
}
