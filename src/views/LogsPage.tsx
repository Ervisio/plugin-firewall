/**
 * Firewall logs: the kernel lines with IN= OUT= SRC= that every firewall writes when it logs a packet, read from the
 * journal or a syslog file, parsed, filtered and counted. "Live" follows the source with a stream.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { CmdError, errorText, run } from '../api';
import { detect, firewalld, ufw, useBackend } from '../data';
import { t, tn } from '../i18n';
import { AreaChart, Badge, Button, IconButton, Input, Segmented, Skeleton, Switch, toast } from '../kit';
import type { LogEntry } from '../model';
import { go, openRuleDialog } from '../nav';
import { isNoise, parseLogLine } from '../parse/misc';
import { getSdk } from '../sdk';
import { useSettings } from '../settings';
import { DataTable, ErrorState, Hint, PageHeader, Section } from '../ui/parts';
import { useInbound } from './hooks';

const RANGES = [{ id: '-1h', ms: 3600e3 }, { id: '-24h', ms: 86400e3 }, { id: '-7d', ms: 7 * 86400e3 }];
const MAX = 20000;
const GREP = '--grep=IN=.*OUT=';

async function readJournal(since: string, lines: number): Promise<string> {
  const exec = (grep: string) => getSdk().api.exec('log-journal', [since, String(lines), grep]);
  let r = await exec(GREP);
  // journalctl built without PCRE2 cannot --grep: read everything and filter here.
  if (r.exitCode !== 0 && /pattern|pcre|grep/i.test(r.stderr)) r = await exec('--no-hostname');
  if (r.exitCode !== 0 && !/-- No entries --|No journal files/.test(r.stdout + r.stderr)) throw new CmdError('log-journal', r.stderr.trim() || `exit ${r.exitCode}`, r.exitCode);
  return r.stdout;
}

const parseAll = (text: string, tz?: number): LogEntry[] => {
  const now = new Date();
  const out: LogEntry[] = [];
  for (const line of text.split('\n')) {
    const e = parseLogLine(line, now, tz);
    if (e) out.push(e);
  }
  return out.reverse();
};

export function LogsPage() {
  const { backend } = useBackend();
  const [settings, ready] = useSettings();
  useInbound(backend);
  const [range, setRange] = useState('-24h');
  const [entries, setEntries] = useState<LogEntry[] | null>(null);
  const [error, setError] = useState<unknown>();
  const [loading, setLoading] = useState(false);
  const [live, setLive] = useState(false);
  const [verdict, setVerdict] = useState<'all' | 'block' | 'allow'>('all');
  const [q, setQ] = useState('');
  const [limit, setLimit] = useState(300);
  const source = settings.logSource;

  const load = async () => {
    setLoading(true);
    setError(undefined);
    try {
      const text = source === 'journal' ? await readJournal(range, settings.logLines) : await run('log-file', [String(settings.logLines), source]);
      const ms = RANGES.find((r) => r.id === range)!.ms;
      const from = Date.now() - ms;
      const tz = (detect.get().data ?? (await detect.refresh(), detect.get().data))?.tzMinutes;
      setEntries(parseAll(text, tz).filter((e) => Number.isNaN(e.time) || e.time >= from));
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    if (ready) void load();
  }, [ready, range, source, settings.logLines]);

  // Live: follow the source, restart when the command ends (it has a 10 minute limit).
  const liveRef = useRef(live);
  liveRef.current = live;
  useEffect(() => {
    if (!live) return;
    let stream: { close(): void } | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const start = () => {
      const [cmd, args] = source === 'journal' ? ['log-journal-follow', [GREP]] as const : ['log-file-follow', [source]] as const;
      stream = getSdk().api.execStream(cmd, [...args], {
        onLine(kind, line) {
          if (kind !== 'stdout') return;
          const e = parseLogLine(line, new Date(), detect.get().data?.tzMinutes);
          if (e) setEntries((cur) => [e, ...(cur ?? [])].slice(0, MAX));
        },
        onExit() {
          if (liveRef.current) timer = setTimeout(start, 1500);
        },
        onError(err) {
          toast.err(t('logs.liveFail'), errorText(err));
          setLive(false);
        },
      });
    };
    start();
    return () => {
      clearTimeout(timer);
      stream?.close();
    };
  }, [live, source]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (entries ?? []).filter((e) => {
      if (settings.hideNoise && isNoise(e)) return false;
      if (verdict === 'block' && e.verdict !== 'block') return false;
      if (verdict === 'allow' && e.verdict !== 'allow') return false;
      if (!needle) return true;
      return `${e.src} ${e.dst} ${e.dpt ?? ''} ${e.spt ?? ''} ${e.proto} ${e.in} ${e.out} ${e.prefix}`.toLowerCase().includes(needle);
    });
  }, [entries, q, verdict, settings.hideNoise]);

  const stats = useMemo(() => {
    const count = (key: (e: LogEntry) => string | undefined) => {
      const m = new Map<string, number>();
      for (const e of filtered) {
        const k = key(e);
        if (k) m.set(k, (m.get(k) ?? 0) + 1);
      }
      return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
    };
    const blocked = filtered.filter((e) => e.verdict === 'block');
    // Time buckets for the chart
    const ms = RANGES.find((r) => r.id === range)!.ms;
    const n = 48;
    const now = Date.now();
    const b = Array(n).fill(0);
    const a = Array(n).fill(0);
    for (const e of filtered) {
      if (Number.isNaN(e.time)) continue;
      const i = Math.floor(((e.time - (now - ms)) / ms) * n);
      if (i < 0 || i >= n) continue;
      if (e.verdict === 'block') b[i]++;
      else a[i]++;
    }
    return {
      blocked: blocked.length,
      sources: new Set(filtered.map((e) => e.src)).size,
      topSrc: count((e) => (e.verdict === 'block' ? e.src : undefined)),
      topPort: count((e) => (e.dpt !== undefined ? `${e.dpt}/${e.proto}` : undefined)),
      series: [{ values: b, label: t('logs.blocked'), color: 'var(--err)' }, { values: a, label: t('logs.other'), color: 'var(--h)' }],
    };
  }, [filtered, range]);

  const block = (ip: string) => {
    go('rules');
    openRuleDialog({ action: 'deny', source: ip, first: true, port: '', proto: 'any', comment: t('logs.blockComment') });
  };
  const exportCsv = () => {
    const rows = [['time', 'verdict', 'prefix', 'in', 'out', 'src', 'spt', 'dst', 'dpt', 'proto'].join(',')];
    for (const e of filtered) rows.push([Number.isNaN(e.time) ? '' : new Date(e.time).toISOString(), e.verdict, JSON.stringify(e.prefix), e.in, e.out, e.src, e.spt ?? '', e.dst, e.dpt ?? '', e.proto].join(','));
    void getSdk().saveFile(`firewall-log-${new Date().toISOString().slice(0, 10)}.csv`, rows.join('\n') + '\n', 'text/csv');
  };

  const u = backend === 'ufw' ? ufw.get().data : undefined;
  const f = backend === 'firewalld' ? firewalld('runtime').get().data : undefined;

  return (
    <>
      <PageHeader icon="logs" title={t('nav.logs')} subtitle={source === 'journal' ? t('logs.subJournal') : t('logs.subFile', { file: source })}
        actions={<>
          <Segmented aria-label={t('logs.range')} value={range} onChange={setRange} options={RANGES.map((r) => ({ value: r.id, label: t(`logs.range.${r.id}`) }))} />
          <Switch checked={live} onChange={setLive} label={t('logs.live')} aria-label={t('logs.live')} />
        </>} />

      {u && u.logging === 'off' && <Hint tone="warn" icon="alert" action={<Button size="sm" variant="secondary" onClick={() => void run('ufw-logging', ['low']).then(() => ufw.refresh()).then(() => toast.ok(t('ufw.loggingSet')), (e) => toast.err(t('err.action'), errorText(e)))}>{t('logs.turnOnUfw')}</Button>}>{t('logs.ufwOff')}</Hint>}
      {f && f.logDenied === 'off' && <Hint tone="warn" icon="alert" action={<Button size="sm" variant="secondary" onClick={() => void run('fwd-log-denied', ['unicast']).then(() => firewalld('runtime').refresh()).then(() => toast.ok(t('fwd.changed')), (e) => toast.err(t('err.action'), errorText(e)))}>{t('logs.turnOnFwd')}</Button>}>{t('logs.fwdOff')}</Hint>}
      {(backend === 'nftables' || backend === 'iptables') && <p className="fw-sec-note">{t('logs.rawNote')}</p>}

      {error ? <ErrorState error={error} onRetry={() => void load()} /> : null}
      {!entries && loading && <Skeleton height={300} style={{ borderRadius: 18 }} />}
      {entries && (
        <>
          <div className="fw-stats">
            <div className="fw-stat"><span>{t('logs.total')}</span><b>{filtered.length}</b></div>
            <div className="fw-stat fw-stat--err"><span>{t('logs.blocked')}</span><b>{stats.blocked}</b></div>
            <div className="fw-stat"><span>{t('logs.sources')}</span><b>{stats.sources}</b></div>
          </div>
          <Section icon="logs" title={t('logs.timeline')}>
            <AreaChart series={stats.series} height={120} label={t('logs.timeline')} />
          </Section>
          <div className="fw-two">
            <Section icon="ban" title={t('logs.topSrc')}>
              {stats.topSrc.length ? stats.topSrc.map(([ip, n]) => (
                <div key={ip} className="fw-top"><span className="fw-mono">{ip}</span><b>{n}</b>{backend && <Button size="sm" variant="ghost" icon="ban" onClick={() => block(ip)}>{t('logs.block')}</Button>}</div>
              )) : <p className="fw-empty">{t('logs.noBlocked')}</p>}
            </Section>
            <Section icon="ports" title={t('logs.topPort')}>
              {stats.topPort.length ? stats.topPort.map(([p, n]) => (
                <div key={p} className="fw-top"><span className="fw-mono">{p}</span><b>{n}</b><Button size="sm" variant="ghost" icon="filter" onClick={() => setQ(p.split('/')[0])}>{t('logs.filter')}</Button></div>
              )) : <p className="fw-empty">{t('logs.noPorts')}</p>}
            </Section>
          </div>
          <Section icon="list" title={t('logs.entries')} action={<>
            <Button size="sm" variant="ghost" icon="download" disabled={!filtered.length} onClick={exportCsv}>{t('logs.export')}</Button>
            <Button size="sm" variant="ghost" icon="refresh" loading={loading} onClick={() => void load()}>{t('common.refresh')}</Button>
          </>}>
            <div className="fw-toolbar">
              <Input compact icon="search" fieldClassName="fw-search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('logs.search')} aria-label={t('logs.search')}
                end={q ? <IconButton icon="close" size="sm" label={t('common.clear')} onClick={() => setQ('')} /> : undefined} />
              <Segmented aria-label={t('logs.verdict')} value={verdict} onChange={(v) => setVerdict(v as typeof verdict)} options={[{ value: 'all', label: t('logs.all') }, { value: 'block', label: t('logs.blocked') }, { value: 'allow', label: t('logs.allowed') }]} />
            </div>
            <DataTable rows={filtered.slice(0, limit)} rowKey={(e) => `${e.time}-${e.raw.length}-${e.src}-${e.spt}-${e.dpt}-${e.raw.slice(-24)}`}
              empty={<p className="fw-empty">{entries.length ? t('logs.noMatch') : t('logs.none')}</p>}
              rowClass={(e) => (e.verdict === 'block' ? 'fw-bad' : undefined)}
              columns={[
                { key: 'time', header: t('col.time'), render: (e) => <span className="fw-mono fw-muted">{Number.isNaN(e.time) ? '' : new Date(e.time).toLocaleString()}</span>, width: 170 },
                { key: 'v', header: t('col.verdict'), render: (e) => <Badge tone={e.verdict === 'block' ? 'err' : e.verdict === 'allow' ? 'ok' : 'neutral'}>{t(`verdict.${e.verdict}`)}</Badge>, width: 100 },
                { key: 'src', header: t('col.source'), render: (e) => <span className="fw-mono">{e.src}{e.spt !== undefined ? `:${e.spt}` : ''}</span> },
                { key: 'dst', header: t('col.dest'), render: (e) => <span className="fw-mono">{e.dst}{e.dpt !== undefined ? `:${e.dpt}` : ''}</span>, hideBelow: 'sm' },
                { key: 'proto', header: t('col.proto'), render: (e) => <span className="fw-mono">{e.proto}{e.flags.includes('SYN') ? ' SYN' : ''}</span>, hideBelow: 'md' },
                { key: 'if', header: t('col.iface'), render: (e) => <span className="fw-mono fw-muted">{e.in || e.out}</span>, hideBelow: 'md' },
                { key: 'prefix', header: t('col.prefix'), render: (e) => <span className="fw-mono fw-muted fw-wrap">{e.prefix}</span>, hideBelow: 'md' },
                { key: 'act', header: '', width: 44, render: (e) => backend && e.src ? <IconButton icon="ban" size="sm" variant="ghost" label={t('logs.blockIp', { ip: e.src })} onClick={() => block(e.src)} /> : null },
              ]} />
            {filtered.length > limit && <Button variant="ghost" onClick={() => setLimit((l) => l + 500)}>{tn('logs.more', { n: filtered.length - limit })}</Button>}
          </Section>
        </>
      )}
    </>
  );
}
