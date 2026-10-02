import { useState } from 'react';
import { errorText, run } from '../api';
import { f2bCall } from '../backends/translate';
import { detect, f2b } from '../data';
import { t, tn } from '../i18n';
import { Badge, Button, EmptyState, IconButton, Input, Select, Skeleton, toast } from '../kit';
import type { Jail } from '../model';
import { installed } from '../parse/misc';
import { isIPv4, isIPv6 } from '../parse/ports';
import { ErrorState, Hint, PageHeader, Section } from '../ui/parts';

export function BansPage() {
  const d = detect.use();
  const { data, error, loading } = f2b.use();
  const [busy, setBusy] = useState('');
  const [jail, setJail] = useState('');
  const [ip, setIp] = useState('');
  const [q, setQ] = useState('');

  if (d.data && !installed(d.data, 'fail2ban')) {
    return <><PageHeader icon="ban" title={t('nav.bans')} /><EmptyState icon="ban" title={t('bans.notInstalled')} text={t('bans.notInstalledText')} /></>;
  }

  const act = async (key: string, j: string, op: 'banip' | 'unbanip', addr: string) => {
    setBusy(key);
    try {
      const c = f2bCall(j, op, addr);
      await run(c.command, c.args);
      await f2b.refresh();
      toast.ok(op === 'banip' ? t('bans.banned', { ip: addr, jail: j }) : t('bans.unbanned', { ip: addr, jail: j }));
      if (op === 'banip') setIp('');
    } catch (e) {
      toast.err(t('err.action'), errorText(e));
    } finally {
      setBusy('');
    }
  };
  const ipOk = isIPv4(ip) || isIPv6(ip);
  const jails = data?.jails ?? [];
  const pick = jail || jails.find((j) => j.name === 'sshd')?.name || jails[0]?.name || '';
  const total = jails.reduce((n, j) => n + j.currentlyBanned, 0);
  const match = (x: string) => !q || x.includes(q.trim());

  return (
    <>
      <PageHeader icon="ban" title={t('nav.bans')} subtitle={data?.running ? tn('bans.sub', { n: total, jails: jails.length, version: data.version }) : undefined}
        actions={<Button variant="ghost" icon="refresh" loading={loading} onClick={() => void f2b.refresh()}>{t('common.refresh')}</Button>} />
      {!data && loading && <Skeleton height={220} style={{ borderRadius: 18 }} />}
      {!data && error ? <ErrorState error={error} onRetry={() => void f2b.refresh()} /> : null}
      {data && !data.running && <EmptyState icon="power" title={t('bans.down')} text={t('bans.downText')} />}
      {data?.running && (
        <>
          <Section icon="ban" title={t('bans.banTitle')}>
            <form className="fw-inline-form" onSubmit={(e) => { e.preventDefault(); if (ipOk && pick) void act('ban', pick, 'banip', ip); }}>
              <Input compact mono value={ip} onChange={(e) => setIp(e.target.value.trim())} placeholder="203.0.113.7" aria-label={t('bans.ip')} error={ip && !ipOk ? t('spec.badAddr') : undefined} />
              <Select compact aria-label={t('bans.jail')} value={pick} onChange={setJail} options={jails.map((j) => ({ value: j.name, label: j.name }))} />
              <Button type="submit" variant="danger" icon="ban" disabled={!ipOk || !pick || !!busy} loading={busy === 'ban'}>{t('bans.ban')}</Button>
            </form>
            <p className="fw-sec-note">{t('bans.banNote')}</p>
          </Section>
          {total > 8 && <Input compact icon="search" fieldClassName="fw-search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('bans.search')} aria-label={t('bans.search')} />}
          {jails.map((j) => <JailCard key={j.name} jail={j} busy={busy} match={match} onUnban={(addr) => void act(`un-${j.name}-${addr}`, j.name, 'unbanip', addr)} />)}
          {!jails.length && <Hint icon="info">{t('bans.noJails')}</Hint>}
        </>
      )}
    </>
  );
}

function JailCard({ jail, busy, match, onUnban }: { jail: Jail; busy: string; match(x: string): boolean; onUnban(ip: string): void }) {
  const list = jail.banned.filter(match);
  return (
    <Section icon="lock" title={<><span className="fw-mono">{jail.name}</span><Badge tone={jail.currentlyBanned ? 'err' : 'neutral'}>{tn('bans.count', { n: jail.currentlyBanned })}</Badge></>}>
      <div className="fw-kv">
        <div><span>{t('bans.failedNow')}</span><b>{jail.currentlyFailed}</b></div>
        <div><span>{t('bans.failedTotal')}</span><b>{jail.totalFailed}</b></div>
        <div><span>{t('bans.bannedTotal')}</span><b>{jail.totalBanned}</b></div>
        <div className="fw-kv-wide"><span>{t('bans.watches')}</span><b className="fw-mono fw-wrap">{jail.files.join(' ') || '?'}</b></div>
      </div>
      {list.length ? (
        <div className="fw-chips">
          {list.map((ip) => (
            <span key={ip} className="fw-chip">
              <span className="fw-mono">{ip}</span>
              <IconButton icon="close" size="sm" variant="ghost" label={t('bans.unban', { ip })} disabled={!!busy} onClick={() => onUnban(ip)} />
            </span>
          ))}
        </div>
      ) : <p className="fw-empty">{jail.banned.length ? t('bans.noMatch') : t('bans.none')}</p>}
    </Section>
  );
}
