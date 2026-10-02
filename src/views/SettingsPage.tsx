/**
 * Settings (design round 001, variant A "Lista raggruppata"): sections of label + control rows, a strip of jump links,
 * a sticky footer that saves. The watchdog row talks to the jobs API directly: it is not part of the saved file.
 */
import { useEffect, useState } from 'react';
import { errorText } from '../api';
import { detect, listeners, useBackend } from '../data';
import { t } from '../i18n';
import { Badge, Button, Input, Segmented, Select, Skeleton, Switch, toast } from '../kit';
import { BACKENDS, type BackendId } from '../model';
import { installed, pickBackend, sshPortFrom } from '../parse/misc';
import { getSdk } from '../sdk';
import { DEFAULTS, saveSettings, useSettings, type LogSource, type Settings } from '../settings';
import { Hint, PageHeader, Row, Section } from '../ui/parts';
import { useSshState, useWatchdog } from './hooks';
import { backendActive, backendVersion } from './status';

const LOG_SOURCES: LogSource[] = ['journal', '/var/log/ufw.log', '/var/log/kern.log', '/var/log/messages', '/var/log/syslog', '/var/log/firewalld'];
const SECTIONS = ['be', 'safe', 'apply', 'log', 'watch'] as const;

export function SettingsPage() {
  const [saved, ready] = useSettings();
  const [draft, setDraft] = useState<Settings>(saved);
  const [busy, setBusy] = useState(false);
  useEffect(() => setDraft(saved), [saved]);
  const set = <K extends keyof Settings>(k: K, v: Settings[K]) => setDraft((d) => ({ ...d, [k]: v }));
  const dirty = JSON.stringify(draft) !== JSON.stringify(saved);

  const save = async () => {
    setBusy(true);
    try {
      await saveSettings(draft);
      toast.ok(t('settings.saved'));
    } catch (e) {
      toast.err(t('settings.saveFail'), errorText(e));
    } finally {
      setBusy(false);
    }
  };

  if (!ready) return <><PageHeader icon="cog" title={t('nav.settings')} /><Skeleton height={320} style={{ borderRadius: 18 }} /></>;

  return (
    <>
      <PageHeader icon="cog" title={t('nav.settings')} subtitle={t('settings.sub')} />
      <nav className="fw-jump" aria-label={t('settings.jump')}>
        {SECTIONS.map((s) => <a key={s} href={`#fw-set-${s}`} onClick={(e) => { e.preventDefault(); document.getElementById(`fw-set-${s}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' }); }}>{t(`settings.sec.${s}`)}</a>)}
      </nav>
      <BackendSection draft={draft} set={set} />
      <SafetySection draft={draft} set={set} />
      <ApplySection draft={draft} set={set} />
      <LogSection draft={draft} set={set} />
      <WatchdogSection />
      <div className="fw-foot">
        {dirty && <span className="fw-muted">{t('settings.unsaved')}</span>}
        <Button variant="ghost" onClick={() => setDraft({ ...DEFAULTS })} disabled={JSON.stringify(draft) === JSON.stringify(DEFAULTS)}>{t('settings.restore')}</Button>
        <Button variant="primary" icon="check" loading={busy} disabled={!dirty || busy} onClick={() => void save()}>{t('settings.save')}</Button>
      </div>
    </>
  );
}

type SecProps = { draft: Settings; set<K extends keyof Settings>(k: K, v: Settings[K]): void };

function BackendSection({ draft, set }: SecProps) {
  const d = detect.use();
  const det = d.data;
  const auto = det ? pickBackend(det) : null;
  const tile = (id: 'auto' | BackendId) => {
    const isAuto = id === 'auto';
    const has = isAuto ? !!auto : !!det && installed(det, id);
    const on = draft.backend === id;
    let sub = '';
    if (!det) sub = '…';
    else if (isAuto) sub = auto ? t('settings.be.autoUses', { name: t(`backend.${auto}`) }) : t('settings.be.noneFound');
    else if (!has) sub = t('status.notInstalled');
    else sub = `${backendActive(det, id) ? t('status.active') : t('status.inactive')}${backendVersion(det, id) ? `, ${backendVersion(det, id)}` : ''}`;
    return (
      <button key={id} type="button" role="radio" aria-checked={on} className="fw-tile" data-on={on || undefined} disabled={!has} onClick={() => set('backend', id)}>
        <b>{isAuto ? t('settings.be.auto') : t(`backend.${id}`)}</b>
        <small>{sub}</small>
      </button>
    );
  };
  return (
    <Section id="fw-set-be" icon="shield" title={t('settings.sec.be')}>
      <div className="fw-tiles" role="radiogroup" aria-label={t('settings.sec.be')}>
        {tile('auto')}
        {BACKENDS.map(tile)}
      </div>
      {det && det.iptablesMode === 'nf_tables' && <p className="fw-sec-note">{t('settings.be.iptNft')}</p>}
      {det && installed(det, 'fail2ban') && <p className="fw-sec-note">{t('settings.be.f2b', { state: backendActive(det, 'fail2ban') ? t('status.active') : t('status.inactive') })}</p>}
    </Section>
  );
}

function SafetySection({ draft, set }: SecProps) {
  const { backend } = useBackend();
  const l = listeners.use();
  const detected = l.data ? sshPortFrom(l.data) : null;
  const effective = draft.sshPort || detected || 22;
  const ssh = useSshState(backend, effective);
  return (
    <Section id="fw-set-safe" icon="lock" title={t('settings.sec.safe')}>
      {ssh === 'open' && <Hint tone="ok" icon="check">{t('settings.ssh.open', { port: effective })}</Hint>}
      {ssh === 'closed' && <Hint tone="warn" icon="alert">{t('settings.ssh.closed', { port: effective })}</Hint>}
      {ssh === 'unfiltered' && backend && <Hint tone="info" icon="info">{t('settings.ssh.unfiltered', { name: t(`backend.${backend}`) })}</Hint>}
      <Row label={t('settings.ssh.label')} desc={t('settings.ssh.desc')} htmlFor="fw-ssh-port">
        <Input id="fw-ssh-port" mono compact inputMode="numeric" style={{ width: 90 }} value={draft.sshPort ? String(draft.sshPort) : ''} placeholder={String(detected ?? 22)} aria-label={t('settings.ssh.port')}
          onChange={(e) => { const n = Number(e.target.value.replace(/\D/g, '')); set('sshPort', n > 0 && n < 65536 ? n : 0); }} />
        <Switch checked={draft.sshGuard} onChange={(v) => set('sshGuard', v)} aria-label={t('settings.ssh.label')} />
      </Row>
      {!draft.sshPort && <p className="fw-sec-note">{detected ? t('settings.ssh.detected', { port: detected }) : t('settings.ssh.default')}</p>}
      <Row label={t('settings.typed.label')} desc={t('settings.typed.desc')}>
        <Switch checked={draft.typedConfirm} onChange={(v) => set('typedConfirm', v)} aria-label={t('settings.typed.label')} />
      </Row>
    </Section>
  );
}

function ApplySection({ draft, set }: SecProps) {
  return (
    <Section id="fw-set-apply" icon="check" title={t('settings.sec.apply')}>
      <Row label={t('settings.fwd.label')} desc={t(`settings.fwd.desc.${draft.firewalldMode}`)}>
        <Segmented aria-label={t('settings.fwd.label')} value={draft.firewalldMode} onChange={(v) => set('firewalldMode', v as Settings['firewalldMode'])}
          options={(['both', 'permanent', 'runtime'] as const).map((m) => ({ value: m, label: t(`settings.fwd.${m}`) }))} />
      </Row>
      <Row label={t('settings.nft.label')} desc={t('settings.nft.desc')}>
        <Select compact aria-label={t('settings.nft.file')} value={draft.nftFile} onChange={(v) => set('nftFile', v as Settings['nftFile'])}
          options={[{ value: '/etc/nftables.conf', label: '/etc/nftables.conf' }, { value: '/etc/sysconfig/nftables.conf', label: '/etc/sysconfig/nftables.conf' }]} />
        <Switch checked={draft.nftSave} onChange={(v) => set('nftSave', v)} aria-label={t('settings.nft.label')} />
      </Row>
      <Row label={t('settings.ipt.label')} desc={t(`settings.ipt.desc.${draft.iptLayout}`)}>
        <Select compact aria-label={t('settings.ipt.layout')} value={draft.iptLayout} onChange={(v) => set('iptLayout', v as Settings['iptLayout'])}
          options={[{ value: 'debian', label: 'Debian, Ubuntu' }, { value: 'rhel', label: 'RHEL, Fedora' }]} />
        <Switch checked={draft.iptSave} onChange={(v) => set('iptSave', v)} aria-label={t('settings.ipt.label')} />
      </Row>
      <Row label={t('settings.comment.label')} desc={t('settings.comment.desc')} htmlFor="fw-comment">
        <Input id="fw-comment" compact style={{ width: 200 }} value={draft.defaultComment} maxLength={64} onChange={(e) => set('defaultComment', e.target.value)} />
      </Row>
      <Row label={t('settings.v6.label')} desc={t('settings.v6.desc')}>
        <Switch checked={draft.showV6} onChange={(v) => set('showV6', v)} aria-label={t('settings.v6.label')} />
      </Row>
    </Section>
  );
}

function LogSection({ draft, set }: SecProps) {
  return (
    <Section id="fw-set-log" icon="logs" title={t('settings.sec.log')}>
      <Row label={t('settings.logsrc.label')} desc={t('settings.logsrc.desc')}>
        <Select compact aria-label={t('settings.logsrc.label')} value={draft.logSource} onChange={(v) => set('logSource', v as LogSource)}
          options={LOG_SOURCES.map((s) => ({ value: s, label: s === 'journal' ? t('logs.src.journal') : s }))} />
      </Row>
      <Row label={t('settings.lines.label')} desc={t('settings.lines.desc')} htmlFor="fw-lines">
        <Input id="fw-lines" mono compact inputMode="numeric" style={{ width: 100 }} value={String(draft.logLines)} onChange={(e) => { const n = Number(e.target.value.replace(/\D/g, '')); set('logLines', Math.min(Math.max(n || 1, 1), 50000)); }} />
      </Row>
      <Row label={t('settings.noise.label')} desc={t('settings.noise.desc')}>
        <Switch checked={draft.hideNoise} onChange={(v) => set('hideNoise', v)} aria-label={t('settings.noise.label')} />
      </Row>
    </Section>
  );
}

const EVERY = [300, 900, 3600];

function WatchdogSection() {
  const { backend } = useBackend();
  const { jobs, error, reload } = useWatchdog();
  const [busy, setBusy] = useState(false);
  const [every, setEvery] = useState(300);
  const api = getSdk().api.jobs;
  const job = jobs?.[0];
  useEffect(() => {
    if (job?.schedule?.every) setEvery(job.schedule.every);
  }, [job?.id, job?.schedule?.every]);

  const act = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true);
    try {
      await fn();
      toast.ok(ok);
    } catch (e) {
      toast.err(t('watch.fail'), errorText(e));
    } finally {
      setBusy(false);
      reload();
    }
  };
  const toggle = (on: boolean) => {
    if (!api || !backend) return;
    if (on) void act(() => api.create({ job: 'watchdog', name: t(`backend.${backend}`), params: { backend }, schedule: { every } }), t('watch.created'));
    else if (job) void act(() => api.delete(job.id), t('watch.deleted'));
  };
  const changeEvery = (v: string) => {
    const n = Number(v);
    setEvery(n);
    if (job && api) void act(() => api.update(job.id, { schedule: { every: n } }), t('watch.updated'));
  };
  const wrongBackend = job && backend && job.params.backend !== backend;

  return (
    <Section id="fw-set-watch" icon="bell" title={t('settings.sec.watch')}>
      <Row label={t('watch.label', { name: backend ? t(`backend.${backend}`) : t('watch.theFirewall') })} desc={t('watch.desc')}>
        <Select compact aria-label={t('watch.every')} value={String(every)} onChange={changeEvery} disabled={busy}
          options={EVERY.map((s) => ({ value: String(s), label: t(`watch.every.${s}`) }))} />
        <Switch checked={!!job} disabled={busy || !api || !backend || jobs === null} onChange={toggle} aria-label={t('watch.label', { name: '' })} />
      </Row>
      {error && <Hint tone="err" icon="alert">{error}</Hint>}
      {job?.awaitingApproval && <Hint tone="warn" icon="lock">{t('watch.approval')}</Hint>}
      {job && !job.awaitingApproval && job.last && (
        <p className="fw-sec-note">
          {t('watch.last', { when: new Date(job.last.started).toLocaleString() })} <Badge tone={job.last.status === 'ok' ? 'ok' : 'err'}>{job.last.status}</Badge>
        </p>
      )}
      {wrongBackend && (
        <Hint tone="warn" icon="alert" action={<Button size="sm" variant="secondary" disabled={busy} onClick={() => void act(() => api!.update(job!.id, { params: { backend: backend! }, name: t(`backend.${backend}`) }), t('watch.updated'))}>{t('watch.switch', { name: t(`backend.${backend}`) })}</Button>}>
          {t('watch.mismatch', { name: t(`backend.${job!.params.backend as BackendId}`) })}
        </Hint>
      )}
    </Section>
  );
}
