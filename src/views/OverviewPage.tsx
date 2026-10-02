import { detect, listeners, useBackend, useSshPort } from '../data';
import { t } from '../i18n';
import { Badge, Button, Skeleton } from '../kit';
import { BACKENDS, type Listener, type Rule } from '../model';
import { go, openRuleDialog } from '../nav';
import { SERVICE_PORTS } from '../parse/firewalld';
import { installed } from '../parse/misc';
import { coversPort, isAny } from '../parse/ports';
import { DataTable, ErrorState, Hint, PageHeader, Section } from '../ui/parts';
import { policyOpen, useInbound, useLiveActive, useSshState } from './hooks';
import { backendActive, backendVersion } from './status';

type Exposure = 'local' | 'open' | 'closed' | 'unknown';

function ruleOpens(r: Rule, port: number, proto: string): boolean {
  if (r.action !== 'allow' && r.action !== 'limit') return false;
  if (r.direction === 'out' || r.direction === 'fwd' || r.iface) return false;
  if (!isAny(r.source)) return false;
  if (r.proto !== 'any' && r.proto !== proto) return false;
  if (r.service && !r.port) return (SERVICE_PORTS[r.service] ?? (/ssh/i.test(r.service) ? ['22/tcp'] : [])).includes(`${port}/${proto}`);
  if (!r.port) return !/\b(ct ?state|state|established|related|iifname)\b/i.test(r.text);
  return coversPort(r.port, port);
}

export function OverviewPage() {
  const { backend, detected, settings, loading } = useBackend();
  const d = detect.use();
  const l = listeners.use();
  const { rules } = useInbound(backend);
  const sshPort = useSshPort();
  const ssh = useSshState(backend, sshPort);
  const live = useLiveActive(backend, undefined);

  const exposure = (x: Listener): Exposure => {
    if (x.local) return 'local';
    if (!backend || !rules) return 'unknown';
    const open = policyOpen(backend);
    if (open === null) return 'unknown';
    if (open) return 'open';
    return rules.some((r) => ruleOpens(r, x.port, x.proto)) ? 'open' : 'closed';
  };
  const conflict = detected && installed(detected, 'ufw') && detected.ufwEnabled && detected.units.firewalld?.active === 'active';
  const ports = (l.data ?? []).filter((x, i, all) => all.findIndex((y) => y.proto === x.proto && y.port === x.port && y.local === x.local) === i);

  return (
    <>
      <PageHeader icon="shield" title={t('nav.overview')} subtitle={backend ? t('overview.sub', { name: t(`backend.${backend}`) }) : loading || !detected ? undefined : t('overview.subNone')}
        actions={<>
          <Button variant="secondary" icon="ban" onClick={() => { go('rules'); openRuleDialog({ action: 'deny', first: true, port: '' }); }} disabled={!backend}>{t('overview.blockIp')}</Button>
          <Button variant="primary" icon="plus" onClick={() => { go('rules'); openRuleDialog(); }} disabled={!backend}>{t('rule.new')}</Button>
        </>} />

      {d.error ? <ErrorState error={d.error} onRetry={() => void detect.refresh()} /> : null}
      <div className="fw-tiles fw-tiles--status">
        {!detected && <Skeleton height={76} style={{ borderRadius: 18, gridColumn: '1 / -1' }} />}
        {detected && [...BACKENDS, 'fail2ban' as const].map((b) => {
          const has = installed(detected, b);
          const on = has && (b === backend && live !== undefined ? live : backendActive(detected, b));
          const managed = b === backend;
          return (
            <button key={b} type="button" className="fw-tile" data-on={managed || undefined} disabled={!has} onClick={() => go(b === 'fail2ban' ? 'bans' : managed ? 'rules' : 'settings')}>
              <span className="fw-tile-top"><b>{t(`backend.${b}`)}</b>{managed && <Badge tone="info">{t('overview.managed')}</Badge>}</span>
              <small><span className={`fw-dot fw-dot--${!has ? 'off' : on ? 'ok' : 'warn'}`} />{!has ? t('status.notInstalled') : `${on ? t('status.active') : t('status.inactive')} ${backendVersion(detected, b)}`}</small>
            </button>
          );
        })}
      </div>

      {conflict && <Hint tone="warn" icon="alert">{t('overview.conflict')}</Hint>}
      {ssh === 'unfiltered' && backend && <Hint tone="warn" icon="alert">{t('overview.unfiltered', { name: t(`backend.${backend}`) })}</Hint>}
      {backend && ssh === 'open' && <Hint tone="ok" icon="check">{t('overview.sshOk', { port: sshPort })}</Hint>}
      {backend && ssh === 'closed' && (
        <Hint tone={settings.sshGuard ? 'warn' : 'err'} icon="alert" action={<Button size="sm" variant="secondary" onClick={() => { go('rules'); openRuleDialog({ port: String(sshPort), proto: 'tcp', comment: 'SSH' }); }}>{t('overview.openSsh', { port: sshPort })}</Button>}>
          {t('overview.sshClosed', { port: sshPort })}
        </Hint>
      )}

      <Section icon="ports" title={t('overview.listening')} action={<Button size="sm" variant="ghost" icon="refresh" onClick={() => void listeners.refresh()}>{t('common.refresh')}</Button>}>
        <p className="fw-sec-note">{t('overview.listeningNote')}</p>
        {l.error && !l.data ? <ErrorState error={l.error} onRetry={() => void listeners.refresh()} /> : !l.data ? <Skeleton height={140} style={{ borderRadius: 14 }} /> : (
          <DataTable rows={ports} rowKey={(x) => `${x.proto}-${x.port}-${x.local}`} empty={<p className="fw-empty">{t('overview.noListeners')}</p>}
            columns={[
              { key: 'port', header: t('col.port'), render: (x) => <b className="fw-mono">{x.port}/{x.proto}</b>, width: 110 },
              { key: 'proc', header: t('col.process'), render: (x) => x.process || <span className="fw-muted">?</span> },
              { key: 'addr', header: t('col.address'), render: (x) => <span className="fw-mono fw-muted">{x.address}</span>, hideBelow: 'sm' },
              { key: 'exp', header: t('col.exposure'), render: (x) => { const e = exposure(x); return <Badge tone={e === 'open' ? 'warn' : e === 'closed' ? 'ok' : 'neutral'}>{t(`exposure.${e}`)}</Badge>; } },
              { key: 'act', header: '', align: 'right', render: (x) => exposure(x) === 'closed' && backend ? (
                <Button size="sm" variant="ghost" icon="plus" onClick={() => { go('rules'); openRuleDialog({ port: String(x.port), proto: x.proto, comment: x.process || '' }); }}>{t('overview.open')}</Button>
              ) : exposure(x) === 'open' && backend ? (
                <Button size="sm" variant="ghost" icon="lock" onClick={() => { go('rules'); openRuleDialog({ action: 'deny', port: String(x.port), proto: x.proto, first: true }); }}>{t('overview.close')}</Button>
              ) : null },
            ]} />
        )}
      </Section>
    </>
  );
}
