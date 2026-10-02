import { useState } from 'react';
import { errorText, run, runAll } from '../../api';
import { fwdCalls, fwdRemoveOp } from '../../backends/translate';
import { afterChange, firewalld, inboundRules } from '../../data';
import { t } from '../../i18n';
import { Badge, Button, EmptyState, Segmented, Select, Skeleton, Switch, Tabs, toast } from '../../kit';
import type { Rule } from '../../model';
import { openRuleDialog } from '../../nav';
import { zoneRules } from '../../parse/firewalld';
import { useSettings } from '../../settings';
import { ErrorState, Hint, Row, Section } from '../../ui/parts';
import { RuleTable } from './shared';

const LOG_DENIED = ['off', 'all', 'unicast', 'broadcast', 'multicast'];

export function FirewalldRules() {
  const [config, setConfig] = useState<'runtime' | 'permanent'>('runtime');
  const { data, error, loading } = firewalld(config).use();
  const [settings] = useSettings();
  const [zoneSel, setZone] = useState('');
  const [busy, setBusy] = useState('');

  if (!data && loading) return <Skeleton height={260} style={{ borderRadius: 18 }} />;
  if (!data) return <ErrorState error={error} onRetry={() => void firewalld(config).refresh()} />;
  if (!data.running && config === 'runtime') {
    return <EmptyState icon="power" title={t('fwd.notRunning')} text={t('fwd.notRunningText', { state: data.state || '?' })} />;
  }

  const zones = [...data.zones].sort((a, b) => Number(b.active || b.isDefault) - Number(a.active || a.isDefault) || a.name.localeCompare(b.name));
  const zone = zones.find((z) => z.name === zoneSel) ?? zones.find((z) => z.isDefault) ?? zones[0];
  const mode = config === 'permanent' ? 'permanent' : settings.firewalldMode;

  const act = async (key: string, fn: () => Promise<unknown>, ok: string) => {
    setBusy(key);
    try {
      await fn();
      await afterChange('firewalld');
      toast.ok(ok);
    } catch (e) {
      toast.err(t('err.action'), errorText(e));
    } finally {
      setBusy('');
    }
  };
  const del = async (rules: Rule[]) => {
    await runAll(fwdCalls(zone.name, rules.map(fwdRemoveOp), mode));
    await afterChange('firewalld');
  };

  return (
    <>
      <Section icon="globe" title={t('fwd.zones')} action={<>
        <Segmented aria-label={t('fwd.config')} value={config} onChange={(v) => setConfig(v as 'runtime' | 'permanent')} options={[{ value: 'runtime', label: t('fwd.runtime') }, { value: 'permanent', label: t('fwd.permanent') }]} />
      </>}>
        <Tabs aria-label={t('fwd.zones')} variant="pill" value={zone?.name ?? ''} onChange={setZone}
          items={zones.filter((z) => z.active || z.isDefault || z.name === zone?.name).map((z) => ({ id: z.name, label: z.name, count: z.isDefault ? '★' : undefined }))} />
        <div className="fw-zone-pick">
          <Select compact aria-label={t('fwd.otherZone')} value="" onChange={(v) => v && setZone(v)}
            options={[{ value: '', label: t('fwd.otherZone') }, ...zones.filter((z) => !z.active && !z.isDefault).map((z) => ({ value: z.name, label: z.name }))]} />
        </div>
        {zone && (
          <>
            <Row label={t('fwd.zoneTarget')} desc={t('fwd.zoneTargetDesc')}><Badge>{zone.target}</Badge></Row>
            <Row label={t('fwd.bound')} desc={t('fwd.boundDesc')}>
              <span className="fw-mono fw-wrap">{[...zone.interfaces, ...zone.sources].join(', ') || t('fwd.boundNone')}</span>
            </Row>
            <Row label={t('fwd.masq')} desc={t('fwd.masqDesc')}>
              <Switch checked={zone.masquerade} disabled={!!busy} aria-label={t('fwd.masq')}
                onChange={(on) => void act('masq', () => runAll(fwdCalls(zone.name, [on ? '--add-masquerade' : '--remove-masquerade'], mode)), t('fwd.changed'))} />
            </Row>
            {!zone.isDefault && config === 'runtime' && (
              <Row label={t('fwd.makeDefault')} desc={t('fwd.makeDefaultDesc', { zone: data.defaultZone })}>
                <Button size="sm" variant="secondary" disabled={!!busy} onClick={() => void act('def', () => run('fwd-default-zone', [zone.name]), t('fwd.changed'))}>{t('fwd.makeDefaultBtn', { zone: zone.name })}</Button>
              </Row>
            )}
          </>
        )}
      </Section>

      {zone && (
        <Section icon="list" title={t('fwd.rulesOf', { zone: zone.name })} action={<>
          <Button size="sm" variant="ghost" icon="refresh" onClick={() => void firewalld(config).refresh()}>{t('common.refresh')}</Button>
          <Button size="sm" variant="primary" icon="plus" onClick={() => openRuleDialog({ zone: zone.name })}>{t('rule.new')}</Button>
        </>}>
          {config === 'permanent' && <Hint icon="info">{t('fwd.permanentNote')}</Hint>}
          <RuleTable rules={zoneRules(zone)} inbound={inboundRules('firewalld') ?? zoneRules(zone)} onDelete={del} />
        </Section>
      )}

      <Section icon="cog" title={t('fwd.service')}>
        <Row label={t('fwd.logDenied')} desc={t('fwd.logDeniedDesc')}>
          <Select compact aria-label={t('fwd.logDenied')} value={LOG_DENIED.includes(data.logDenied) ? data.logDenied : 'off'} disabled={!!busy}
            onChange={(v) => void act('log', () => run('fwd-log-denied', [v]), t('fwd.changed'))} options={LOG_DENIED.map((l) => ({ value: l, label: t(`fwd.log.${l}`) }))} />
        </Row>
        <Row label={t('fwd.reload')} desc={t('fwd.reloadDesc')}>
          <Button size="sm" variant="secondary" icon="refresh" loading={busy === 'reload'} disabled={!!busy} onClick={() => void act('reload', () => run('fwd-reload'), t('fwd.reloaded'))}>{t('fwd.reloadBtn')}</Button>
        </Row>
        <Row label={t('fwd.persist')} desc={t('fwd.persistDesc')}>
          <Button size="sm" variant="secondary" icon="check" loading={busy === 'persist'} disabled={!!busy} onClick={() => void act('persist', () => run('fwd-persist'), t('fwd.persisted'))}>{t('fwd.persistBtn')}</Button>
        </Row>
      </Section>
    </>
  );
}
