import { useState } from 'react';
import { errorText, run } from '../../api';
import { ufwDelete } from '../../backends/translate';
import { afterChange, ufw, useSshPort } from '../../data';
import { sshOpen } from '../../guard';
import { t } from '../../i18n';
import { Button, Select, Skeleton, Switch, toast } from '../../kit';
import type { Rule } from '../../model';
import { openRuleDialog } from '../../nav';
import { parseAddedRule } from '../../parse/ufw';
import { useSettings } from '../../settings';
import { ErrorState, Hint, Row, Section } from '../../ui/parts';
import { RuleTable, TypedConfirm } from './shared';

const POLICIES = ['allow', 'deny', 'reject'];
const LEVELS = ['off', 'low', 'medium', 'high', 'full'];

export function UfwRules() {
  const { data, error, loading } = ufw.use();
  const [settings] = useSettings();
  const sshPort = useSshPort();
  const [askOff, setAskOff] = useState(false);
  const [busy, setBusy] = useState('');

  if (!data && loading) return <Skeleton height={260} style={{ borderRadius: 18 }} />;
  if (!data) return <ErrorState error={error} onRetry={() => void ufw.refresh()} />;

  const act = async (key: string, fn: () => Promise<unknown>, ok: string) => {
    setBusy(key);
    try {
      await fn();
      await afterChange('ufw');
      toast.ok(ok);
    } catch (e) {
      toast.err(t('err.action'), errorText(e));
    } finally {
      setBusy('');
    }
  };

  const added = data.added.map(parseAddedRule);
  const enable = () => {
    if (settings.sshGuard && !sshOpen(added, sshPort) && data.defaults.incoming !== 'allow') {
      toast.err(t('guard.enableBlocked', { port: sshPort }), t('guard.addSshFirst'));
      return;
    }
    void act('enable', () => run('ufw-enable'), t('ufw.enabled'));
  };
  const setDefault = (chain: 'incoming' | 'outgoing' | 'routed', policy: string) => {
    if (chain === 'incoming' && policy !== 'allow' && settings.sshGuard && !sshOpen(data.rules, sshPort) && data.active) {
      toast.err(t('guard.policyBlocked', { port: sshPort }), t('guard.addSshFirst'));
      return;
    }
    void act(`def-${chain}`, () => run('ufw-default', [policy, chain]), t('ufw.defaultSet'));
  };
  const del = async (rules: Rule[]) => {
    // Highest number first: deleting renumbers the rules below.
    for (const r of [...rules].sort((a, b) => Number(b.ref!.num) - Number(a.ref!.num))) await run(ufwDelete(r).command, ufwDelete(r).args);
    await afterChange('ufw');
  };

  return (
    <>
      <Section icon="power" title={t('ufw.state')}>
        <Row label={data.active ? t('ufw.on') : t('ufw.off')} desc={data.active ? t('ufw.onDesc') : t('ufw.offDesc')}>
          <Switch checked={data.active} disabled={!!busy} onChange={(on) => (on ? enable() : setAskOff(true))} aria-label={t('ufw.state')} />
        </Row>
        {(['incoming', 'outgoing', 'routed'] as const).map((c) => (
          <Row key={c} label={t(`ufw.def.${c}`)} desc={t(`ufw.def.${c}.desc`)}>
            <Select compact aria-label={t(`ufw.def.${c}`)} value={data.defaults[c] || 'deny'} disabled={!!busy || !data.defaults[c]} onChange={(v) => setDefault(c, v)}
              options={(c === 'routed' && data.defaults.routed === 'disabled' ? ['disabled', ...POLICIES] : POLICIES).map((p) => ({ value: p, label: t(`policy.${p}`) }))} />
          </Row>
        ))}
        <Row label={t('ufw.logging')} desc={t('ufw.loggingDesc')}>
          <Select compact aria-label={t('ufw.logging')} value={LEVELS.includes(data.logging) ? data.logging : 'low'} disabled={!!busy} onChange={(v) => void act('log', () => run('ufw-logging', [v]), t('ufw.loggingSet'))}
            options={LEVELS.map((l) => ({ value: l, label: t(`ufw.level.${l}`) }))} />
        </Row>
      </Section>

      <Section icon="list" title={t('rules.title')} action={<>
        <Button size="sm" variant="ghost" icon="refresh" onClick={() => void ufw.refresh()}>{t('common.refresh')}</Button>
        <Button size="sm" variant="primary" icon="plus" onClick={() => openRuleDialog()}>{t('rule.new')}</Button>
      </>}>
        {data.active ? (
          <RuleTable rules={data.rules} inbound={data.rules} onDelete={del} where />
        ) : (
          <>
            <Hint tone="warn" icon="alert">{t('ufw.inactiveRules')}</Hint>
            <RuleTable rules={added} inbound={added} />
          </>
        )}
      </Section>

      <TypedConfirm open={askOff} word="ufw" title={t('ufw.offTitle')} description={t('ufw.offText')} label={t('ufw.turnOff')} onClose={() => setAskOff(false)}
        onConfirm={() => act('disable', () => run('ufw-disable'), t('ufw.disabled'))} />
    </>
  );
}
