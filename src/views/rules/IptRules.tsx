import { useState } from 'react';
import { errorText, run } from '../../api';
import { iptDelete } from '../../backends/translate';
import { afterChange, detect, ipt, reachable, useSshPort } from '../../data';
import { sshOpen } from '../../guard';
import { t } from '../../i18n';
import { Badge, Button, Segmented, Select, Skeleton, toast } from '../../kit';
import type { Rule } from '../../model';
import { openRuleDialog } from '../../nav';
import { ownerOfChain, type IptChain } from '../../parse/iptables';
import { iptFiles, useSettings } from '../../settings';
import { ErrorState, fmtCount, Hint, Section } from '../../ui/parts';
import { RuleTable } from './shared';

const TABLES = ['filter', 'nat', 'mangle', 'raw'];
const BUILTIN = ['INPUT', 'FORWARD', 'OUTPUT', 'PREROUTING', 'POSTROUTING'];

export function IptRules() {
  const [v6, setV6] = useState(false);
  const [table, setTable] = useState('filter');
  const bin = v6 ? 'ip6tables' : 'iptables';
  const { data, error, loading } = ipt(`${bin} ${table}`).use();
  const d = detect.use();
  const [settings] = useSettings();
  const sshPort = useSshPort();
  const [busy, setBusy] = useState('');
  const [showManaged, setShowManaged] = useState(false);

  const act = async (key: string, fn: () => Promise<unknown>, ok: string) => {
    setBusy(key);
    try {
      await fn();
      const saved = await afterChange('iptables', { v6 });
      await ipt(`${bin} ${table}`).refresh();
      toast.ok(ok, saved.length ? t('rule.savedTo', { files: saved.join(', ') }) : undefined);
    } catch (e) {
      toast.err(t('err.action'), errorText(e));
    } finally {
      setBusy('');
    }
  };
  const setPolicy = (c: IptChain, policy: string) => {
    if (policy === 'DROP' && c.name === 'INPUT' && settings.sshGuard && !sshOpen(inbound, sshPort)) {
      toast.err(t('guard.policyBlocked', { port: sshPort }), t('guard.addSshFirst'));
      return;
    }
    void act(`pol-${c.name}`, () => run('ipt-policy', [bin, c.name, policy]), t('ipt.policySet'));
  };
  const del = async (rules: Rule[]) => {
    // Highest number first in each chain: deleting renumbers the rules below.
    for (const r of [...rules].sort((a, b) => Number(b.ref!.num) - Number(a.ref!.num))) await run(iptDelete(r).command, iptDelete(r).args);
    await afterChange('iptables', { v6 });
    await ipt(`${bin} ${table}`).refresh();
  };
  const [f4, f6] = iptFiles(settings);
  const inbound = data ? reachable(data, ['INPUT']) : [];

  return (
    <>
      <div className="fw-toolbar fw-toolbar--top">
        <Segmented aria-label={t('ipt.family')} value={v6 ? '6' : '4'} onChange={(v) => setV6(v === '6')} options={[{ value: '4', label: 'IPv4' }, { value: '6', label: 'IPv6' }]} />
        <Select compact aria-label={t('ipt.table')} value={table} onChange={setTable} options={TABLES.map((x) => ({ value: x, label: x }))} />
        <span className="fw-grow" />
        {!settings.iptSave && <Button size="sm" variant="secondary" icon="download" loading={busy === 'save'} onClick={() => void act('save', () => run('ipt-save', [v6 ? f6 : f4]), t('ipt.saved', { file: v6 ? f6 : f4 }))}>{t('ipt.saveTo', { file: v6 ? f6 : f4 })}</Button>}
        <Button size="sm" variant="ghost" icon="refresh" onClick={() => void ipt(`${bin} ${table}`).refresh()}>{t('common.refresh')}</Button>
      </div>
      {d.data?.iptablesMode === 'nf_tables' && <Hint icon="info">{t('ipt.nftNote')}</Hint>}
      {!settings.iptSave && <Hint tone="warn" icon="alert">{t('ipt.notSaved')}</Hint>}
      {!data && loading && <Skeleton height={260} style={{ borderRadius: 18 }} />}
      {!data && !loading && error ? <ErrorState error={error} onRetry={() => void ipt(`${bin} ${table}`).refresh()} /> : null}
      {data && !showManaged && data.some((c) => ownerOfChain(c.name)) && (
        <Hint icon="info" action={<Button size="sm" variant="secondary" onClick={() => setShowManaged(true)}>{t('ipt.showManaged')}</Button>}>
          {t('ipt.managedHidden', { n: data.filter((c) => ownerOfChain(c.name)).length, by: [...new Set(data.map((c) => ownerOfChain(c.name)).filter(Boolean))].join(', ') })}
        </Hint>
      )}
      {data?.filter((c) => showManaged || !ownerOfChain(c.name)).map((c) => (
        <Section key={c.name} icon="list" title={<><span className="fw-mono">{c.name}</span>{c.references !== undefined && <Badge>{t('ipt.refs', { n: c.references })}</Badge>}{c.rules[0]?.managedBy && <Badge tone="info">{c.rules[0].managedBy}</Badge>}</>}
          action={<>
            {c.policy && table === 'filter' && BUILTIN.includes(c.name) && (
              <Select compact aria-label={t('ipt.policy')} value={c.policy} disabled={!!busy} onChange={(v) => setPolicy(c, v)}
                options={[{ value: 'ACCEPT', label: t('ipt.policyAccept') }, { value: 'DROP', label: t('ipt.policyDrop') }]} />
            )}
            {c.policy && <span className="fw-muted">{t('ipt.policyHits', { n: fmtCount(c.packets) })}</span>}
            {table === 'filter' && <Button size="sm" variant="ghost" icon="plus" onClick={() => openRuleDialog({ chain: c.name, v6, direction: c.name === 'OUTPUT' ? 'out' : 'in' })}>{t('rule.new')}</Button>}
          </>}>
          <RuleTable rules={c.rules} inbound={inbound} onDelete={del} counters empty={<p className="fw-empty">{t('ipt.noRules')}</p>} />
        </Section>
      ))}
    </>
  );
}
