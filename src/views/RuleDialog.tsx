/**
 * "New rule" for every firewall. The form is the same RuleSpec everywhere; the backend decides which fields apply and
 * translates it (backends/translate.ts). The exact commands are shown before they run.
 */
import { useMemo, useState } from 'react';
import manifest from '../../plugin/manifest.json';
import { errorText, resource, runAll } from '../api';
import { fwdCalls, fwdOps, iptAdd, nftAdd, preview, SpecError, ufwAdd, type Call } from '../backends/translate';
import { afterChange, firewalld, ipt, nft, ufwApps, useBackend, useSshPort } from '../data';
import { specClosesSsh } from '../guard';
import { t } from '../i18n';
import { Button, Checkbox, Dialog, Input, Segmented, Select, toast } from '../kit';
import type { BackendId, RuleSpec } from '../model';
import type { FirewalldInfo } from '../parse/firewalld';
import type { IptChain } from '../parse/iptables';
import type { NftTable } from '../parse/nftables';
import { closeRuleDialog } from '../nav';
import type { Settings } from '../settings';
import { Hint } from '../ui/parts';

const ARGV: Record<string, string[]> = Object.fromEntries(manifest.capabilities.commands.map((c) => [c.name, c.argv]));

/** Stands in for the resources a backend does not need, so the hooks keep their order. */
const noneRes = resource(async () => undefined as unknown);

const BLANK: RuleSpec = { action: 'allow', direction: 'in', proto: 'tcp', port: '', source: '', dest: '', iface: '', comment: '', first: false };

export function RuleDialog({ prefill }: { prefill: Partial<RuleSpec> }) {
  const { backend, settings } = useBackend();
  if (!backend) return null;
  return <Form backend={backend} settings={settings} prefill={prefill} />;
}

function Form({ backend, settings, prefill }: { backend: BackendId; settings: Settings; prefill: Partial<RuleSpec> }) {
  const sshPort = useSshPort();
  const [s, setS] = useState<RuleSpec>({ ...BLANK, ...prefill });
  const [target, setTarget] = useState<'port' | 'app'>(prefill.app ? 'app' : 'port');
  const [busy, setBusy] = useState(false);
  const set = <K extends keyof RuleSpec>(k: K, v: RuleSpec[K]) => setS((x) => ({ ...x, [k]: v }));

  // Context each backend needs
  const apps = (backend === 'ufw' ? ufwApps : noneRes).use();
  const fwd = (backend === 'firewalld' ? firewalld('runtime') : noneRes).use();
  const nftData = (backend === 'nftables' ? nft : noneRes).use();
  const ipt4 = (backend === 'iptables' ? ipt(s.v6 ? 'ip6tables filter' : 'iptables filter') : noneRes).use();

  const fwInfo = backend === 'firewalld' ? (fwd.data as FirewalldInfo | undefined) : undefined;
  const zones = fwInfo?.zones ?? [];
  const zone = s.zone || fwInfo?.defaultZone || zones[0]?.name || '';
  const nftChains = useMemo(() => {
    const tables = (nftData.data as NftTable[] | undefined) ?? [];
    return tables.flatMap((tb) => tb.chains.map((c) => ({ value: `${c.family} ${c.table} ${c.name}`, label: `${c.family} ${c.table} ${c.name}${c.hook ? ` (${c.hook})` : ''}${tb.managedBy ? `, ${tb.managedBy}` : ''}`, hook: c.hook, managed: !!tb.managedBy })));
  }, [nftData.data]);
  // Chains of tables another tool writes stay out of the list unless the rule was opened on one of them.
  const nftOptions = nftChains.filter((c) => !c.managed || c.value === s.chain);
  const nftChain = s.chain || nftChains.find((c) => c.hook === 'input' && !c.managed)?.value || nftChains.find((c) => !c.managed)?.value || '';
  const iptChains = ((ipt4.data as IptChain[] | undefined) ?? []).filter((c) => !c.name.startsWith('ufw') && !c.name.startsWith('DOCKER'));
  const iptChain = s.chain || (s.direction === 'out' ? 'OUTPUT' : 'INPUT');
  const iptCount = iptChains.find((c) => c.name === iptChain)?.rules.length ?? 0;

  const spec: RuleSpec = {
    ...s,
    app: target === 'app' ? s.app : undefined,
    port: target === 'app' ? '' : s.port,
    zone,
    chain: backend === 'nftables' ? nftChain : backend === 'iptables' ? iptChain : undefined,
    direction: backend === 'nftables' ? (nftChains.find((c) => c.value === nftChain)?.hook === 'output' ? 'out' : 'in') : backend === 'iptables' ? (iptChain === 'OUTPUT' ? 'out' : 'in') : s.direction,
  };

  let calls: Call[] = [];
  let problem = '';
  try {
    if (target === 'app' && !spec.app) problem = t('spec.pickApp');
    else if (backend === 'ufw') calls = ufwAdd(spec, settings.defaultComment);
    else if (backend === 'firewalld') calls = zone ? fwdCalls(zone, fwdOps(spec), settings.firewalldMode) : [];
    else if (backend === 'nftables') calls = nftAdd(spec);
    else calls = iptAdd(spec, iptCount, settings.defaultComment);
  } catch (e) {
    problem = e instanceof SpecError ? t(e.key) : errorText(e);
  }
  const closesSsh = specClosesSsh(spec, sshPort);
  const blocked = closesSsh && settings.sshGuard;

  const submit = async () => {
    if (!calls.length || blocked) return;
    setBusy(true);
    try {
      await runAll(calls);
      const saved = await afterChange(backend, { v6: !!spec.v6 });
      toast.ok(t('rule.added'), saved.length ? t('rule.savedTo', { files: saved.join(', ') }) : undefined);
      closeRuleDialog();
    } catch (e) {
      toast.err(t('rule.addFail'), errorText(e));
      setBusy(false);
    }
  };

  const actions: RuleSpec['action'][] = backend === 'ufw' || backend === 'firewalld' ? ['allow', 'deny', 'reject', 'limit'] : ['allow', 'deny', 'reject'];
  const hasApps = backend === 'ufw' || backend === 'firewalld';
  const appOptions = backend === 'ufw' ? ((apps.data as string[] | undefined) ?? []) : (fwInfo?.services ?? []);

  return (
    <Dialog open onClose={closeRuleDialog} title={t('rule.title', { name: t(`backend.${backend}`) })} icon="plus" size="lg"
      onSubmit={(e) => { e.preventDefault(); void submit(); }}
      footer={<>
        <Button variant="ghost" type="button" onClick={closeRuleDialog}>{t('common.cancel')}</Button>
        <Button variant="primary" type="submit" icon="plus" loading={busy} disabled={busy || !calls.length || blocked || !!problem}>{t('rule.add')}</Button>
      </>}>
      <div className="fw-form">
        <div className="fw-form-row">
          <span className="fw-form-l">{t('rule.action')}</span>
          <Segmented aria-label={t('rule.action')} value={s.action} onChange={(v) => set('action', v as RuleSpec['action'])} options={actions.map((a) => ({ value: a, label: t(`action.${a}`) }))} />
        </div>
        {s.action === 'limit' && <p className="fw-form-note">{t('rule.limitNote')}</p>}

        {backend === 'ufw' && (
          <div className="fw-form-row">
            <span className="fw-form-l">{t('rule.direction')}</span>
            <Segmented aria-label={t('rule.direction')} value={s.direction} onChange={(v) => set('direction', v as RuleSpec['direction'])} options={[{ value: 'in', label: t('dir.in') }, { value: 'out', label: t('dir.out') }]} />
          </div>
        )}
        {backend === 'firewalld' && (
          <Select label={t('rule.zone')} value={zone} onChange={(v) => set('zone', v)} options={zones.map((z) => ({ value: z.name, label: `${z.name}${z.isDefault ? ` (${t('fwd.default')})` : ''}${z.active ? '' : `, ${t('fwd.inactiveZone')}`}` }))} />
        )}
        {backend === 'nftables' && (
          <Select label={t('rule.chain')} value={nftChain} onChange={(v) => set('chain', v)} options={nftOptions.length ? nftOptions : [{ value: '', label: t('nft.noChains') }]} />
        )}
        {backend === 'iptables' && (
          <div className="fw-form-2">
            <Select label={t('rule.chain')} value={iptChain} onChange={(v) => set('chain', v)} options={(iptChains.length ? iptChains.map((c) => c.name) : ['INPUT', 'OUTPUT', 'FORWARD']).map((c) => ({ value: c, label: c }))} />
            <div className="fw-form-row fw-form-row--end"><Checkbox checked={!!s.v6} onChange={(v) => set('v6', v)} label={t('rule.ipv6')} /></div>
          </div>
        )}

        {hasApps && (
          <div className="fw-form-row">
            <span className="fw-form-l">{t('rule.what')}</span>
            <Segmented aria-label={t('rule.what')} value={target} onChange={(v) => setTarget(v as 'port' | 'app')} options={[{ value: 'port', label: t('rule.ports') }, { value: 'app', label: backend === 'ufw' ? t('rule.app') : t('rule.service') }]} />
          </div>
        )}
        {target === 'port' ? (
          <div className="fw-form-2">
            <Input label={t('rule.port')} mono value={s.port} placeholder="22, 80,443, 6000-6007" hint={t('rule.portHint')} onChange={(e) => set('port', e.target.value)} />
            <Select label={t('rule.proto')} value={s.proto} onChange={(v) => set('proto', v as RuleSpec['proto'])} options={[{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }, { value: 'any', label: t('rule.tcpudp') }]} />
          </div>
        ) : (
          <Select label={backend === 'ufw' ? t('rule.app') : t('rule.service')} value={s.app ?? ''} onChange={(v) => set('app', v)}
            options={[{ value: '', label: t('rule.pick') }, ...appOptions.map((a) => ({ value: a, label: a }))]} />
        )}

        <div className="fw-form-2">
          <Input label={t('rule.source')} mono value={s.source} placeholder={t('common.anywhere')} hint={t('rule.addrHint')} onChange={(e) => set('source', e.target.value.trim())} />
          <Input label={t('rule.dest')} mono value={s.dest} placeholder={t('common.anywhere')} onChange={(e) => set('dest', e.target.value.trim())} />
        </div>
        {(backend === 'ufw' || backend === 'nftables') && (
          <Input label={t('rule.iface')} mono value={s.iface} placeholder={t('rule.ifaceAny')} onChange={(e) => set('iface', e.target.value.trim())} />
        )}
        {backend !== 'firewalld' && (
          <Input label={t('rule.comment')} value={s.comment} maxLength={64} placeholder={backend === 'nftables' ? '' : settings.defaultComment} onChange={(e) => set('comment', e.target.value)} />
        )}
        {backend !== 'firewalld' && <Checkbox checked={s.first} onChange={(v) => set('first', v)} label={t('rule.first')} />}

        {problem && <Hint tone="warn" icon="alert">{problem}</Hint>}
        {!problem && spec.action === 'allow' && !spec.port && !spec.app && !spec.source && spec.direction === 'in' && <Hint tone="warn" icon="alert">{t('rule.allowAll')}</Hint>}
        {closesSsh && (blocked
          ? <Hint tone="err" icon="lock">{t('guard.specBlocked', { port: sshPort })}</Hint>
          : <Hint tone="warn" icon="alert">{t('guard.specWarn', { port: sshPort })}</Hint>)}
        {calls.length > 0 && (
          <div className="fw-preview">
            <span>{t('rule.preview', { n: calls.length })}</span>
            <pre>{calls.map((c) => `$ ${preview(c, ARGV)}`).join('\n')}</pre>
          </div>
        )}
      </div>
    </Dialog>
  );
}
