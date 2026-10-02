import { useState } from 'react';
import { errorText, run } from '../../api';
import { nftDelete } from '../../backends/translate';
import { afterChange, inboundRules, nft, useSshPort } from '../../data';
import { sshOpen } from '../../guard';
import { t } from '../../i18n';
import { Badge, Button, Dialog, DropdownMenu, EmptyState, IconButton, Input, Select, Skeleton, toast } from '../../kit';
import type { Rule } from '../../model';
import { openRuleDialog } from '../../nav';
import type { NftChain, NftTable } from '../../parse/nftables';
import { useSettings } from '../../settings';
import { ErrorState, Hint, Section } from '../../ui/parts';
import { RuleTable, TypedConfirm } from './shared';

const FAMILIES = ['inet', 'ip', 'ip6', 'bridge', 'netdev', 'arp'];
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;

export function NftRules() {
  const { data, error, loading } = nft.use();
  const [settings] = useSettings();
  const sshPort = useSshPort();
  const [busy, setBusy] = useState('');
  const [newTable, setNewTable] = useState(false);
  const [newChain, setNewChain] = useState<NftTable | null>(null);
  const [dropTable, setDropTable] = useState<NftTable | null>(null);
  // Tables another tool writes are long (ufw makes dozens of chains): closed until asked for.
  const [opened, setOpened] = useState<Set<string>>(new Set());

  if (!data && loading) return <Skeleton height={260} style={{ borderRadius: 18 }} />;
  if (!data) return <ErrorState error={error} onRetry={() => void nft.refresh()} />;

  const act = async (key: string, fn: () => Promise<unknown>, ok: string) => {
    setBusy(key);
    try {
      await fn();
      const saved = await afterChange('nftables');
      toast.ok(ok, saved.length ? t('rule.savedTo', { files: saved.join(', ') }) : undefined);
    } catch (e) {
      toast.err(t('err.action'), errorText(e));
    } finally {
      setBusy('');
    }
  };
  const inbound = inboundRules('nftables') ?? [];
  const setPolicy = (c: NftChain, policy: string) => {
    if (policy === 'drop' && c.hook === 'input' && settings.sshGuard && !sshOpen(c.rules, sshPort)) {
      toast.err(t('guard.policyBlocked', { port: sshPort }), t('guard.addSshFirst'));
      return;
    }
    void act(`pol-${c.table}-${c.name}`, () => run('nft-policy', [c.family, c.table, c.name, policy]), t('nft.policySet'));
  };
  const del = async (rules: Rule[]) => {
    for (const r of rules) await run(nftDelete(r).command, nftDelete(r).args);
    await afterChange('nftables');
  };

  return (
    <>
      <div className="fw-toolbar fw-toolbar--top">
        <Button size="sm" variant="secondary" icon="plus" onClick={() => setNewTable(true)}>{t('nft.newTable')}</Button>
        {!settings.nftSave && <Button size="sm" variant="secondary" icon="download" loading={busy === 'save'} onClick={() => void act('save', () => run('nft-save', [settings.nftFile]), t('nft.saved', { file: settings.nftFile }))}>{t('nft.saveTo', { file: settings.nftFile })}</Button>}
        <Button size="sm" variant="ghost" icon="refresh" onClick={() => void nft.refresh()}>{t('common.refresh')}</Button>
      </div>
      {settings.nftSave && <Hint icon="info">{t('nft.autoSave', { file: settings.nftFile })}</Hint>}
      {!data.length && <EmptyState icon="list" title={t('nft.empty')} text={t('nft.emptyText')} action={<Button variant="primary" icon="plus" onClick={() => setNewTable(true)}>{t('nft.newTable')}</Button>} />}
      {data.map((tb) => (
        <Section key={`${tb.family}-${tb.name}`} icon="list" title={<><span className="fw-mono">{tb.family} {tb.name}</span>{tb.managedBy && <Badge tone="info">{t('nft.managedBy', { by: tb.managedBy })}</Badge>}</>}
          action={<DropdownMenu aria-label={t('common.more')} trigger={(p) => <IconButton icon="more" size="sm" variant="ghost" label={t('common.more')} {...p} />} items={[
            { id: 'chain', label: t('nft.newChain'), icon: 'plus', onSelect: () => setNewChain(tb) },
            { id: 'flush', label: t('nft.flushTable'), icon: 'broom', danger: true, onSelect: () => void act('flush', () => run('nft-table', ['flush', tb.family, tb.name]), t('nft.flushed')) },
            { id: 'del', label: t('nft.deleteTable'), icon: 'trash', danger: true, onSelect: () => setDropTable(tb) },
          ]} />}>
          {tb.managedBy && <Hint tone="warn" icon="alert" action={!opened.has(`${tb.family} ${tb.name}`) ? <Button size="sm" variant="secondary" onClick={() => setOpened((o) => new Set(o).add(`${tb.family} ${tb.name}`))}>{t('nft.showChains', { n: tb.chains.length, rules: tb.chains.reduce((n, c) => n + c.rules.length, 0) })}</Button> : undefined}>{t('nft.managedWarn', { by: tb.managedBy })}</Hint>}
          {tb.objects.length > 0 && <p className="fw-sec-note">{t('nft.objects', { list: tb.objects.join(', ') })}</p>}
          {(!tb.managedBy || opened.has(`${tb.family} ${tb.name}`)) && tb.chains.map((c) => (
            <div key={c.name} className="fw-chain">
              <div className="fw-chain-h">
                <b className="fw-mono">{c.name}</b>
                {c.hook ? <Badge tone="info">{c.type} {c.hook} {c.priority}</Badge> : <Badge>{t('nft.regular')}</Badge>}
                {c.policy && (
                  <Select compact aria-label={t('nft.policy')} value={c.policy} disabled={!!busy} onChange={(v) => setPolicy(c, v)}
                    options={[{ value: 'accept', label: t('nft.policyAccept') }, { value: 'drop', label: t('nft.policyDrop') }]} />
                )}
                <span className="fw-grow" />
                <Button size="sm" variant="ghost" icon="plus" onClick={() => openRuleDialog({ chain: `${c.family} ${c.table} ${c.name}` })}>{t('rule.new')}</Button>
                <IconButton icon="trash" size="sm" variant="ghost" label={t('nft.deleteChain')} disabled={!!busy || c.rules.length > 0}
                  onClick={() => void act('dchain', () => run('nft-chain', ['delete', c.family, c.table, c.name]), t('nft.chainDeleted'))} />
              </div>
              <RuleTable rules={c.rules} inbound={inbound} onDelete={del} counters raw empty={<p className="fw-empty">{t('nft.noRules')}</p>} />
            </div>
          ))}
        </Section>
      ))}

      {newTable && <NewTableDialog onClose={() => setNewTable(false)} onCreate={(f, n) => act('table', () => run('nft-table', ['add', f, n]), t('nft.tableCreated'))} />}
      {newChain && <NewChainDialog table={newChain} onClose={() => setNewChain(null)} onCreate={(args) => act('chain', () => (args.length === 3 ? run('nft-chain', ['add', ...args]) : run('nft-base-chain', args)), t('nft.chainCreated'))} />}
      <TypedConfirm open={!!dropTable} word={dropTable?.name ?? ''} title={t('nft.deleteTableTitle', { name: dropTable?.name ?? '' })} description={t('nft.deleteTableText')} label={t('nft.deleteTable')}
        onClose={() => setDropTable(null)} onConfirm={() => act('dtable', () => run('nft-table', ['delete', dropTable!.family, dropTable!.name]), t('nft.tableDeleted'))} />
    </>
  );
}

function NewTableDialog({ onClose, onCreate }: { onClose(): void; onCreate(family: string, name: string): Promise<void> }) {
  const [family, setFamily] = useState('inet');
  const [name, setName] = useState('');
  const ok = NAME_RE.test(name);
  return (
    <Dialog open onClose={onClose} title={t('nft.newTable')} icon="plus" onSubmit={(e) => { e.preventDefault(); if (ok) void onCreate(family, name).then(onClose); }}
      footer={<><Button variant="ghost" type="button" onClick={onClose}>{t('common.cancel')}</Button><Button variant="primary" type="submit" disabled={!ok}>{t('common.create')}</Button></>}>
      <div className="fw-form">
        <Select label={t('nft.family')} hint={t('nft.familyHint')} value={family} onChange={setFamily} options={FAMILIES.map((f) => ({ value: f, label: f }))} />
        <Input label={t('nft.tableName')} mono value={name} onChange={(e) => setName(e.target.value.trim())} error={name && !ok ? t('nft.badName') : undefined} />
      </div>
    </Dialog>
  );
}

function NewChainDialog({ table, onClose, onCreate }: { table: NftTable; onClose(): void; onCreate(args: string[]): Promise<void> }) {
  const [name, setName] = useState('');
  const [base, setBase] = useState(true);
  const [hook, setHook] = useState('input');
  const [type, setType] = useState('filter');
  const [priority, setPriority] = useState('filter');
  const [policy, setPolicy] = useState('accept');
  const [settings] = useSettings();
  const closes = base && hook === 'input' && policy === 'drop';
  const ok = !(closes && settings.sshGuard) && NAME_RE.test(name) && (!base || /^(-?\d{1,4}|raw|mangle|dstnat|filter|security|srcnat)$/.test(priority));
  const args = base ? [table.family, table.name, name, type, hook, priority, policy] : [table.family, table.name, name];
  return (
    <Dialog open onClose={onClose} title={t('nft.newChainIn', { table: `${table.family} ${table.name}` })} icon="plus" onSubmit={(e) => { e.preventDefault(); if (ok) void onCreate(args).then(onClose); }}
      footer={<><Button variant="ghost" type="button" onClick={onClose}>{t('common.cancel')}</Button><Button variant="primary" type="submit" disabled={!ok}>{t('common.create')}</Button></>}>
      <div className="fw-form">
        <Input label={t('nft.chainName')} mono value={name} onChange={(e) => setName(e.target.value.trim())} error={name && !NAME_RE.test(name) ? t('nft.badName') : undefined} />
        <Select label={t('nft.chainKind')} value={base ? 'base' : 'regular'} onChange={(v) => setBase(v === 'base')} options={[{ value: 'base', label: t('nft.base') }, { value: 'regular', label: t('nft.regularLong') }]} />
        {base && (
          <>
            <div className="fw-form-2">
              <Select label={t('nft.hook')} value={hook} onChange={setHook} options={['prerouting', 'input', 'forward', 'output', 'postrouting', 'ingress'].map((h) => ({ value: h, label: h }))} />
              <Select label={t('nft.type')} value={type} onChange={setType} options={['filter', 'nat', 'route'].map((h) => ({ value: h, label: h }))} />
            </div>
            <div className="fw-form-2">
              <Input label={t('nft.priority')} mono value={priority} onChange={(e) => setPriority(e.target.value.trim())} hint={t('nft.priorityHint')} />
              <Select label={t('nft.policy')} value={policy} onChange={setPolicy} options={[{ value: 'accept', label: t('nft.policyAccept') }, { value: 'drop', label: t('nft.policyDrop') }]} />
            </div>
            {closes && <Hint tone={settings.sshGuard ? 'err' : 'warn'} icon="alert">{settings.sshGuard ? t('nft.dropBlocked') : t('nft.dropWarn')}</Hint>}
          </>
        )}
      </div>
    </Dialog>
  );
}
