import { useBackend } from '../data';
import { t } from '../i18n';
import { Button, EmptyState, Skeleton } from '../kit';
import { go, openRuleDialog } from '../nav';
import { ErrorState, PageHeader } from '../ui/parts';
import { FirewalldRules } from './rules/FirewalldRules';
import { IptRules } from './rules/IptRules';
import { NftRules } from './rules/NftRules';
import { UfwRules } from './rules/UfwRules';

export function RulesPage() {
  const { backend, loading, error } = useBackend();
  return (
    <>
      <PageHeader icon="list" title={t('nav.rules')} subtitle={backend ? t('rules.sub', { name: t(`backend.${backend}`) }) : undefined}
        actions={backend && <>
          <Button variant="ghost" icon="cog" onClick={() => go('settings')}>{t('rules.switch')}</Button>
          <Button variant="primary" icon="plus" onClick={() => openRuleDialog()}>{t('rule.new')}</Button>
        </>} />
      {loading ? <Skeleton height={260} style={{ borderRadius: 18 }} />
        : error ? <ErrorState error={error} />
        : !backend ? <EmptyState icon="shield" title={t('rules.noneInstalled')} text={t('rules.noneInstalledText')} />
        : backend === 'ufw' ? <UfwRules />
        : backend === 'firewalld' ? <FirewalldRules />
        : backend === 'nftables' ? <NftRules />
        : <IptRules />}
    </>
  );
}
