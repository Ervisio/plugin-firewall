/**
 * Entry of the Firewall plugin. Order matters: the SDK and React are stored first, because every component reads them
 * through getSdk() and the `react` shim.
 */
import { createElement } from 'react';
import { setReact } from '@ervisio/plugin-sdk/react';
import { setSdk, type PluginSDK } from './sdk';
import { registerAllStrings, t } from './i18n';
import { injectStyles } from './styles';
import { EmptyState } from './kit';
import { registerIcons } from './ui/parts';
import { App } from './views/App';
import { StatusWidget } from './views/StatusWidget';

function TooOld() {
  return createElement(EmptyState, { icon: 'alert', hue: 'svc', title: t('old.title'), text: t('old.text') });
}

export default function activate(sdk: PluginSDK): void {
  setSdk(sdk);
  setReact(sdk.react);
  registerAllStrings();
  injectStyles();
  registerIcons();
  const ok = sdk.version >= 3 && !!sdk.api.jobs;
  sdk.registerPage('firewall', ok ? App : TooOld);
  sdk.registerWidget({ id: 'status', render: ok ? StatusWidget : TooOld });
}
