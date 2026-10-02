/**
 * The plugin SDK as this plugin uses it. The SDK exists only after activate() ran: call getSdk() inside functions and
 * components, never at import time.
 */
export type { AuditEntry, ExecResult, JobInstance, PluginError, PluginSDK } from '@ervisio/plugin-sdk';
export { getSdk, setSdk } from '@ervisio/plugin-sdk';
