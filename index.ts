import { Type } from '@earendil-works/pi-ai';
import { createBashTool, getAgentDir, type ExtensionAPI } from '@earendil-works/pi-coding-agent';
import { getPermissionsService } from '@gotgenes/pi-permission-system';
import { registerSandbox } from './src/extension.mjs';
import { packageExtensionEntries } from './src/child-extensions.mjs';
import { fileURLToPath } from 'node:url';

export default async function scopeSandbox(pi: ExtensionAPI) {
  let childSupport;
  try {
    const { registerRequiredChildExtensions } = await import('pi-subagents/required-child-extensions');
    const permissionEntries = packageExtensionEntries('@gotgenes/pi-permission-system', import.meta.resolve('@gotgenes/pi-permission-system'));
    childSupport = {
      register: registerRequiredChildExtensions,
      extensions: [
        { id: 'pi-scope-sandbox', path: fileURLToPath(import.meta.url) },
        ...permissionEntries.map((path, index) => ({ id: `scope-permissions-${index}`, path })),
      ],
    };
  } catch {
    // Ordinary Bash remains usable; unprotected subagent launches are blocked.
  }
  registerSandbox(pi, { Type, createBashTool, getAgentDir, getPermissionsService, childSupport });
}
