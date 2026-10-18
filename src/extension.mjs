import { homedir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkWriteRoot, directory, GRANT_TOOL, loadConfig, PACKAGE_NAME } from './config.mjs';
import { runSandbox } from './sandbox.mjs';

const sourceDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const text = (value, details = {}) => ({ content: [{ type: 'text', text: value }], details });

// Dependencies are injected to test the adapter without credentials or model calls.
export function registerSandbox(pi, { Type, createBashTool, getAgentDir, getPermissionsService, childSupport, run = runSandbox, readConfig = loadConfig }) {
  const sessions = new Map();
  function state(ctx) {
    const id = ctx.sessionManager.getSessionId();
    const entry = sessions.get(id);
    if (!entry || entry.cwd !== directory(ctx.cwd)) throw new Error('Sandbox has not initialized for this session/workspace');
    if (entry.error) throw new Error(`Sandbox configuration unavailable: ${entry.error}`);
    if (!getPermissionsService(id)) throw new Error('pi-permission-system is required in this session; refusing execution');
    return entry;
  }

  pi.on('session_start', (_event, ctx) => {
    const id = ctx.sessionManager.getSessionId();
    try {
      sessions.get(id)?.children?.dispose();
      const config = readConfig(getAgentDir(), homedir(), sourceDir);
      const entry = { cwd: directory(ctx.cwd), config };
      if (childSupport) {
        try {
          entry.children = childSupport.register({
            sessionId: id,
            extensions: [...childSupport.extensions, ...config.childExtensions.map((path, index) => ({ id: `scope-operator-${index}`, path }))],
            requireForAllRunners: true,
          });
        } catch (error) { entry.childError = error.message; }
      }
      sessions.set(id, entry);
      ctx.ui.setStatus(PACKAGE_NAME, 'scope sandbox: Linux, fail-closed');
    } catch (error) {
      sessions.set(id, { cwd: directory(ctx.cwd), error: error.message });
      ctx.ui.setStatus(PACKAGE_NAME, 'scope sandbox: BLOCKED (configuration)');
    }
  });
  pi.on('session_shutdown', (_event, ctx) => {
    const id = ctx.sessionManager.getSessionId();
    sessions.get(id)?.children?.dispose();
    sessions.delete(id);
  });
  pi.on('tool_call', (event, ctx) => {
    if (event.toolName !== 'subagent') return;
    try {
      const entry = state(ctx);
      if (!entry.children) return { block: true, reason: 'Protected pi-subagents requires the public required-child-extensions API and successful scope-sandbox registration. ' + (entry.childError ?? '') };
    } catch (error) { return { block: true, reason: error.message }; }
  });

  pi.registerTool({
    name: GRANT_TOOL,
    label: 'Authorize sandbox scope for one Bash call',
    exposure: 'codemode',
    description: 'Request exactly one sandbox scope exception for the specified command. This does not run a command or grant future calls. A path grants write access to that directory; network=true enables all host networking for that call. Authorization belongs to pi-permission-system.',
    parameters: Type.Object({
      command: Type.String(),
      path: Type.Optional(Type.String({ description: 'Existing absolute directory to make writable for this command' })),
      network: Type.Boolean(),
    }),
    async execute(_id, params, signal, _onUpdate, ctx) {
      const { config, cwd } = state(ctx);
      if (signal?.aborted) throw new Error('Scope request aborted');
      if (!params.path && params.network !== true) throw new Error('No additional scope requested');
      const path = params.path ? checkWriteRoot(params.path, config) : undefined;
      return text('Scope request passed permission gates; no command was executed.', {
        command: params.command, cwd, path, network: params.network === true,
      });
    },
  });

  const base = createBashTool(process.cwd());
  pi.registerTool({
    ...base,
    name: 'bash',
    label: 'Bash (scope sandbox)',
    reachesTools: input => input.writeRoot || input.network ? [GRANT_TOOL] : [],
    description: base.description + '\nRuns in a fail-closed Linux sandbox. No network by default; only the workspace and private temporary storage are writable. Optional writeRoot/network requests pass through a nested permission-gated tool before execution. There is no unsandboxed fallback.',
    parameters: Type.Object({
      ...base.parameters.properties,
      writeRoot: Type.Optional(Type.String({ description: 'Request one additional existing absolute writable directory for this call' })),
      network: Type.Optional(Type.Boolean({ description: 'Request full host networking for this call, subject to permission approval' })),
    }),
    async execute(id, params, signal, onUpdate, ctx) {
      const { config, cwd } = state(ctx);
      const command = params.command;
      if (typeof command !== 'string' || !command.trim() || command.length > 16384 || command.includes('\0')) throw new Error('Invalid or oversized sandbox command');
      if (signal?.aborted) throw new Error('Sandbox command aborted');
      const path = params.writeRoot === undefined ? undefined : checkWriteRoot(params.writeRoot, config);
      const network = params.network === true && !config.network;
      if (path || network) {
        if (typeof ctx.executeTool !== 'function') throw new Error('Pi nested tool execution is required for scope requests');
        // executeTool applies the actual permission gates and authorizer chain.
        // A policy query returning `ask` is not an approval, nor is a bus event.
        const result = await ctx.executeTool(GRANT_TOOL, { command, ...(path ? { path } : {}), network }, { signal });
        const approved = result?.result?.details;
        if (result?.isError || !approved || approved.command !== command || approved.cwd !== cwd || approved.path !== path || approved.network !== network) {
          throw new Error('Sandbox scope was not approved for this exact command');
        }
        if (path && checkWriteRoot(params.writeRoot, config) !== path) throw new Error('Requested write scope changed during authorization');
        if (signal?.aborted) throw new Error('Sandbox command aborted');
      }
      const bash = createBashTool(cwd, {
        operations: { exec: (cmd, actualCwd, options) => {
          if (cmd !== command || directory(actualCwd) !== cwd) throw new Error('Sandbox execution identity changed');
          return run(config, cwd, cmd, { path, network }, options);
        } },
      });
      return bash.execute(id, { command, ...(params.timeout !== undefined ? { timeout: params.timeout } : {}) }, signal, onUpdate, ctx);
    },
  });

  // User-shell commands bypass normal tool_call authorization. Do not silently
  // route !/!! around the contextual permission gates.
  pi.on('user_bash', () => ({ result: { output: 'pi-scope-sandbox: !/!! is disabled; ask the agent to use the permission-gated Bash tool, or use your own terminal.', exitCode: 1, cancelled: false, truncated: false } }));
  pi.registerCommand('scope-sandbox', {
    description: 'Show this session\'s sandbox policy (does not change permissions)',
    handler: async (_args, ctx) => {
      const { config, cwd } = state(ctx);
      ctx.ui.notify(JSON.stringify({ cwd, mode: config.mode, network: config.network, writeRoots: config.writeRoots, denyRead: config.denyRead }, null, 2), 'info');
    },
  });
}
