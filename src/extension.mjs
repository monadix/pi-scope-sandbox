import { homedir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkWriteRoot, directory, GRANT_TOOL, HOST_GRANT_TOOL, loadConfig, normalizeScopes, PACKAGE_NAME, resourcePath, resourceType } from './config.mjs';
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
      const entry = { cwd: directory(ctx.cwd), config, hostDefault: false, modeEpoch: 0 };
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

  // A distinct host gate keeps full-user execution visible even if input previews truncate.
  for (const hostGate of [false, true]) pi.registerTool({
    name: hostGate ? HOST_GRANT_TOOL : GRANT_TOOL,
    label: hostGate ? 'Authorize UNSANDBOXED host execution for one Bash call' : 'Authorize sandbox scope for one Bash call',
    exposure: 'codemode',
    description: 'Request exactly one scope exception for the specified command. This does not run a command or grant future calls. Each scalar path identifies one exact read, write, writable-root or Unix-socket resource and also passes through permission path gates; scope binds the complete aggregate. network=true enables host networking. host=true instead requests UNSANDBOXED execution as the Pi user, with host filesystem, networking, Unix sockets and environment (including credentials) accessible. Host mode requires trusted allowHost=true. Authorization belongs to pi-permission-system.',
    parameters: Type.Object({
      command: Type.String(),
      path: Type.Optional(Type.String({ description: 'One canonical filesystem resource passed through path and external-directory gates' })),
      resourceKind: Type.Optional(Type.String()), resourceName: Type.Optional(Type.String()), resourceType: Type.Optional(Type.String()),
      scope: Type.Optional(Type.Object({ path: Type.Optional(Type.String()), network: Type.Boolean(), host: Type.Optional(Type.Boolean()), readPaths: Type.Array(Type.String()), writePaths: Type.Array(Type.String()), unixSockets: Type.Array(Type.String()), env: Type.Array(Type.String()), resourceTypes: Type.Array(Type.Object({ path: Type.String(), kind: Type.String(), type: Type.String() })) })),
      network: Type.Boolean(),
      host: Type.Optional(Type.Boolean({ description: 'UNSANDBOXED execution with the Pi user\'s host permissions and environment, including credentials' })),
    }),
    async execute(_id, params, signal, _onUpdate, ctx) {
      const { config, cwd } = state(ctx);
      if (signal?.aborted) throw new Error('Scope request aborted');
      const host = params.host === true;
      if (host !== hostGate) throw new Error('Host execution requires its dedicated scope_host_authorize gate');
      if (host && !config.allowHost) throw new Error('Host escalation is disabled by trusted global configuration');
      if (host && (params.path !== undefined || params.scope !== undefined)) throw new Error('Host escalation cannot be combined with narrower scopes');
      if (typeof params.command !== 'string' || !params.command.trim() || params.command.length > 16384 || params.command.includes('\0')) throw new Error('Invalid or oversized sandbox command');
      const resourceKind = params.resourceKind ?? 'writeRoot';
      if (!['writeRoot', 'read', 'write', 'socket', 'network', 'env', 'host'].includes(resourceKind)) throw new Error('Invalid scope resource kind');
      const path = params.path === undefined ? undefined : resourceKind === 'writeRoot' ? checkWriteRoot(params.path, config) : resourcePath(params.path, config, resourceKind === 'read' ? 'read' : resourceKind === 'write' ? 'write' : 'socket');
      const actualType = path ? resourceKind === 'writeRoot' ? 'directory' : resourceType(path) : undefined;
      if (params.resourceType !== undefined && params.resourceType !== actualType) throw new Error('Scoped resource type changed or did not match');
      const scope = params.scope;
      if (!host && !path && !params.resourceName && params.network !== true) throw new Error('No additional scope requested');
      return text('Scope request passed permission gates; no command was executed.', {
        command: params.command, cwd, path, resourceKind: params.resourceKind, resourceName: params.resourceName, resourceType: params.resourceType, scope,
        network: host || params.network === true, ...(host ? { host: true } : {}),
      });
    },
  });

  const base = createBashTool(process.cwd());
  pi.registerTool({
    ...base,
    name: 'bash',
    label: 'Bash (scope sandbox)',
    reachesTools: input => input.host ? [HOST_GRANT_TOOL] : input.writeRoot || input.network || input.readPaths?.length || input.writePaths?.length || input.unixSockets?.length || input.env?.length ? [GRANT_TOOL] : [],
    description: base.description + '\nRuns in a fail-closed Linux sandbox by default. Optional writeRoot/network/readPaths/writePaths/unixSockets/env requests pass through nested permission gates. With trusted allowHost=true, host=true requests UNSANDBOXED execution as the Pi user, exposing host filesystem, network, Unix sockets and environment (including credentials) for this exact call. Do not combine host with narrower scopes. Every host call requires its own nested permission gate. There is no automatic unsandboxed fallback.',
    parameters: Type.Object({
      ...base.parameters.properties,
      writeRoot: Type.Optional(Type.String({ description: 'Request one additional existing absolute writable directory for this call' })),
      network: Type.Optional(Type.Boolean({ description: 'Request full host networking for this call, subject to permission approval' })),
      readPaths: Type.Optional(Type.Array(Type.String({ description: 'Existing file or directory to expose read-only for this call' }))),
      writePaths: Type.Optional(Type.Array(Type.String({ description: 'Existing file or directory to expose writable for this call' }))),
      unixSockets: Type.Optional(Type.Array(Type.String({ description: 'Existing AF_UNIX socket node to expose for this call' }))),
      env: Type.Optional(Type.Array(Type.String({ description: 'Inherited variable name to pass for this call; values are never included in the approval request' }))),
      host: Type.Optional(Type.Boolean({ description: 'Request UNSANDBOXED execution with the Pi user\'s host permissions/environment for this call; requires trusted allowHost=true and separate scope approval' })),
    }),
    async execute(id, params, signal, onUpdate, ctx) {
      const entry = state(ctx);
      const { config, cwd } = entry;
      const hostDefault = entry.hostDefault;
      const modeEpoch = entry.modeEpoch;
      const command = params.command;
      if (typeof command !== 'string' || !command.trim() || command.length > 16384 || command.includes('\0')) throw new Error('Invalid or oversized sandbox command');
      if (signal?.aborted) throw new Error('Sandbox command aborted');
      const host = params.host === true || hostDefault;
      if (host && !config.allowHost) throw new Error('Host escalation is disabled by trusted global configuration');
      const path = params.writeRoot === undefined ? undefined : checkWriteRoot(params.writeRoot, config);
      const granular = normalizeScopes(params, config);
      if (host && (path !== undefined || params.network === true || granular.readPaths.length || granular.writePaths.length || granular.unixSockets.length || granular.env.length)) throw new Error('Host escalation cannot be combined with narrower scopes');
      const network = host || (params.network === true && !config.network);
      const resourceTypes = [...granular.resourceTypes, ...(path ? [{ path, kind: 'writeRoot', type: 'directory' }] : [])].sort((a, b) => `${a.kind}:${a.path}`.localeCompare(`${b.kind}:${b.path}`));
      const scope = { path, network, ...granular, resourceTypes, ...(host ? { host: true } : {}) };
      const typeFor = (kind, resource) => resourceTypes.find(item => item.kind === kind && item.path === resource)?.type;
      const resources = [ ...(path ? [[path, 'writeRoot', undefined, [params.writeRoot], 'directory']] : []), ...granular.readPaths.map(p => [p, 'read', undefined, params.readPaths.filter(raw => resourcePath(raw, config, 'read') === p), typeFor('read', p)]), ...granular.writePaths.map(p => [p, 'write', undefined, params.writePaths.filter(raw => resourcePath(raw, config, 'write') === p), typeFor('write', p)]), ...granular.unixSockets.map(p => [p, 'socket', undefined, params.unixSockets.filter(raw => resourcePath(raw, config, 'socket') === p), typeFor('socket', p)]), ...granular.env.map(name => [undefined, 'env', name, [], undefined]) ];
      if (network && !host) resources.push([undefined, 'network']);
      if (host) resources.push([undefined, 'host']);
      if (resources.length) {
        if (typeof ctx.executeTool !== 'function') throw new Error('Pi nested tool execution is required for scope requests');
        // Each path-bearing request reaches the permission system's scalar path extractor.
        for (const [resource, resourceKind, resourceName, originals = [], type] of resources) {
          if (signal?.aborted) throw new Error('Sandbox command aborted');
          const gate = host ? HOST_GRANT_TOOL : GRANT_TOOL;
          const request = { command, ...(resource ? { path: resource } : {}), resourceKind, ...(resourceName ? { resourceName } : {}), ...(type ? { resourceType: type } : {}), ...(!host ? { scope, network } : { network: true, host: true }) };
          const result = await ctx.executeTool(gate, request, { signal });
          const approved = result?.result?.details;
          if (result?.isError || !approved || approved.command !== command || approved.cwd !== cwd || approved.path !== resource || approved.resourceKind !== resourceKind || approved.resourceName !== resourceName || approved.resourceType !== type || JSON.stringify(approved.scope) !== JSON.stringify(host ? undefined : scope) || approved.network !== (host ? true : network) || approved.host !== (host ? true : undefined)) throw new Error('Sandbox scope was not approved for this exact command and aggregate scope');
          for (const original of originals) {
            const current = resourceKind === 'writeRoot' ? checkWriteRoot(original, config) : resourcePath(original, config, resourceKind === 'read' ? 'read' : resourceKind === 'write' ? 'write' : 'socket');
            if (current !== resource || resourceType(original) !== type) throw new Error('Requested resource changed during authorization');
          }
        }
        if (signal?.aborted) throw new Error('Sandbox command aborted');
      }
      const bash = createBashTool(cwd, {
        operations: { exec: (cmd, actualCwd, options) => {
          if (cmd !== command || directory(actualCwd) !== cwd) throw new Error('Sandbox execution identity changed');
          if (sessions.get(ctx.sessionManager.getSessionId()) !== entry) throw new Error('Sandbox session changed before execution');
          if (entry.modeEpoch !== modeEpoch) throw new Error('Sandbox mode changed while the command was awaiting authorization; retry explicitly');
          return run(config, cwd, cmd, scope, options);
        } },
      });
      return bash.execute(id, { command, ...(params.timeout !== undefined ? { timeout: params.timeout } : {}) }, signal, onUpdate, ctx);
    },
  });

  // User-shell commands bypass normal tool_call authorization. Do not silently
  // route !/!! around the contextual permission gates.
  pi.on('user_bash', () => ({ result: { output: 'pi-scope-sandbox: !/!! is disabled; ask the agent to use the permission-gated Bash tool, or use your own terminal.', exitCode: 1, cancelled: false, truncated: false } }));
  pi.registerCommand('scope-sandbox', {
    description: 'Show sandbox policy; off/on changes execution mode for this session only',
    handler: async (args, ctx) => {
      const entry = state(ctx);
      const id = ctx.sessionManager.getSessionId();
      const command = args.trim();
      const showStatus = () => ctx.ui.notify(JSON.stringify({
        cwd: entry.cwd,
        configuredMode: entry.config.mode,
        sessionOverride: entry.hostDefault ? 'off (unsandboxed host default)' : 'on (configured sandbox baseline)',
        effectiveMode: entry.hostDefault ? 'host' : entry.config.mode,
        network: entry.config.network,
        allowHost: entry.config.allowHost,
        writeRoots: entry.config.writeRoots,
        denyRead: entry.config.denyRead,
      }, null, 2), 'info');
      if (!command) { showStatus(); return; }
      if (command !== 'off' && command !== 'on') throw new Error('Usage: /scope-sandbox [off|on]');
      if (ctx.mode !== 'tui' || !ctx.hasUI) throw new Error('Sandbox mode can only be changed from the interactive TUI');
      if (command === 'off') {
        if (!entry.config.allowHost) throw new Error('Cannot disable sandbox: trusted global allowHost=true is required');
        const confirmed = await ctx.ui.confirm('Disable sandbox for this session?', 'Subsequent Bash commands will run unsandboxed as the Pi user. Each call still requires scope_host_authorize approval. This does not change permissions or persist settings.');
        if (sessions.get(id) !== entry) throw new Error('Sandbox session ended or changed during confirmation');
        if (!confirmed) { ctx.ui.notify('Sandbox remains enabled.', 'info'); return; }
        if (!entry.hostDefault) { entry.hostDefault = true; entry.modeEpoch++; }
      } else if (entry.hostDefault) {
        entry.hostDefault = false;
        entry.modeEpoch++;
      }
      showStatus();
    },
  });
}
