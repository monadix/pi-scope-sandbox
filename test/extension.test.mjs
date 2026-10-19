import assert from 'node:assert/strict';
import { symlinkSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { GRANT_TOOL, HOST_GRANT_TOOL } from '../src/config.mjs';
import { registerSandbox } from '../src/extension.mjs';
import { context, FakeType, fixture } from './helpers.mjs';

function harness(t, childSupport, override = {}) {
  const f = fixture(t, override);
  const tools = new Map(), hooks = new Map(), commands = new Map(), runs = [], services = new Map([['session-a', {}], ['session-b', {}]]);
  const pi = { registerTool: tool => tools.set(tool.name, tool), registerCommand: (name, command) => commands.set(name, command), on: (event, handler) => hooks.set(event, handler) };
  const createBashTool = (cwd, options) => ({
    parameters: FakeType.Object({ command: {}, timeout: {} }), description: 'Run Bash',
    execute: async (_id, params, signal) => {
      const result = await options.operations.exec(params.command, cwd, { signal, timeout: params.timeout });
      return { content: [{ type: 'text', text: 'ran' }], details: result };
    },
  });
  registerSandbox(pi, {
    Type: FakeType, createBashTool, getAgentDir: () => f.agent,
    getPermissionsService: id => services.get(id), readConfig: () => f.config, childSupport,
    run: async (...args) => { runs.push(args); return { exitCode: 0 }; },
  });
  const ctx = context(f.workspace);
  ctx.mode = 'tui';
  hooks.get('session_start')({}, ctx);
  const nested = [];
  ctx.executeTool = async (name, args) => {
    nested.push({ name, args });
    return { toolCall: { name, arguments: args }, result: await tools.get(name).execute('nested', args, undefined, undefined, ctx), isError: false };
  };
  return { ...f, tools, hooks, commands, runs, nested, ctx, services };
}

const execute = (f, args, ctx = f.ctx) => f.tools.get('bash').execute('call', args, undefined, undefined, ctx);

test('normal Bash runs unchanged inside baseline scope without nested approval', async t => {
  const f = harness(t);
  await execute(f, { command: 'printf hello' });
  assert.equal(f.runs.length, 1);
  assert.deepEqual(f.runs[0].slice(1, 4), [f.workspace, 'printf hello', { path: undefined, network: false, readPaths: [], writePaths: [], unixSockets: [], env: [], resourceTypes: [] }]);
  assert.equal(f.nested.length, 0);
});

test('scope exception takes nested gate path and does not persist', async t => {
  const f = harness(t);
  await execute(f, { command: 'printf hello', writeRoot: f.external, network: true });
  assert.equal(f.nested[0].name, GRANT_TOOL);
  assert.deepEqual(f.nested[0].args, { command: 'printf hello', path: f.external, resourceKind: 'writeRoot', resourceType: 'directory', scope: { path: f.external, network: true, readPaths: [], writePaths: [], unixSockets: [], env: [], resourceTypes: [{ path: f.external, kind: 'writeRoot', type: 'directory' }] }, network: true });
  assert.deepEqual(f.runs[0][3], { path: f.external, network: true, readPaths: [], writePaths: [], unixSockets: [], env: [], resourceTypes: [{ path: f.external, kind: 'writeRoot', type: 'directory' }] });
  await execute(f, { command: 'printf hello' });
  assert.deepEqual(f.runs[1][3], { path: undefined, network: false, readPaths: [], writePaths: [], unixSockets: [], env: [], resourceTypes: [] });
});

test('host escalation is opt-in, separately gated on every call, and never persists', async t => {
  const disabled = harness(t);
  await assert.rejects(execute(disabled, { command: 'true', host: true }), /disabled/);
  assert.equal(disabled.nested.length, 0);
  assert.equal(disabled.runs.length, 0);
  const f = harness(t, undefined, { allowHost: true });
  assert.deepEqual(f.tools.get('bash').reachesTools({ host: true }), [HOST_GRANT_TOOL]);
  await assert.rejects(f.tools.get(GRANT_TOOL).execute('wrong-gate', { command: 'true', host: true, network: true }, undefined, undefined, f.ctx), /dedicated/);
  for (let i = 0; i < 2; i++) {
    await execute(f, { command: 'printf host', host: true });
    assert.equal(f.nested[i].name, HOST_GRANT_TOOL);
    assert.deepEqual(f.nested[i].args, { command: 'printf host', resourceKind: 'host', network: true, host: true });
    assert.deepEqual(f.runs[i][3], { path: undefined, network: true, readPaths: [], writePaths: [], unixSockets: [], env: [], resourceTypes: [], host: true });
  }
  await execute(f, { command: 'printf baseline' });
  assert.equal(f.nested.length, 2);
  assert.deepEqual(f.runs[2][3], { path: undefined, network: false, readPaths: [], writePaths: [], unixSockets: [], env: [], resourceTypes: [] });
  for (const args of [{ host: true, network: true }, { host: true, writeRoot: f.external }]) {
    await assert.rejects(execute(f, { command: 'true', ...args }), /combined/);
  }
});

test('host scope binds approval identity and refusal/abort cannot run it', async t => {
  const f = harness(t, undefined, { allowHost: true });
  const approve = f.ctx.executeTool;
  for (const change of [{ host: undefined }, { host: false }, { command: 'other' }, { cwd: f.external }, { network: false }, { path: f.external }]) {
    f.ctx.executeTool = async (...args) => {
      const outcome = await approve(...args);
      Object.assign(outcome.result.details, change);
      return outcome;
    };
    await assert.rejects(execute(f, { command: 'true', host: true }), /not approved/);
  }
  f.ctx.executeTool = async () => { throw new Error('permission denied'); };
  await assert.rejects(execute(f, { command: 'true', host: true }), /permission denied/);
  delete f.ctx.executeTool;
  await assert.rejects(execute(f, { command: 'true', host: true }), /nested tool/);
  const controller = new AbortController();
  f.ctx.executeTool = async (...args) => { const result = await approve(...args); controller.abort(); return result; };
  await assert.rejects(f.tools.get('bash').execute('call', { command: 'true', host: true }, controller.signal, undefined, f.ctx), /aborted/);
  assert.equal(f.runs.length, 0);
});

test('session-only sandbox off requires TUI confirmation and keeps the host gate per call', async t => {
  const disabled = harness(t);
  disabled.ctx.hasUI = true;
  disabled.ctx.ui.confirm = async () => true;
  await assert.rejects(disabled.commands.get('scope-sandbox').handler('off', disabled.ctx), /allowHost=true/);
  assert.equal(disabled.runs.length, 0);

  const cancelled = harness(t, undefined, { allowHost: true });
  cancelled.ctx.hasUI = true;
  cancelled.ctx.ui.confirm = async () => false;
  await cancelled.commands.get('scope-sandbox').handler('off', cancelled.ctx);
  await execute(cancelled, { command: 'true' });
  assert.equal(cancelled.runs[0][3].host, undefined);
  assert.equal(cancelled.nested.length, 0);

  const f = harness(t, undefined, { allowHost: true });
  const status = [];
  f.ctx.hasUI = true;
  f.ctx.ui.notify = message => status.push(JSON.parse(message));
  f.ctx.ui.confirm = async () => true;
  await f.commands.get('scope-sandbox').handler('off', f.ctx);
  assert.equal(status.at(-1).configuredMode, 'workspace-write');
  assert.equal(status.at(-1).effectiveMode, 'host');
  await execute(f, { command: 'printf host' });
  assert.equal(f.nested[0].name, HOST_GRANT_TOOL);
  assert.equal(f.runs[0][3].host, true);
  f.ctx.executeTool = async () => ({ isError: true });
  await assert.rejects(execute(f, { command: 'printf denied' }), /not approved/);
  await assert.rejects(execute(f, { command: 'true', readPaths: [f.external] }), /cannot be combined/i);
  assert.equal(f.runs.length, 1);
});

test('non-TUI modes with hasUI cannot disable or re-enable the session override', async t => {
  for (const mode of ['rpc', 'print']) {
    const f = harness(t, undefined, { allowHost: true });
    f.ctx.mode = mode;
    f.ctx.hasUI = true;
    let confirmations = 0;
    f.ctx.ui.confirm = async () => { confirmations++; return true; };
    await assert.rejects(f.commands.get('scope-sandbox').handler('off', f.ctx), /interactive TUI/);
    assert.equal(confirmations, 0);
    await execute(f, { command: 'true' });
    assert.equal(f.runs[0][3].host, undefined);
    assert.equal(f.nested.length, 0);
  }

  const f = harness(t, undefined, { allowHost: true });
  f.ctx.hasUI = true;
  f.ctx.ui.confirm = async () => true;
  await f.commands.get('scope-sandbox').handler('off', f.ctx);
  f.ctx.mode = 'rpc';
  let confirmations = 0;
  f.ctx.ui.confirm = async () => { confirmations++; return true; };
  await assert.rejects(f.commands.get('scope-sandbox').handler('on', f.ctx), /interactive TUI/);
  assert.equal(confirmations, 0);
  await execute(f, { command: 'true' });
  assert.equal(f.runs[0][3].host, true);
  assert.equal(f.nested[0].name, HOST_GRANT_TOOL);
});

test('session mode commands reject headless, invalid, stale confirmation and restore baseline', async t => {
  const headless = harness(t, undefined, { allowHost: true });
  await assert.rejects(headless.commands.get('scope-sandbox').handler('off', headless.ctx), /interactive TUI/);
  await assert.rejects(headless.commands.get('scope-sandbox').handler('maybe', headless.ctx), /Usage/);

  const f = harness(t, undefined, { allowHost: true, mode: 'read-only' });
  f.ctx.hasUI = true;
  f.ctx.ui.confirm = async () => {
    f.hooks.get('session_shutdown')({}, f.ctx);
    return true;
  };
  await assert.rejects(f.commands.get('scope-sandbox').handler('off', f.ctx), /session ended/);
  f.hooks.get('session_start')({}, f.ctx);
  f.ctx.ui.confirm = async () => true;
  await f.commands.get('scope-sandbox').handler('off', f.ctx);
  await f.commands.get('scope-sandbox').handler('on', f.ctx);
  await execute(f, { command: 'true' });
  assert.equal(f.runs[0][3].host, undefined);
  assert.equal(f.runs[0][3].path, undefined);
  const status = [];
  f.ctx.ui.notify = message => status.push(JSON.parse(message));
  await f.commands.get('scope-sandbox').handler('', f.ctx);
  assert.equal(status[0].configuredMode, 'read-only');
  assert.equal(status[0].effectiveMode, 'read-only');
});

test('mode change while approval is pending prevents execution under captured mode', async t => {
  const f = harness(t, undefined, { allowHost: true });
  f.ctx.hasUI = true;
  f.ctx.ui.confirm = async () => true;
  let release;
  const waiting = new Promise(resolve => { release = resolve; });
  const approvedExecute = f.ctx.executeTool;
  f.ctx.executeTool = async (...args) => { await waiting; return approvedExecute(...args); };
  const pending = execute(f, { command: 'true', network: true });
  await f.commands.get('scope-sandbox').handler('off', f.ctx);
  release();
  await assert.rejects(pending, /mode changed/);
  assert.equal(f.runs.length, 0);

  const revoked = harness(t, undefined, { allowHost: true });
  revoked.ctx.hasUI = true;
  revoked.ctx.ui.confirm = async () => true;
  await revoked.commands.get('scope-sandbox').handler('off', revoked.ctx);
  let releaseHost;
  const hostWaiting = new Promise(resolve => { releaseHost = resolve; });
  const hostApproval = revoked.ctx.executeTool;
  revoked.ctx.executeTool = async (...args) => { await hostWaiting; return hostApproval(...args); };
  const hostPending = execute(revoked, { command: 'true' });
  await revoked.commands.get('scope-sandbox').handler('on', revoked.ctx);
  releaseHost();
  await assert.rejects(hostPending, /mode changed/);
  assert.equal(revoked.runs.length, 0);
});

test('new session starts sandboxed after this session selected host default', async t => {
  const f = harness(t, undefined, { allowHost: true });
  f.ctx.hasUI = true;
  f.ctx.ui.confirm = async () => true;
  await f.commands.get('scope-sandbox').handler('off', f.ctx);
  const other = context(f.external, 'session-b');
  f.hooks.get('session_start')({}, other);
  other.executeTool = async (...args) => {
    f.nested.push({ name: args[0], args: args[1] });
    return { toolCall: { name: args[0], arguments: args[1] }, result: await f.tools.get(args[0]).execute('nested', args[1], undefined, undefined, other), isError: false };
  };
  await execute(f, { command: 'true' }, other);
  assert.equal(f.runs[0][3].host, undefined);
  assert.equal(f.nested.length, 0);
});

test('standalone host approval does not authorize a later call', async t => {
  const f = harness(t, undefined, { allowHost: true });
  await f.tools.get(HOST_GRANT_TOOL).execute('standalone', { command: 'true', host: true, network: true }, undefined, undefined, f.ctx);
  f.ctx.executeTool = async () => ({ isError: true });
  await assert.rejects(execute(f, { command: 'true', host: true }), /not approved/);
  assert.equal(f.runs.length, 0);
});

test('granular scopes approve each scalar resource and bind the complete aggregate without persistence', async t => {
  const f = harness(t);
  const read = join(f.external, 'read.txt'), write = join(f.external, 'write.txt');
  const { writeFileSync } = await import('node:fs');
  writeFileSync(read, 'read'); writeFileSync(write, 'before');
  await execute(f, { command: 'true', readPaths: [read], writePaths: [write], env: ['NIX_REMOTE'] });
  assert.equal(f.nested.length, 3);
  assert.deepEqual(f.nested.map(item => item.args.path), [read, write, undefined]);
  assert.deepEqual(f.nested.map(item => item.args.resourceKind), ['read', 'write', 'env']);
  assert.equal(f.nested[2].args.resourceName, 'NIX_REMOTE');
  for (const request of f.nested) assert.deepEqual(request.args.scope, f.runs[0][3]);
  assert.deepEqual(f.runs[0][3], { path: undefined, network: false, readPaths: [read], writePaths: [write], unixSockets: [], env: ['NIX_REMOTE'], resourceTypes: [{ path: read, kind: 'read', type: 'file' }, { path: write, kind: 'write', type: 'file' }] });
  await execute(f, { command: 'true' });
  assert.deepEqual(f.runs[1][3].readPaths, []);
});

test('undeclared caller aliases cannot add granular grants or bypass nested approval', async t => {
  const f = harness(t);
  const hidden = join(f.agent, 'hidden.txt');
  const { writeFileSync } = await import('node:fs');
  writeFileSync(hidden, 'hidden');
  await execute(f, { command: `cat ${hidden}`, aliases: [{ path: hidden, original: hidden, kind: 'read', type: 'file' }] });
  assert.equal(f.nested.length, 0);
  assert.deepEqual(f.runs[0][3].readPaths, []);
  assert.deepEqual(f.runs[0][3].aliases, undefined);
});

test('symlink grants bind alias and target and pass both spellings through path gates', async t => {
  const f = harness(t);
  const target = join(f.external, 'target'), alias = join(f.agent, 'config-link');
  const { writeFileSync } = await import('node:fs');
  writeFileSync(target, 'data'); symlinkSync(target, alias);
  await execute(f, { command: 'true', readPaths: [alias] });
  assert.deepEqual(f.nested.map(item => item.args.path), [alias, target]);
  assert.deepEqual(f.runs[0][3].aliases, [{ path: target, original: alias, kind: 'read', type: 'file' }]);
});

test('granular approval denial, aggregate tampering, invalid input and abort all block execution', async t => {
  const f = harness(t);
  const target = join(f.external, 'target');
  const { writeFileSync } = await import('node:fs');
  writeFileSync(target, 'x');
  const defaultExecute = f.ctx.executeTool;
  f.ctx.executeTool = async () => ({ isError: true });
  await assert.rejects(execute(f, { command: 'true', readPaths: [target] }), /not approved/);
  assert.equal(f.runs.length, 0);
  const approve = defaultExecute;
  f.ctx.executeTool = async (...args) => {
    const response = await approve(...args);
    response.result.details.scope = { ...response.result.details.scope, env: [...response.result.details.scope.env, 'EXTRA'] };
    return response;
  };
  await assert.rejects(execute(f, { command: 'true', readPaths: [target] }), /not approved/);
  assert.equal(f.runs.length, 0);
  await assert.rejects(execute(f, { command: 'true', env: ['BASH_ENV'] }), /invalid/);
  assert.equal(f.runs.length, 0);
  const controller = new AbortController();
  f.ctx.executeTool = async (...args) => { const result = await defaultExecute(...args); controller.abort(); return result; };
  await assert.rejects(f.tools.get('bash').execute('call', { command: 'true', readPaths: [target] }, controller.signal, undefined, f.ctx), /aborted/);
  assert.equal(f.runs.length, 0);
});

test('scope refusal or wrong command identity blocks execution', async t => {
  const f = harness(t);
  f.ctx.executeTool = async () => { throw new Error('permission denied'); };
  await assert.rejects(execute(f, { command: 'true', network: true }), /permission denied/);
  f.ctx.executeTool = async () => ({ result: { details: { command: 'different', cwd: f.workspace, network: true } }, isError: false });
  await assert.rejects(execute(f, { command: 'true', network: true }), /not approved/);
  f.ctx.executeTool = async () => ({ isError: true, result: { details: { command: 'true', cwd: f.workspace, network: true } } });
  await assert.rejects(execute(f, { command: 'true', network: true }), /not approved/);
  assert.equal(f.runs.length, 0);
});

test('missing service, session initialization or nested execution is fail-closed', async t => {
  const f = harness(t);
  f.services.clear();
  await assert.rejects(execute(f, { command: 'true' }), /required/);
  f.services.set('session-a', {});
  await assert.rejects(execute(f, { command: 'true' }, context(f.workspace, 'unknown')), /not initialized/);
  delete f.ctx.executeTool;
  await assert.rejects(execute(f, { command: 'true', network: true }), /nested tool/);
  f.hooks.get('session_shutdown')({}, f.ctx);
  await assert.rejects(execute(f, { command: 'true' }), /not initialized/);
  assert.equal(f.runs.length, 0);
});

test('scope retargeting during approval is rejected', async t => {
  const f = harness(t);
  const alias = join(f.workspace, 'link');
  symlinkSync(f.external, alias);
  const nested = f.ctx.executeTool;
  f.ctx.executeTool = async (...args) => {
    const result = await nested(...args);
    unlinkSync(alias);
    symlinkSync(f.scratch, alias);
    return result;
  };
  await assert.rejects(execute(f, { command: 'true', writeRoot: alias }), /changed during/);
  assert.equal(f.runs.length, 0);
});

test('granular symlink aliases are revalidated after approval', async t => {
  const f = harness(t);
  const source = join(f.external, 'source'), replacement = join(f.scratch, 'replacement'), alias = join(f.workspace, 'resource-link');
  const { writeFileSync } = await import('node:fs');
  writeFileSync(source, 'source'); writeFileSync(replacement, 'replacement');
  symlinkSync(source, alias);
  const approve = f.ctx.executeTool;
  f.ctx.executeTool = async (...args) => {
    const result = await approve(...args);
    unlinkSync(alias); symlinkSync(replacement, alias);
    return result;
  };
  await assert.rejects(execute(f, { command: 'true', readPaths: [alias] }), /changed during/);
  assert.equal(f.runs.length, 0);
});

test('granular resource type changes during approval are rejected', async t => {
  const f = harness(t);
  const source = join(f.external, 'replace-me');
  const { writeFileSync, unlinkSync, mkdirSync } = await import('node:fs');
  writeFileSync(source, 'file');
  const approve = f.ctx.executeTool;
  f.ctx.executeTool = async (...args) => {
    const result = await approve(...args);
    unlinkSync(source); mkdirSync(source);
    return result;
  };
  await assert.rejects(execute(f, { command: 'true', readPaths: [source] }), /changed during/);
  assert.equal(f.runs.length, 0);
});

test('standalone scope tool cannot authorize a future call; user shell is blocked', async t => {
  const f = harness(t);
  await f.tools.get(GRANT_TOOL).execute('standalone', { command: 'true', path: f.external, network: false }, undefined, undefined, f.ctx);
  assert.equal(f.runs.length, 0);
  await execute(f, { command: 'true' });
  assert.equal(f.runs[0][3].path, undefined);
  assert.equal(f.hooks.get('user_bash')().result.exitCode, 1);
});

test('state stays isolated across session IDs', async t => {
  const f = harness(t);
  const other = context(f.external, 'session-b');
  f.hooks.get('session_start')({}, other);
  await execute(f, { command: 'true' }, other);
  assert.equal(f.runs[0][1], f.external);
  f.services.delete('session-b');
  await assert.rejects(execute(f, { command: 'true' }, other), /required/);
  await execute(f, { command: 'true' });
  assert.equal(f.runs[1][1], f.workspace);
});

test('subagent launches require mandatory extension propagation; teardown disposes it', t => {
  const registrations = [];
  let disposed = 0;
  const f = harness(t, {
    extensions: [{ id: 'sandbox', path: '/trusted/sandbox.ts' }],
    register: input => { registrations.push(input); return { dispose() { disposed++; } }; },
  });
  assert.equal(registrations[0].sessionId, 'session-a');
  assert.equal(registrations[0].requireForAllRunners, true);
  assert.equal(f.hooks.get('tool_call')({ toolName: 'subagent' }, f.ctx), undefined);
  f.hooks.get('session_shutdown')({}, f.ctx);
  assert.equal(disposed, 1);
  assert.equal(f.hooks.get('tool_call')({ toolName: 'subagent' }, f.ctx).block, true);
});

test('missing or incompatible child-registration API blocks subagents, not ordinary Bash', async t => {
  const absent = harness(t);
  assert.equal(absent.hooks.get('tool_call')({ toolName: 'subagent' }, absent.ctx).block, true);
  await execute(absent, { command: 'true' });
  const failed = harness(t, { extensions: [], register() { throw new Error('API incompatible'); } });
  const result = failed.hooks.get('tool_call')({ toolName: 'subagent' }, failed.ctx);
  assert.equal(result.block, true);
  assert.match(result.reason, /API incompatible/);
  await execute(failed, { command: 'true' });
});
