import assert from 'node:assert/strict';
import { symlinkSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { GRANT_TOOL } from '../src/config.mjs';
import { registerSandbox } from '../src/extension.mjs';
import { context, FakeType, fixture } from './helpers.mjs';

function harness(t, childSupport) {
  const f = fixture(t);
  const tools = new Map(), hooks = new Map(), runs = [], services = new Map([['session-a', {}], ['session-b', {}]]);
  const pi = { registerTool: tool => tools.set(tool.name, tool), registerCommand() {}, on: (event, handler) => hooks.set(event, handler) };
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
  hooks.get('session_start')({}, ctx);
  const nested = [];
  ctx.executeTool = async (name, args) => {
    nested.push({ name, args });
    return { toolCall: { name, arguments: args }, result: await tools.get(name).execute('nested', args, undefined, undefined, ctx), isError: false };
  };
  return { ...f, tools, hooks, runs, nested, ctx, services };
}

const execute = (f, args, ctx = f.ctx) => f.tools.get('bash').execute('call', args, undefined, undefined, ctx);

test('normal Bash runs unchanged inside baseline scope without nested approval', async t => {
  const f = harness(t);
  await execute(f, { command: 'printf hello' });
  assert.equal(f.runs.length, 1);
  assert.deepEqual(f.runs[0].slice(1, 4), [f.workspace, 'printf hello', { path: undefined, network: false }]);
  assert.equal(f.nested.length, 0);
});

test('scope exception takes nested gate path and does not persist', async t => {
  const f = harness(t);
  await execute(f, { command: 'printf hello', writeRoot: f.external, network: true });
  assert.equal(f.nested[0].name, GRANT_TOOL);
  assert.deepEqual(f.nested[0].args, { command: 'printf hello', path: f.external, network: true });
  assert.deepEqual(f.runs[0][3], { path: f.external, network: true });
  await execute(f, { command: 'printf hello' });
  assert.deepEqual(f.runs[1][3], { path: undefined, network: false });
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
