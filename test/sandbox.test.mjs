import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { checkWriteRoot, executable, loadConfig, normalizeScopes } from '../src/config.mjs';
import { plan, planHost, runSandbox, spawnSandbox } from '../src/sandbox.mjs';
import { fixture } from './helpers.mjs';

const quote = value => `'${value.replaceAll("'", "'\\''")}'`;

test('profile preserves literal command and orders writable mounts before protection', t => {
  const f = fixture(t);
  const command = 'printf "%s" "$(echo literal)"';
  const p = plan(f.config, f.workspace, command, {}, f.scratch);
  assert.ok(p.args.includes('--unshare-all'));
  assert.ok(!p.args.includes('--share-net'));
  assert.deepEqual(p.args.slice(-4), ['--noprofile', '--norc', '-c', command]);
  assert.ok(p.args.indexOf('--bind') < p.args.indexOf('--remount-ro'));
  assert.ok(plan(f.config, f.workspace, 'true', { network: true }, f.scratch).args.includes('--share-net'));
});

test('profile preserves private virtual filesystems and rejects granular overrides', t => {
  const f = fixture(t);
  const profile = plan(f.config, f.workspace, 'true', {}, f.scratch);
  assert.ok(profile.args.includes('--proc') && profile.args.includes('/proc'));
  assert.ok(profile.args.includes('--dev') && profile.args.includes('/dev'));
  for (const path of ['/proc', '/proc/self/status', '/dev', '/dev/null']) {
    assert.throws(() => plan(f.config, f.workspace, 'true', { readPaths: [path] }, f.scratch), /private virtual filesystem mounts/);
  }
});

test('profile rejects a resource type changed after approval', t => {
  const f = fixture(t);
  const target = join(f.external, 'resource');
  writeFileSync(target, 'file');
  const scope = { readPaths: [target], resourceTypes: [{ path: target, kind: 'read', type: 'file' }] };
  rmSync(target); mkdirSync(target);
  assert.throws(() => plan(f.config, f.workspace, 'true', scope, f.scratch), /types changed/);
});

test('launch planning rejects an alias retargeted after authorization', t => {
  const f = fixture(t);
  const target = join(f.external, 'target'), replacement = join(f.external, 'replacement'), alias = join(f.agent, 'link');
  writeFileSync(target, 'approved'); writeFileSync(replacement, 'changed'); symlinkSync(target, alias);
  const scope = normalizeScopes({ readPaths: [alias] }, f.config);
  unlinkSync(alias); symlinkSync(replacement, alias);
  assert.throws(() => plan(f.config, f.workspace, 'true', scope, f.scratch), /aliases changed|did not match/);
});

test('read-only profile never grants baseline write roots', t => {
  const f = fixture(t, { mode: 'read-only' });
  const p = plan(f.config, f.workspace, 'true', {}, f.scratch);
  assert.equal(p.args.filter(x => x === '--bind').length, 1, 'only private scratch');
  assert.equal(plan(f.config, f.workspace, 'true', { path: f.external }, f.scratch).args.filter(x => x === '--bind').length, 2);
});

test('invalid scope and missing backend fail before any command', async t => {
  const f = fixture(t);
  assert.throws(() => plan({ ...f.config, bwrap: '/nonexistent/bwrap' }, f.workspace, 'true', {}, f.scratch), /unavailable/);
  assert.throws(() => plan(f.config, f.workspace, 'x'.repeat(16385), {}, f.scratch), /oversized/);
  assert.throws(() => plan(f.config, f.workspace, 'true', { path: '/' }, f.scratch), /protected|scratch/);
  await assert.rejects(spawnSandbox({ file: '/nonexistent/backend', args: [], cwd: f.workspace, env: {} }), /failed to start/);
});

test('workspaces and scopes may not cover private scratch mountpoints', t => {
  const f = fixture(t);
  for (const path of ['/tmp', '/var/tmp', '/var']) {
    assert.throws(() => checkWriteRoot(path, f.config), /scratch/);
    assert.throws(() => plan({ ...f.config, mode: 'read-only' }, path, 'true', {}, f.scratch), /scratch/);
  }
  assert.doesNotThrow(() => plan(f.config, f.workspace, 'true', {}, f.scratch));
});

test('absolute backend backing directory is protected and identity changes fail closed', t => {
  const f = fixture(t);
  const backend = join(f.external, 'backend');
  writeFileSync(backend, '#!/bin/sh\nexit 0\n');
  chmodSync(backend, 0o700);
  const config = loadConfig(f.agent, f.home, f.extension, { bwrap: backend });
  assert.equal(config.bwrap, backend);
  assert.throws(() => checkWriteRoot(f.external, config), /protected/);
  writeFileSync(backend, '#!/bin/sh\nprintf replaced\n');
  assert.throws(() => plan(config, f.workspace, 'true', {}, f.scratch), /backend changed/);
});

test('host profile needs opt-in, uses the pinned shell and rejects a replaced shell', async t => {
  const f = fixture(t);
  assert.throws(() => planHost(f.config, f.workspace, 'true'), /disabled/);
  const shell = join(f.external, 'shell');
  writeFileSync(shell, '#!/bin/sh\nexit 0\n');
  chmodSync(shell, 0o700);
  const config = loadConfig(f.agent, f.home, f.extension, { shell, allowHost: true });
  const invocation = planHost(config, f.workspace, 'printf host');
  assert.equal(invocation.file, shell);
  assert.deepEqual(invocation.args, ['--noprofile', '--norc', '-c', 'printf host']);
  assert.equal(invocation.env.HOME, process.env.HOME);
  assert.throws(() => checkWriteRoot(f.external, config), /protected/);
  assert.throws(() => planHost(config, f.workspace, 'x'.repeat(16385)), /oversized/);
  assert.throws(() => plan(config, f.workspace, 'true', { host: true }, f.scratch), /Host execution/);
  await assert.rejects(runSandbox(config, f.workspace, 'true', { host: true, path: f.external }), /combined/);
  writeFileSync(shell, '#!/bin/sh\nprintf changed\n');
  assert.throws(() => planHost(config, f.workspace, 'true'), /shell changed/);
  assert.throws(() => plan(config, f.workspace, 'true', {}, f.scratch), /shell changed/);
});

test('explicit host execution does not create sandbox metadata or retry a failed command', async t => {
  const f = fixture(t, { allowHost: true });
  const marker = join(f.external, 'attempts');
  let output = '';
  const result = await runSandbox(f.config, f.workspace, `printf x >> ${quote(marker)}; printf host-output; exit 7`, { host: true }, { onData: data => { output += data; } });
  assert.equal(result.exitCode, 7);
  assert.equal(output, 'host-output');
  assert.equal(readFileSync(marker, 'utf8'), 'x');
  assert.equal(existsSync(join(f.workspace, '.pi')), false);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(runSandbox(f.config, f.workspace, 'true', { host: true }, { signal: controller.signal }), /aborted/);
});

test('process runner streams output and preserves nonzero status', async t => {
  const f = fixture(t);
  let output = '';
  const result = await spawnSandbox({ file: executable('bash'), args: ['--noprofile', '--norc', '-c', 'printf out; printf err >&2; exit 7'], cwd: f.workspace, env: {} }, { onData: data => { output += data; } });
  assert.equal(result.exitCode, 7);
  assert.match(output, /out/);
  assert.match(output, /err/);
});

test('pre-aborted command never starts', async t => {
  const f = fixture(t);
  const controller = new AbortController();
  controller.abort();
  const marker = join(f.workspace, 'unexpected');
  await assert.rejects(spawnSandbox({ file: executable('bash'), args: ['-c', `touch ${quote(marker)}`], cwd: f.workspace, env: {} }, { signal: controller.signal }), /aborted/);
  assert.equal(existsSync(marker), false);
});

test('timeout kills descendants and a running abort rejects', async t => {
  const f = fixture(t);
  const marker = join(f.workspace, 'late-child');
  const shell = executable('bash');
  await assert.rejects(spawnSandbox({ file: shell, args: ['-c', `(sleep 0.5; printf bad > ${quote(marker)}) & wait`], cwd: f.workspace, env: process.env }, { timeout: 0.05 }), /timed out/);
  await new Promise(resolve => setTimeout(resolve, 650));
  assert.equal(existsSync(marker), false);
  const controller = new AbortController();
  const task = spawnSandbox({ file: shell, args: ['-c', 'sleep 5'], cwd: f.workspace, env: process.env }, { signal: controller.signal });
  setTimeout(() => controller.abort(), 30);
  await assert.rejects(task, /aborted/);
});
