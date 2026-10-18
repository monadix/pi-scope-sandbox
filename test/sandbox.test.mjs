import assert from 'node:assert/strict';
import { chmodSync, existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { checkWriteRoot, executable, loadConfig } from '../src/config.mjs';
import { plan, spawnSandbox } from '../src/sandbox.mjs';
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
