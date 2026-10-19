import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { checkWriteRoot, contains, loadConfig, normalizeScopes, protectedWritePaths, safeEnvironment, hostEnvironment } from '../src/config.mjs';
import { fixture } from './helpers.mjs';

test('configuration defaults, validation and no project override', t => {
  const f = fixture(t);
  assert.equal(f.config.network, false);
  assert.equal(f.config.allowHost, false);
  assert.equal(loadConfig(f.agent, f.home, f.extension, { allowHost: true }).allowHost, true);
  assert.equal(f.config.mode, 'workspace-write');
  for (const bad of [null, [], { yolo: true }, { network: 'yes' }, { allowHost: 'yes' }, { mode: 'danger-full-access' }, { writeRoots: ['relative'] }, { denyRead: ['relative'] }, { envAllow: ['BASH_ENV'] }, { envAllow: ['LD_PRELOAD'] }, { shell: 'relative' }]) {
    assert.throws(() => loadConfig(f.agent, f.home, f.extension, bad));
  }
  mkdirSync(join(f.workspace, '.pi'), { recursive: true });
  writeFileSync(join(f.workspace, '.pi', 'sandbox.json'), '{"network":true,"allowHost":true}');
  assert.equal(loadConfig(f.agent, f.home, f.extension).network, false);
  assert.equal(loadConfig(f.agent, f.home, f.extension).allowHost, false);
});

test('write roots are canonical and protected roots cannot be granted', t => {
  const f = fixture(t);
  symlinkSync(f.external, join(f.workspace, 'alias'));
  assert.equal(checkWriteRoot(join(f.workspace, 'alias'), f.config), f.external);
  for (const path of ['/', '/etc', '/nix', f.home, f.agent, f.extension, f.root]) {
    assert.throws(() => checkWriteRoot(path, f.config), path);
  }
  assert.equal(contains('/foo', '/foobar'), false);
});

test('granular writes allow ordinary home descendants but preserve home and hidden-path protections', t => {
  const f = fixture(t);
  const file = join(f.home, 'project', 'report.txt');
  const directory = join(f.home, 'other-checkout');
  mkdirSync(join(f.home, 'project'), { recursive: true });
  mkdirSync(directory);
  writeFileSync(file, 'mock');
  assert.deepEqual(normalizeScopes({ writePaths: [file, directory] }, f.config).writePaths, [directory, file].sort());
  assert.throws(() => normalizeScopes({ writePaths: [f.home] }, f.config), /home root/);

  mkdirSync(join(f.home, '.ssh'));
  const protectedConfig = loadConfig(f.agent, f.home, f.extension, {});
  assert.throws(() => normalizeScopes({ writePaths: [join(f.home, '.ssh')] }, protectedConfig), /hidden path/);
});

test('granular writes cannot expose Git config or hooks, including metadata roots', t => {
  const f = fixture(t);
  const git = join(f.external, '.git');
  mkdirSync(join(git, 'hooks'), { recursive: true });
  writeFileSync(join(git, 'config'), 'config');
  for (const path of [join(git, 'config'), join(git, 'hooks'), git]) {
    assert.throws(() => normalizeScopes({ writePaths: [path] }, f.config), /Git config or hooks/);
  }
  assert.deepEqual(normalizeScopes({ writePaths: [f.external] }, f.config).writePaths, [f.external]);
});

test('granular single-file writes reject symlinked .git and .pi metadata ancestry', t => {
  const f = fixture(t);
  const checkoutGit = join(f.external, 'symlinked-git-checkout');
  const gitMetadata = join(f.root, 'external-git-metadata');
  mkdirSync(checkoutGit);
  mkdirSync(join(gitMetadata, 'hooks'), { recursive: true });
  writeFileSync(join(gitMetadata, 'config'), 'protected-config');
  writeFileSync(join(gitMetadata, 'hooks', 'pre-commit'), 'protected-hook');
  symlinkSync(gitMetadata, join(checkoutGit, '.git'));
  for (const path of [join(checkoutGit, '.git', 'config'), join(checkoutGit, '.git', 'hooks', 'pre-commit')]) {
    assert.throws(() => normalizeScopes({ writePaths: [path] }, f.config), /Git config or hooks/);
  }

  const policyDirectory = join(f.root, 'external-pi-metadata');
  mkdirSync(policyDirectory);
  writeFileSync(join(policyDirectory, 'policy'), 'protected-policy');
  symlinkSync(policyDirectory, join(checkoutGit, '.pi'));
  assert.throws(() => normalizeScopes({ writePaths: [join(checkoutGit, '.pi', 'policy')] }, f.config), /.pi metadata/);
  assert.equal(readFileSync(join(gitMetadata, 'config'), 'utf8'), 'protected-config');
  assert.equal(readFileSync(join(gitMetadata, 'hooks', 'pre-commit'), 'utf8'), 'protected-hook');
  assert.equal(readFileSync(join(policyDirectory, 'policy'), 'utf8'), 'protected-policy');
});

test('granular resources cannot replace private /proc or /dev mounts', t => {
  const f = fixture(t);
  for (const path of ['/proc', '/proc/self/status', '/dev', '/dev/null']) {
    assert.throws(() => normalizeScopes({ readPaths: [path] }, f.config), /private virtual filesystem mounts/);
  }
});

test('per-call scope normalization validates existing resources, denyRead and env names', t => {
  const f = fixture(t, { denyRead: [] });
  const file = join(f.external, 'resource');
  writeFileSync(file, 'mock');
  const normalized = normalizeScopes({ readPaths: [file], writePaths: [file], unixSockets: [], env: ['NIX_REMOTE', 'SSH_AUTH_SOCK'] }, f.config);
  assert.deepEqual(normalized, { readPaths: [file], writePaths: [file], unixSockets: [], env: ['NIX_REMOTE', 'SSH_AUTH_SOCK'], resourceTypes: [{ path: file, kind: 'read', type: 'file' }, { path: file, kind: 'write', type: 'file' }] });
  for (const env of [['HOME'], ['PATH'], ['TMPDIR'], ['LD_PRELOAD'], ['BASH_ENV'], ['PS4'], ['PYTHONPATH'], ['NODE_OPTIONS']]) assert.throws(() => normalizeScopes({ env }, f.config));
  assert.throws(() => normalizeScopes({ readPaths: ['relative'] }, f.config));
  assert.throws(() => normalizeScopes({ writePaths: [join(f.external, 'missing')] }, f.config));
  assert.throws(() => normalizeScopes({ writePaths: [f.home] }, f.config));
  assert.throws(() => normalizeScopes({ readPaths: ['/tmp'] }, f.config), /scratch/);
  mkdirSync(join(f.home, '.ssh'));
  const masked = loadConfig(f.agent, f.home, f.extension, {});
  assert.throws(() => normalizeScopes({ readPaths: [f.home] }, masked), /masked descendants/);
  const denied = fixture(t, { denyRead: [file] });
  assert.throws(() => normalizeScopes({ readPaths: [file] }, denied.config), /denyRead/);
  assert.throws(() => normalizeScopes({ writePaths: [file] }, denied.config), /denyRead/);
});

test('shell/loader/provider credentials are not inherited', t => {
  const f = fixture(t, { envAllow: ['CUSTOM_VALUE'] });
  const env = safeEnvironment(f.config, { PATH: '/bin:.:relative', HOME: f.home, BASH_ENV: '/evil', NODE_OPTIONS: '--require /evil', CLIPROXYAPI_API_KEY: 'not-real', EXA_API_KEY: 'not-real', CUSTOM_VALUE: 'value', https_proxy: 'http://proxy' });
  assert.equal(env.HOME, '/tmp/home');
  assert.equal(env.CUSTOM_VALUE, 'value');
  for (const key of ['BASH_ENV', 'NODE_OPTIONS', 'CLIPROXYAPI_API_KEY', 'EXA_API_KEY', 'https_proxy']) assert.equal(env[key], undefined);
  assert.ok(!env.PATH.split(':').includes('.'));
});

test('host environment preserves user capabilities but strips implicit execution injection', () => {
  const env = hostEnvironment({ HOME: '/home/example', PATH: '/bin', NIX_REMOTE: 'daemon', SSH_AUTH_SOCK: '/run/mock-agent', EXA_API_KEY: 'mock-only', BASH_ENV: '/evil', LD_PRELOAD: '/evil', NODE_OPTIONS: '--require /evil' });
  assert.deepEqual(env, { HOME: '/home/example', PATH: '/bin', NIX_REMOTE: 'daemon', SSH_AUTH_SOCK: '/run/mock-agent', EXA_API_KEY: 'mock-only' });
});

test('existing project security paths and git worktree metadata are protected', t => {
  const f = fixture(t);
  const git = join(f.external, 'gitmeta');
  mkdirSync(join(git, 'hooks'), { recursive: true });
  writeFileSync(join(git, 'config'), 'config');
  writeFileSync(join(f.workspace, '.git'), `gitdir: ${git}\n`);
  mkdirSync(join(f.workspace, '.pi'));
  const paths = protectedWritePaths([f.workspace], f.config);
  assert.ok(paths.includes(join(git, 'config')));
  assert.ok(paths.includes(join(git, 'hooks')));
  assert.ok(paths.includes(join(f.workspace, '.pi')));
});
