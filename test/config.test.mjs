import assert from 'node:assert/strict';
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { checkWriteRoot, contains, loadConfig, protectedWritePaths, safeEnvironment } from '../src/config.mjs';
import { fixture } from './helpers.mjs';

test('configuration defaults, validation and no project override', t => {
  const f = fixture(t);
  assert.equal(f.config.network, false);
  assert.equal(f.config.mode, 'workspace-write');
  for (const bad of [null, [], { yolo: true }, { network: 'yes' }, { mode: 'danger-full-access' }, { writeRoots: ['relative'] }, { denyRead: ['relative'] }, { envAllow: ['BASH_ENV'] }, { envAllow: ['LD_PRELOAD'] }, { shell: 'relative' }]) {
    assert.throws(() => loadConfig(f.agent, f.home, f.extension, bad));
  }
  mkdirSync(join(f.workspace, '.pi'), { recursive: true });
  writeFileSync(join(f.workspace, '.pi', 'sandbox.json'), '{"network":true}');
  assert.equal(loadConfig(f.agent, f.home, f.extension).network, false);
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

test('shell/loader/provider credentials are not inherited', t => {
  const f = fixture(t, { envAllow: ['CUSTOM_VALUE'] });
  const env = safeEnvironment(f.config, { PATH: '/bin:.:relative', HOME: f.home, BASH_ENV: '/evil', NODE_OPTIONS: '--require /evil', CLIPROXYAPI_API_KEY: 'not-real', EXA_API_KEY: 'not-real', CUSTOM_VALUE: 'value', https_proxy: 'http://proxy' });
  assert.equal(env.HOME, '/tmp/home');
  assert.equal(env.CUSTOM_VALUE, 'value');
  for (const key of ['BASH_ENV', 'NODE_OPTIONS', 'CLIPROXYAPI_API_KEY', 'EXA_API_KEY', 'https_proxy']) assert.equal(env[key], undefined);
  assert.ok(!env.PATH.split(':').includes('.'));
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
