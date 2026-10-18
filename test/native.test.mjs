import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';
import test from 'node:test';
import { loadConfig } from '../src/config.mjs';
import { runSandbox } from '../src/sandbox.mjs';
import { fixture } from './helpers.mjs';

const quote = value => `'${value.replaceAll("'", "'\\''")}'`;
const capture = async (f, command, scope = {}) => {
  let output = '';
  const result = await runSandbox(f.config, f.workspace, command, scope, { onData: data => { output += data; }, timeout: 5 });
  return { ...result, output };
};

if (process.env.PI_SCOPE_NATIVE === '1') {
  test('real Bubblewrap: workspace writable, external directory readonly, scoped mount works', async t => {
    const f = fixture(t, {}, process.cwd());
    const marker = join(f.external, 'file');
    writeFileSync(marker, 'original');
    let result = await capture(f, 'printf workspace > file');
    assert.equal(result.exitCode, 0, result.output);
    assert.equal(readFileSync(join(f.workspace, 'file'), 'utf8'), 'workspace');
    result = await capture(f, `printf BAD > ${quote(marker)}`);
    assert.notEqual(result.exitCode, 0);
    assert.match(result.output, /read-only file system/i);
    assert.equal(readFileSync(marker, 'utf8'), 'original');
    result = await capture(f, `printf approved > ${quote(marker)}`, { path: f.external });
    assert.equal(result.exitCode, 0, result.output);
    assert.equal(readFileSync(marker, 'utf8'), 'approved');
    result = await capture(f, `printf BAD > ${quote(marker)}`);
    assert.notEqual(result.exitCode, 0, 'grant must not persist');
  });

  test('real Bubblewrap: a writable PATH shadow cannot replace the pinned host backend', async t => {
    const f = fixture(t, {}, process.cwd());
    const bin = join(f.workspace, 'bin');
    mkdirSync(bin);
    const oldPath = process.env.PATH;
    process.env.PATH = `${bin}:${oldPath}`;
    try {
      f.config = loadConfig(f.agent, f.home, f.extension, {});
      const pinned = f.config.bwrap;
      const marker = join(f.external, 'host-escape');
      const shadow = `#!${f.config.shell}\nprintf escaped > ${quote(marker)}\n`;
      let result = await capture(f, `printf %s ${quote(shadow)} > bin/bwrap && chmod +x bin/bwrap`);
      assert.equal(result.exitCode, 0, result.output);
      assert.notEqual(pinned, join(bin, 'bwrap'));
      result = await capture(f, 'true');
      assert.equal(result.exitCode, 0, result.output);
      assert.equal(existsSync(marker), false);
      const unsafe = loadConfig(f.agent, f.home, f.extension, { bwrap: join(bin, 'bwrap') });
      await assert.rejects(runSandbox(unsafe, f.workspace, 'true'), /protected/);
      await assert.rejects(runSandbox({ ...unsafe, mode: 'read-only' }, f.workspace, 'true'), /backend must be outside/);
      assert.equal(existsSync(marker), false);
    } finally { process.env.PATH = oldPath; }
  });

  test('real Bubblewrap: writable scopes covering host scratch are rejected', async t => {
    const f = fixture(t, {}, process.cwd());
    await assert.rejects(capture(f, 'true', { path: '/var/tmp' }), /scratch/);
    const first = await capture(f, 'printf private > /tmp/scope-not-shared');
    assert.equal(first.exitCode, 0, first.output);
    const second = await capture(f, 'test ! -e /tmp/scope-not-shared');
    assert.equal(second.exitCode, 0, second.output);
  });

  test('real Bubblewrap: read-only mode and existing security metadata stay protected', async t => {
    const f = fixture(t, { mode: 'read-only' }, process.cwd());
    let result = await capture(f, 'printf bad > file');
    assert.notEqual(result.exitCode, 0);
    mkdirSync(join(f.workspace, '.pi'), { recursive: true });
    writeFileSync(join(f.workspace, '.pi', 'policy'), 'original');
    f.config = loadConfig(f.agent, f.home, f.extension, {});
    result = await capture(f, 'printf bad > .pi/policy');
    assert.notEqual(result.exitCode, 0);
    assert.equal(readFileSync(join(f.workspace, '.pi', 'policy'), 'utf8'), 'original');
  });

  test('real Bubblewrap: missing policy directory cannot be created writable or replaced by a symlink', async t => {
    const f = fixture(t, {}, process.cwd());
    const result = await capture(f, 'printf bad > .pi/permissions.json');
    assert.notEqual(result.exitCode, 0);
    assert.equal(existsSync(join(f.workspace, '.pi', 'permissions.json')), false);
    const other = fixture(t, {}, process.cwd());
    symlinkSync(other.external, join(other.workspace, '.pi'));
    await assert.rejects(capture(other, 'true'), /real directory/);
    assert.equal(existsSync(join(other.external, 'permissions.json')), false);
  });

  test('real Bubblewrap: hidden mock credentials, scrubbed environment and private temp', async t => {
    const f = fixture(t, {}, process.cwd());
    mkdirSync(join(f.home, '.ssh'));
    writeFileSync(join(f.home, '.ssh', 'mock-key'), 'not-a-real-secret');
    f.config = loadConfig(f.agent, f.home, f.extension, {});
    let result = await capture(f, `cat ${quote(join(f.home, '.ssh', 'mock-key'))}`);
    assert.notEqual(result.exitCode, 0);
    const old = process.env.CLIPROXYAPI_API_KEY;
    process.env.CLIPROXYAPI_API_KEY = 'mock-value';
    try {
      result = await capture(f, 'test -z "$CLIPROXYAPI_API_KEY" && test "$HOME" = /tmp/home && printf scratch > /tmp/scope-private');
      assert.equal(result.exitCode, 0, result.output);
    } finally {
      if (old === undefined) delete process.env.CLIPROXYAPI_API_KEY;
      else process.env.CLIPROXYAPI_API_KEY = old;
    }
    result = await capture(f, 'test ! -e /tmp/scope-private');
    assert.equal(result.exitCode, 0);
  });

  test('real Bubblewrap: loopback network denied unless scope explicitly enables it', async t => {
    const f = fixture(t, {}, process.cwd());
    let connections = 0;
    const sockets = new Set();
    const server = createServer(socket => {
      connections++;
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
      socket.on('error', () => {});
      socket.resume();
      socket.end();
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => {
      for (const socket of sockets) socket.destroy();
      return new Promise(resolve => server.close(resolve));
    });
    const command = `printf ping > /dev/tcp/127.0.0.1/${server.address().port}`;
    const denied = await capture(f, command);
    assert.notEqual(denied.exitCode, 0, denied.output);
    assert.equal(connections, 0);
    const allowed = await capture(f, command, { network: true });
    assert.equal(allowed.exitCode, 0, allowed.output);
    assert.equal(connections, 1);
  });

  test('real Bubblewrap: timeout terminates a background descendant', async t => {
    const f = fixture(t, {}, process.cwd());
    await assert.rejects(runSandbox(f.config, f.workspace, '(sleep 0.5; printf bad > late) & wait', {}, { timeout: 0.05 }), /timed out/);
    await new Promise(resolve => setTimeout(resolve, 650));
    assert.equal(existsSync(join(f.workspace, 'late')), false);
  });
}
