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

  test('explicit host execution can write outside the sandbox without persisting the grant', async t => {
    const f = fixture(t, { allowHost: true }, process.cwd());
    const marker = join(f.external, 'host-write');
    const command = `printf host > ${quote(marker)}`;
    assert.notEqual((await capture(f, command)).exitCode, 0);
    const allowed = await capture(f, command, { host: true });
    assert.equal(allowed.exitCode, 0, allowed.output);
    assert.equal(readFileSync(marker, 'utf8'), 'host');
    assert.notEqual((await capture(f, command)).exitCode, 0);
  });

  test('explicit host execution can reach a masked mock Unix service, baseline still cannot', async t => {
    const f = fixture(t, { allowHost: true }, process.cwd());
    const socketPath = join(f.agent, 'mock-service.sock');
    let connections = 0;
    const server = createServer(socket => { connections++; socket.on('error', () => {}); socket.end(); });
    await new Promise(resolve => server.listen(socketPath, resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const script = `const c=require('node:net').connect(${JSON.stringify(socketPath)});c.on('error',()=>process.exit(11));c.on('connect',()=>{process.stdout.write('connected');c.end();});`;
    const command = `${quote(process.execPath)} -e ${quote(script)}`;
    assert.notEqual((await capture(f, command)).exitCode, 0);
    assert.equal(connections, 0);
    const allowed = await capture(f, command, { host: true });
    assert.equal(allowed.exitCode, 0, allowed.output);
    assert.match(allowed.output, /connected/);
    assert.equal(connections, 1);
    assert.notEqual((await capture(f, command)).exitCode, 0);
    assert.equal(connections, 1);
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

  test('real Bubblewrap: granular files and directories under home remain usable', async t => {
    const f = fixture(t, {}, process.cwd());
    const project = join(f.home, 'project');
    const report = join(project, 'report.txt');
    const checkout = join(f.home, 'other-checkout');
    mkdirSync(project);
    writeFileSync(report, 'before');
    mkdirSync(checkout);
    let result = await capture(f, `printf updated > ${quote(report)}`, { writePaths: [report] });
    assert.equal(result.exitCode, 0, result.output);
    assert.equal(readFileSync(report, 'utf8'), 'updated');
    result = await capture(f, `printf created > ${quote(join(checkout, 'new.txt'))}`, { writePaths: [checkout] });
    assert.equal(result.exitCode, 0, result.output);
    assert.equal(readFileSync(join(checkout, 'new.txt'), 'utf8'), 'created');
    await assert.rejects(capture(f, 'true', { writePaths: [f.home] }), /home root/);
    mkdirSync(join(f.home, '.ssh'));
    f.config = loadConfig(f.agent, f.home, f.extension, {});
    await assert.rejects(capture(f, 'true', { writePaths: [join(f.home, '.ssh')] }), /hidden path/);
  });

  test('real Bubblewrap: granular writes cannot expose external Git config or hooks', async t => {
    const f = fixture(t, {}, process.cwd());
    const git = join(f.external, '.git');
    mkdirSync(join(git, 'hooks'), { recursive: true });
    writeFileSync(join(git, 'config'), 'original-config');
    writeFileSync(join(git, 'hooks', 'pre-commit'), 'original-hook');
    for (const path of [join(git, 'config'), join(git, 'hooks'), git]) {
      await assert.rejects(capture(f, `printf BAD > ${quote(join(git, 'config'))}`, { writePaths: [path] }), /Git config or hooks/);
    }
    assert.equal(readFileSync(join(git, 'config'), 'utf8'), 'original-config');
    assert.equal(readFileSync(join(git, 'hooks', 'pre-commit'), 'utf8'), 'original-hook');
    const ordinary = join(f.external, 'report.txt');
    writeFileSync(ordinary, 'before');
    const result = await capture(f, `printf ordinary > ${quote(ordinary)}`, { writePaths: [ordinary] });
    assert.equal(result.exitCode, 0, result.output);
    assert.equal(readFileSync(ordinary, 'utf8'), 'ordinary');
  });

  test('real Bubblewrap: writable directory aliases retain .pi, Git, parent and sibling protections', async t => {
    const f = fixture(t, {}, process.cwd());
    const checkout = join(f.external, 'aliased-checkout');
    const aliasParent = join(f.agent, 'masked-parent');
    const alias = join(aliasParent, 'checkout-link');
    mkdirSync(join(checkout, '.git', 'hooks'), { recursive: true });
    mkdirSync(join(checkout, '.pi'), { recursive: true });
    mkdirSync(aliasParent);
    writeFileSync(join(checkout, '.git', 'config'), 'git-config');
    writeFileSync(join(checkout, '.git', 'hooks', 'pre-commit'), 'git-hook');
    writeFileSync(join(checkout, '.pi', 'policy'), 'pi-policy');
    writeFileSync(join(checkout, 'before'), 'before');
    writeFileSync(join(f.external, 'checkout-sibling'), 'sibling');
    symlinkSync(checkout, alias);
    f.config = loadConfig(f.agent, f.home, f.extension, {});
    const result = await capture(f,
      `printf updated > ${quote(join(alias, 'before'))} && ` +
      `! printf BAD > ${quote(join(alias, '.pi', 'policy'))} && ` +
      `! printf BAD > ${quote(join(alias, '.git', 'config'))} && ` +
      `! printf BAD > ${quote(join(alias, '.git', 'hooks', 'pre-commit'))} && ` +
      `! printf BAD > ${quote(join(aliasParent, 'parent-write'))} && ` +
      `! printf BAD > ${quote(join(f.external, 'checkout-sibling'))}`,
      { writePaths: [alias] });
    assert.equal(result.exitCode, 0, result.output);
    assert.equal(readFileSync(join(checkout, 'before'), 'utf8'), 'updated');
    assert.equal(readFileSync(join(checkout, '.pi', 'policy'), 'utf8'), 'pi-policy');
    assert.equal(readFileSync(join(checkout, '.git', 'config'), 'utf8'), 'git-config');
    assert.equal(readFileSync(join(checkout, '.git', 'hooks', 'pre-commit'), 'utf8'), 'git-hook');
    assert.equal(readFileSync(join(f.external, 'checkout-sibling'), 'utf8'), 'sibling');
  });

  test('real Bubblewrap: single-file writes reject symlinked .git and .pi metadata ancestry', async t => {
    const f = fixture(t, {}, process.cwd());
    const checkout = join(f.external, 'symlinked-checkout');
    const gitMetadata = join(f.root, 'external-git-metadata');
    const piMetadata = join(f.root, 'external-pi-metadata');
    mkdirSync(checkout);
    mkdirSync(join(gitMetadata, 'hooks'), { recursive: true });
    mkdirSync(piMetadata);
    writeFileSync(join(gitMetadata, 'config'), 'protected-config');
    writeFileSync(join(gitMetadata, 'hooks', 'pre-commit'), 'protected-hook');
    writeFileSync(join(piMetadata, 'policy'), 'protected-policy');
    symlinkSync(gitMetadata, join(checkout, '.git'));
    symlinkSync(piMetadata, join(checkout, '.pi'));
    for (const path of [join(checkout, '.git', 'config'), join(checkout, '.git', 'hooks', 'pre-commit')]) {
      await assert.rejects(capture(f, `printf BAD > ${quote(path)}`, { writePaths: [path] }), /Git config or hooks/);
    }
    const policy = join(checkout, '.pi', 'policy');
    await assert.rejects(capture(f, `printf BAD > ${quote(policy)}`, { writePaths: [policy] }), /.pi metadata/);
    assert.equal(readFileSync(join(gitMetadata, 'config'), 'utf8'), 'protected-config');
    assert.equal(readFileSync(join(gitMetadata, 'hooks', 'pre-commit'), 'utf8'), 'protected-hook');
    assert.equal(readFileSync(join(piMetadata, 'policy'), 'utf8'), 'protected-policy');
  });

  test('real Bubblewrap: precise masked read grants and single-file/directory writes do not widen siblings', async t => {
    const f = fixture(t, {}, process.cwd());
    mkdirSync(join(f.agent, 'mock-home'), { recursive: true });
    const secret = join(f.agent, 'mock-home', 'allowed.txt'), sibling = join(f.agent, 'mock-home', 'hidden.txt');
    writeFileSync(secret, 'mock-readable'); writeFileSync(sibling, 'must-stay-hidden');
    f.config = loadConfig(f.agent, f.home, f.extension, {});
    let result = await capture(f, `cat ${quote(secret)}`);
    assert.notEqual(result.exitCode, 0);
    result = await capture(f, `test "$(cat ${quote(secret)})" = mock-readable && test ! -e ${quote(sibling)} && ! printf BAD > ${quote(secret)}`, { readPaths: [secret] });
    assert.equal(result.exitCode, 0, result.output);
    assert.equal(readFileSync(secret, 'utf8'), 'mock-readable');

    const one = join(f.external, 'one.txt'), neighbor = join(f.external, 'neighbor.txt');
    writeFileSync(one, 'before'); writeFileSync(neighbor, 'neighbor');
    result = await capture(f, `printf after > ${quote(one)} && ! printf BAD > ${quote(neighbor)}`, { writePaths: [one] });
    assert.equal(result.exitCode, 0, result.output);
    assert.equal(readFileSync(one, 'utf8'), 'after');
    assert.equal(readFileSync(neighbor, 'utf8'), 'neighbor');
    mkdirSync(join(f.external, '.git', 'hooks'), { recursive: true });
    mkdirSync(join(f.external, '.pi'), { recursive: true });
    writeFileSync(join(f.external, '.git', 'config'), 'git-config');
    writeFileSync(join(f.external, '.git', 'hooks', 'pre-commit'), 'hook');
    writeFileSync(join(f.external, '.pi', 'policy'), 'policy');
    result = await capture(f, `mkdir -p ${quote(join(f.external, 'new'))} && printf created > ${quote(join(f.external, 'new', 'file'))} && ! printf BAD > ${quote(join(f.external, '.git', 'config'))} && ! printf BAD > ${quote(join(f.external, '.git', 'hooks', 'pre-commit'))} && ! printf BAD > ${quote(join(f.external, '.pi', 'policy'))}`, { writePaths: [f.external] });
    assert.equal(result.exitCode, 0, result.output);
    assert.equal(readFileSync(join(f.external, 'new', 'file'), 'utf8'), 'created');
    assert.equal(readFileSync(join(f.external, '.git', 'config'), 'utf8'), 'git-config');
    assert.equal(readFileSync(join(f.external, '.git', 'hooks', 'pre-commit'), 'utf8'), 'hook');
    assert.equal(readFileSync(join(f.external, '.pi', 'policy'), 'utf8'), 'policy');
  });

  test('real Bubblewrap: approved symlink alias beneath a masked agent directory stays exact and read-only', async t => {
    const f = fixture(t, {}, process.cwd());
    const targetDir = join(f.external, 'store');
    mkdirSync(targetDir);
    const target = join(targetDir, 'config.json');
    const sibling = join(targetDir, 'sibling.json');
    writeFileSync(target, '{"ok":true}');
    writeFileSync(sibling, 'hidden');
    const alias = join(f.agent, 'extensions', 'mock', 'config.json');
    mkdirSync(join(f.agent, 'extensions', 'mock'), { recursive: true });
    symlinkSync(target, alias);
    f.config = loadConfig(f.agent, f.home, f.extension, {});
    const command = `test "$(cat ${quote(alias)})" = '{"ok":true}' && test ! -e ${quote(join(f.agent, 'extensions', 'mock', 'sibling.json'))} && ! printf BAD > ${quote(alias)}`;
    const result = await capture(f, command, { readPaths: [alias] });
    assert.equal(result.exitCode, 0, result.output);
    assert.equal(readFileSync(target, 'utf8'), '{"ok":true}');
    assert.notEqual((await capture(f, `cat ${quote(alias)}`)).exitCode, 0, 'grant must not persist');
    assert.equal(readFileSync(sibling, 'utf8'), 'hidden');
  });

  test('real Bubblewrap: directory and Unix-socket aliases below masked parents retain exact bounds', async t => {
    const f = fixture(t, {}, process.cwd());
    const dataDir = join(f.external, 'directory');
    mkdirSync(dataDir);
    writeFileSync(join(dataDir, 'allowed'), 'yes');
    writeFileSync(join(dataDir, 'sibling'), 'no');
    const aliasParent = join(f.agent, 'parent-link');
    mkdirSync(aliasParent);
    symlinkSync(dataDir, join(aliasParent, 'directory-alias'));
    const directoryAlias = join(aliasParent, 'directory-alias');
    const socketTarget = join(f.external, 'service.sock');
    const socketAlias = join(f.agent, 'service-link.sock');
    const server = createServer(socket => socket.end());
    await new Promise(resolve => server.listen(socketTarget, resolve));
    symlinkSync(socketTarget, socketAlias);
    t.after(() => new Promise(resolve => server.close(resolve)));
    f.config = loadConfig(f.agent, f.home, f.extension, {});
    let result = await capture(f, `test "$(cat ${quote(join(directoryAlias, 'allowed'))})" = yes && test "$(cat ${quote(join(directoryAlias, 'sibling'))})" = no && test ! -e ${quote(join(aliasParent, 'sibling'))}`, { readPaths: [directoryAlias] });
    assert.equal(result.exitCode, 0, result.output);
    const script = `const c=require('node:net').connect(${JSON.stringify(socketAlias)});c.on('error',e=>{process.stdout.write(e.code);process.exit(11)});c.on('connect',()=>{process.stdout.write('connected');c.end();});`;
    result = await capture(f, `${quote(process.execPath)} -e ${quote(script)}`, { unixSockets: [socketAlias] });
    assert.equal(result.exitCode, 0, `socket alias failed: ${JSON.stringify(result)}`);
    assert.match(result.output, /connected/);
    await assert.rejects(runSandbox(f.config, f.workspace, 'true', { readPaths: [`${aliasParent}/../parent-link/directory-alias`] }), /parent traversal/);
  });

  test('real Bubblewrap: one masked Unix socket and selected variable do not expose neighbors or network', async t => {
    const f = fixture(t, {}, process.cwd());
    const socketPath = join(f.agent, 'mock-nix.sock'), neighborPath = join(f.agent, 'neighbor.sock');
    let connections = 0;
    const server = createServer(socket => { connections++; socket.end(); });
    await new Promise(resolve => server.listen(socketPath, resolve));
    const neighbor = createServer(socket => socket.end());
    await new Promise(resolve => neighbor.listen(neighborPath, resolve));
    const tcp = createServer(socket => socket.end());
    await new Promise(resolve => tcp.listen(0, '127.0.0.1', resolve));
    t.after(async () => { await Promise.all([server, neighbor, tcp].map(server => new Promise(resolve => server.close(resolve)))); });
    f.config = loadConfig(f.agent, f.home, f.extension, {});
    const oldRemote = process.env.NIX_REMOTE;
    process.env.NIX_REMOTE = 'daemon-mock';
    try {
      const script = `const n=require('node:net');const c=n.connect(${JSON.stringify(socketPath)});c.on('error',()=>process.exit(11));c.on('connect',()=>{c.end();});`;
      const networkCheck = `const c=require('node:net').connect(${tcp.address().port},'127.0.0.1');c.on('connect',()=>process.exit(12));c.on('error',()=>process.exit(0));setTimeout(()=>process.exit(13),300);`;
      const command = `${quote(process.execPath)} -e ${quote(script)} && ${quote(process.execPath)} -e ${quote(networkCheck)} && test "$NIX_REMOTE" = daemon-mock && test ! -e ${quote(neighborPath)}`;
      const result = await capture(f, command, { unixSockets: [socketPath], env: ['NIX_REMOTE'] });
      assert.equal(result.exitCode, 0, result.output);
      assert.equal(connections, 1);
      const baseline = await capture(f, `test -z "$NIX_REMOTE" && test ! -e ${quote(socketPath)}`);
      assert.equal(baseline.exitCode, 0, baseline.output);
    } finally {
      if (oldRemote === undefined) delete process.env.NIX_REMOTE; else process.env.NIX_REMOTE = oldRemote;
    }
  });

  test('real Bubblewrap: timeout terminates a background descendant', async t => {
    const f = fixture(t, {}, process.cwd());
    await assert.rejects(runSandbox(f.config, f.workspace, '(sleep 0.5; printf bad > late) & wait', {}, { timeout: 0.05 }), /timed out/);
    await new Promise(resolve => setTimeout(resolve, 650));
    assert.equal(existsSync(join(f.workspace, 'late')), false);
  });
}
