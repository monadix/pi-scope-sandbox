import { spawn } from 'node:child_process';
import { lstat, mkdtemp, mkdir, rm } from 'node:fs/promises';
import { realpathSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checkWriteRoot, contains, directory, hostEnvironment, normalizeScopes, protectedWritePaths, safeEnvironment } from './config.mjs';

function validateResourceTypes(scope, granular) {
  if (scope.resourceTypes === undefined) return;
  const expected = [...granular.resourceTypes, ...(scope.path ? [{ path: scope.path, kind: 'writeRoot', type: 'directory' }] : [])]
    .sort((a, b) => `${a.kind}:${a.path}`.localeCompare(`${b.kind}:${b.path}`));
  if (JSON.stringify(scope.resourceTypes) !== JSON.stringify(expected)) throw new Error('Scoped resource types changed after approval');
}

function checkExecutable(path, identity, label) {
  try {
    const current = statSync(path);
    if (!identity || realpathSync(path) !== path || Object.entries(identity).some(([key, value]) => current[key] !== value)) throw new Error('identity changed');
  } catch { throw new Error(`Pinned ${label} changed or is unavailable`); }
}

export function planHost(config, cwd, command) {
  if (!config.allowHost) throw new Error('Host escalation is disabled by trusted global configuration');
  if (typeof command !== 'string' || !command.trim() || command.length > 16384 || command.includes('\0')) throw new Error('Invalid or oversized sandbox command');
  checkExecutable(config.shell, config.shellIdentity, 'host shell');
  return { file: config.shell, args: ['--noprofile', '--norc', '-c', command], env: hostEnvironment(), cwd: directory(cwd) };
}

export function plan(config, cwd, command, scope = {}, temp) {
  if (scope.host) throw new Error('Host execution must not use a sandbox profile');
  if (process.platform !== 'linux') throw new Error('pi-scope-sandbox currently supports Linux only');
  if (typeof command !== 'string' || !command.trim() || command.length > 16384 || command.includes('\0')) throw new Error('Invalid or oversized sandbox command');
  cwd = directory(cwd);
  if (contains(cwd, config.bwrap)) throw new Error('Sandbox backend must be outside the workspace, including read-only workspaces');
  if (['/tmp', '/var/tmp'].some(path => contains(cwd, path))) throw new Error('Workspace would cover reserved private scratch mounts');
  if (config.denyRead.some(root => contains(root, cwd)) || ['/proc', '/dev', '/run'].some(root => contains(root, cwd))) {
    throw new Error('Workspace is inside a hidden or reserved sandbox path');
  }
  const roots = config.mode === 'workspace-write' ? [checkWriteRoot(cwd, config), ...config.writeRoots] : [];
  if (scope.path) roots.push(checkWriteRoot(scope.path, config));
  const granular = normalizeScopes(scope, config);
  validateResourceTypes(scope, granular);
  const granularDirectories = granular.writePaths.filter(path => statSync(path).isDirectory()).map(path => checkWriteRoot(path, config));
  const network = config.network || scope.network === true;
  const args = [
    '--die-with-parent', '--unshare-all', '--new-session', '--cap-drop', 'ALL',
    '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev', '--bind', temp, '/tmp',
    '--tmpfs', '/var/tmp', '--dir', '/tmp/home',
  ];
  if (network) args.push('--share-net');
  // A private /tmp hides a workspace below host /tmp; mount it back explicitly.
  args.push('--ro-bind', cwd, cwd);
  for (const root of [...new Set(roots)]) args.push('--bind', root, root);
  const maskedDirectories = [];
  for (const path of config.denyRead) {
    if (statSync(path).isDirectory()) { args.push('--tmpfs', path); maskedDirectories.push(path); }
    else args.push('--ro-bind', '/dev/null', path);
  }
  // Re-create only the empty parent chain beneath a masked ancestor; exact
  // resource binds below never expose masked siblings or grant parent writes.
  const grants = [...granular.readPaths.map(path => [path, 'read']), ...granular.writePaths.map(path => [path, 'write']), ...granular.unixSockets.map(path => [path, 'socket'])];
  for (const [path] of grants) {
    const ancestor = config.denyRead.filter(root => contains(root, path) && root !== path).sort((a, b) => b.length - a.length)[0];
    if (ancestor) {
      const pieces = path.slice(ancestor.length).split('/').filter(Boolean);
      let parent = ancestor;
      for (const piece of pieces.slice(0, -1)) { parent = join(parent, piece); args.push('--dir', parent); }
    }
  }
  for (const [path, kind] of grants) args.push(kind === 'write' ? '--bind' : '--ro-bind', path, path);
  for (const path of protectedWritePaths([cwd, ...roots, ...granularDirectories], config)) {
    if (!config.denyRead.some(root => contains(root, path))) args.push('--ro-bind', path, path);
  }
  for (const path of maskedDirectories) args.push('--remount-ro', path);
  args.push('--chdir', cwd, '--', config.shell, '--noprofile', '--norc', '-c', command);
  checkExecutable(config.bwrap, config.bwrapIdentity, 'sandbox backend');
  checkExecutable(config.shell, config.shellIdentity, 'host shell');
  return { file: config.bwrap, args, env: safeEnvironment(config, process.env, granular.env), cwd };
}

export function spawnSandbox(invocation, { signal, timeout, onData = () => {} } = {}) {
  if (signal?.aborted) return Promise.reject(new Error('Sandbox command aborted'));
  if (timeout !== undefined && (!Number.isFinite(timeout) || timeout <= 0)) return Promise.reject(new Error('timeout must be positive'));
  return new Promise((resolve, reject) => {
    let child, timer, aborted = false, timedOut = false, finished = false;
    const kill = () => {
      if (!child?.pid) return;
      try { process.kill(-child.pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch {} }
    };
    const abort = () => { aborted = true; kill(); };
    const finish = (error, code) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      kill();
      if (error) reject(error);
      else if (aborted) reject(new Error('Sandbox command aborted'));
      else if (timedOut) reject(new Error(`Sandbox command timed out after ${timeout}s`));
      else resolve({ exitCode: code });
    };
    try {
      child = spawn(invocation.file, invocation.args, { cwd: invocation.cwd, env: invocation.env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (error) { finish(error); return; }
    child.stdout.on('data', data => { try { onData(data); } catch (error) { kill(); finish(error); } });
    child.stderr.on('data', data => { try { onData(data); } catch (error) { kill(); finish(error); } });
    child.once('error', error => finish(new Error(`Sandbox process failed to start (${error.code ?? 'unknown'})`)));
    child.once('close', code => finish(undefined, code));
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    if (timeout !== undefined) timer = setTimeout(() => { timedOut = true; kill(); }, timeout * 1000);
  });
}

export async function runSandbox(config, cwd, command, scope = {}, options = {}) {
  if (options.signal?.aborted) throw new Error('Sandbox command aborted');
  if (scope.host === true) {
    if (scope.path !== undefined) throw new Error('Host escalation cannot be combined with a write-root scope');
    return spawnSandbox(planHost(config, cwd, command), options);
  }
  // Mounting a missing path below a writable bind needs a host mountpoint.
  // Keep this empty directory between calls: deleting it would race a sibling
  // sandbox. Never follow a project .pi symlink into an unprotected alias.
  const granular = normalizeScopes(scope, config);
  validateResourceTypes(scope, granular);
  const roots = [
    ...(config.mode === 'workspace-write' ? [cwd, ...config.writeRoots] : []),
    ...(scope.path ? [scope.path] : []),
    ...granular.writePaths.filter(path => statSync(path).isDirectory()),
  ].map(path => checkWriteRoot(path, config));
  for (const root of new Set(roots)) {
    const metadata = join(root, '.pi');
    try { await mkdir(metadata, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    const stat = await lstat(metadata);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Sandbox requires .pi to be a real directory, not a symlink or file');
  }
  const temp = await mkdtemp(join(tmpdir(), 'pi-scope-sandbox-'));
  try {
    await mkdir(join(temp, 'home'), { mode: 0o700 });
    return await spawnSandbox(plan(config, cwd, command, scope, temp), options);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
}
