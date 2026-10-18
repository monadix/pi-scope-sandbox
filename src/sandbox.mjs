import { spawn } from 'node:child_process';
import { lstat, mkdtemp, mkdir, rm } from 'node:fs/promises';
import { realpathSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checkWriteRoot, contains, directory, protectedWritePaths, safeEnvironment } from './config.mjs';

export function plan(config, cwd, command, scope = {}, temp) {
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
  for (const path of protectedWritePaths([cwd, ...roots], config)) args.push('--ro-bind', path, path);
  for (const path of config.denyRead) {
    if (statSync(path).isDirectory()) args.push('--tmpfs', path, '--remount-ro', path);
    else args.push('--ro-bind', '/dev/null', path);
  }
  args.push('--chdir', cwd, '--', config.shell, '--noprofile', '--norc', '-c', command);
  try {
    const current = statSync(config.bwrap);
    if (realpathSync(config.bwrap) !== config.bwrap || Object.entries(config.bwrapIdentity).some(([key, value]) => current[key] !== value)) throw new Error('identity changed');
  } catch { throw new Error('Pinned sandbox backend changed or is unavailable'); }
  return { file: config.bwrap, args, env: safeEnvironment(config), cwd };
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
  // Mounting a missing path below a writable bind needs a host mountpoint.
  // Keep this empty directory between calls: deleting it would race a sibling
  // sandbox. Never follow a project .pi symlink into an unprotected alias.
  const roots = [
    ...(config.mode === 'workspace-write' ? [cwd, ...config.writeRoots] : []),
    ...(scope.path ? [scope.path] : []),
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
