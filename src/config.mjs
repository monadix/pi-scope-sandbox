import { accessSync, constants, existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { delimiter, dirname, isAbsolute, join, parse, resolve, sep } from 'node:path';

export const PACKAGE_NAME = 'pi-scope-sandbox';
export const GRANT_TOOL = 'scope_sandbox_authorize';
export const contains = (root, path) => path === root || path.startsWith(root.endsWith(sep) ? root : root + sep);

export function directory(path) {
  if (typeof path !== 'string' || !isAbsolute(path)) throw new Error('Sandbox directories must be absolute paths');
  const canonical = realpathSync(path);
  if (!statSync(canonical).isDirectory()) throw new Error('Sandbox scope must be an existing directory');
  return canonical;
}

export function executable(name, env = process.env) {
  const candidates = isAbsolute(name) ? [name] : (env.PATH ?? '').split(delimiter).filter(isAbsolute).map(p => join(p, name));
  for (const candidate of candidates) {
    try {
      accessSync(candidate, constants.X_OK);
      const path = realpathSync(candidate);
      if (statSync(path).isFile()) return path;
    } catch {}
  }
  throw new Error(`Required sandbox executable unavailable: ${name}`);
}

export function loadConfig(agentDir, home, sourceDir, override) {
  const file = join(agentDir, 'extensions', PACKAGE_NAME, 'config.json');
  const raw = override === undefined ? (existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : {}) : override;
  const allowed = ['mode', 'writeRoots', 'denyRead', 'envAllow', 'network', 'bwrap', 'shell', 'childExtensions'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(k => !allowed.includes(k))) {
    throw new Error('Invalid sandbox configuration (unknown field or non-object)');
  }
  if (raw.mode !== undefined && !['workspace-write', 'read-only'].includes(raw.mode)) throw new Error('Invalid sandbox mode');
  if (raw.network !== undefined && typeof raw.network !== 'boolean') throw new Error('network must be boolean');
  for (const key of ['writeRoots', 'denyRead', 'envAllow', 'childExtensions']) {
    if (raw[key] !== undefined && (!Array.isArray(raw[key]) || raw[key].some(p => typeof p !== 'string' || !p))) {
      throw new Error(`${key} must be an array of nonempty strings`);
    }
  }
  for (const key of ['bwrap', 'shell']) {
    if (raw[key] !== undefined && (typeof raw[key] !== 'string' || !isAbsolute(raw[key]))) throw new Error(`${key} must be absolute`);
  }
  const envAllow = raw.envAllow ?? [];
  if (envAllow.some(k => !/^[A-Z_a-z][A-Z_a-z0-9]*$/.test(k) || /^(?:BASH_ENV|ENV|SHELLOPTS|BASHOPTS|LD_.*|DYLD_.*|NODE_OPTIONS|HOME|TMPDIR|TMP|TEMP|PATH)$/.test(k))) {
    throw new Error('envAllow contains an invalid or execution-control variable');
  }
  if ((raw.denyRead ?? []).some(p => !isAbsolute(p) || !existsSync(p))) throw new Error('denyRead paths must be existing absolute paths');
  // Select the host executable before any agent command can plant a PATH shadow.
  // Its backing directory must never be exposed through a writable scope.
  const bwrap = executable(raw.bwrap ?? 'bwrap');
  const shell = executable(raw.shell ?? 'bash');
  const backendStat = statSync(bwrap);
  const bwrapIdentity = Object.freeze({ dev: backendStat.dev, ino: backendStat.ino, size: backendStat.size, mtimeMs: backendStat.mtimeMs, ctimeMs: backendStat.ctimeMs, mode: backendStat.mode });
  const protectedRoots = [agentDir, sourceDir, dirname(bwrap)].map(p => realpathSync(p));
  const denyRead = [...new Set([
    agentDir, join(home, '.ssh'), join(home, '.gnupg'), join(home, '.aws'), join(home, '.config/sops'),
    '/run', '/nix/var/nix/daemon-socket', ...(raw.denyRead ?? []),
  ].filter(p => existsSync(p)).map(p => realpathSync(p)))];
  const config = {
    mode: raw.mode ?? 'workspace-write', network: raw.network ?? false,
    writeRoots: (raw.writeRoots ?? []).map(directory), denyRead, protectedRoots,
    envAllow, home: realpathSync(home), bwrap, shell, bwrapIdentity,
    childExtensions: (raw.childExtensions ?? []).map(path => {
      if (!isAbsolute(path) || !statSync(path).isFile()) throw new Error('childExtensions must name existing absolute module files');
      return realpathSync(path);
    }),
  };
  for (const root of config.writeRoots) checkWriteRoot(root, config);
  return Object.freeze(config);
}

export function checkWriteRoot(path, config) {
  const root = directory(path);
  if (['/tmp', '/var/tmp'].some(path => contains(root, path))) throw new Error('Write scope would cover reserved private scratch mounts');
  if (root.split(sep).includes('.pi') || root === parse(root).root || contains(root, config.home) ||
      ['/etc', '/usr', '/bin', '/sbin', '/nix', '/proc', '/dev', '/run', '/boot'].some(p => contains(p, root) || contains(root, p)) ||
      config.protectedRoots.some(p => contains(root, p) || contains(p, root)) ||
      config.denyRead.some(p => contains(root, p) || contains(p, root))) {
    throw new Error('Requested write scope overlaps a protected or system directory');
  }
  return root;
}

export function safeEnvironment(config, env = process.env) {
  const result = { HOME: '/tmp/home', TMPDIR: '/tmp', TMP: '/tmp', TEMP: '/tmp', LANG: 'C.UTF-8' };
  result.PATH = [...new Set((env.PATH ?? '').split(delimiter).filter(isAbsolute).flatMap(p => {
    try { return [realpathSync(p)]; } catch { return []; }
  }))].join(delimiter);
  for (const key of ['TERM', 'TZ', 'LANG', 'LC_ALL', 'SSL_CERT_FILE', 'NIX_SSL_CERT_FILE', ...config.envAllow]) {
    if (typeof env[key] === 'string') result[key] = env[key];
  }
  return result;
}

export function protectedWritePaths(roots, config) {
  const paths = [...config.protectedRoots];
  for (const root of roots) {
    paths.push(join(root, '.pi'));
    let git = join(root, '.git');
    if (existsSync(git) && statSync(git).isFile()) {
      const match = /^gitdir: (.+)\s*$/m.exec(readFileSync(git, 'utf8'));
      if (match) git = resolve(dirname(git), match[1]);
    }
    paths.push(join(git, 'config'), join(git, 'hooks'));
  }
  return [...new Set(paths.filter(p => existsSync(p)).map(p => realpathSync(p)))];
}
