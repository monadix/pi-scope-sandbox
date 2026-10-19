import { accessSync, constants, existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { delimiter, dirname, isAbsolute, join, parse, resolve, sep } from 'node:path';

export const PACKAGE_NAME = 'pi-scope-sandbox';
export const GRANT_TOOL = 'scope_sandbox_authorize';
export const HOST_GRANT_TOOL = 'scope_host_authorize';
const EXECUTION_ENV = /^(?:BASH_ENV|ENV|SHELLOPTS|BASHOPTS|BASH_XTRACEFD|PS4|LD_.*|DYLD_.*|NODE_OPTIONS|NODE_PATH|PYTHONPATH|PYTHONHOME|PERL5OPT|RUBYOPT|GCONV_PATH|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS)$/;
const RESERVED_ENV = /^(?:HOME|PATH|TMPDIR|TMP|TEMP)$/;
const ENV_NAME = /^[A-Z_a-z][A-Z_a-z0-9]*$/;
export const executableIdentity = path => {
  const stat = statSync(path);
  return Object.freeze(Object.fromEntries(['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs', 'mode'].map(key => [key, stat[key]])));
};
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
  const allowed = ['mode', 'writeRoots', 'denyRead', 'envAllow', 'network', 'allowHost', 'bwrap', 'shell', 'childExtensions'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(k => !allowed.includes(k))) {
    throw new Error('Invalid sandbox configuration (unknown field or non-object)');
  }
  if (raw.mode !== undefined && !['workspace-write', 'read-only'].includes(raw.mode)) throw new Error('Invalid sandbox mode');
  for (const key of ['network', 'allowHost']) {
    if (raw[key] !== undefined && typeof raw[key] !== 'boolean') throw new Error(`${key} must be boolean`);
  }
  for (const key of ['writeRoots', 'denyRead', 'envAllow', 'childExtensions']) {
    if (raw[key] !== undefined && (!Array.isArray(raw[key]) || raw[key].some(p => typeof p !== 'string' || !p))) {
      throw new Error(`${key} must be an array of nonempty strings`);
    }
  }
  for (const key of ['bwrap', 'shell']) {
    if (raw[key] !== undefined && (typeof raw[key] !== 'string' || !isAbsolute(raw[key]))) throw new Error(`${key} must be absolute`);
  }
  const envAllow = raw.envAllow ?? [];
  if (envAllow.some(k => !/^[A-Z_a-z][A-Z_a-z0-9]*$/.test(k) || EXECUTION_ENV.test(k) || /^(?:HOME|TMPDIR|TMP|TEMP|PATH)$/.test(k))) {
    throw new Error('envAllow contains an invalid or execution-control variable');
  }
  if ((raw.denyRead ?? []).some(p => !isAbsolute(p) || !existsSync(p))) throw new Error('denyRead paths must be existing absolute paths');
  // Select the host executable before any agent command can plant a PATH shadow.
  // Its backing directory must never be exposed through a writable scope.
  const bwrap = executable(raw.bwrap ?? 'bwrap');
  const shell = executable(raw.shell ?? 'bash');
  const bwrapIdentity = executableIdentity(bwrap);
  const shellIdentity = executableIdentity(shell);
  const protectedRoots = [agentDir, sourceDir, dirname(bwrap), dirname(shell)].map(p => realpathSync(p));
  const denyRead = [...new Set([
    agentDir, join(home, '.ssh'), join(home, '.gnupg'), join(home, '.aws'), join(home, '.config/sops'),
    '/run', '/nix/var/nix/daemon-socket', ...(raw.denyRead ?? []),
  ].filter(p => existsSync(p)).map(p => realpathSync(p)))];
  const config = {
    mode: raw.mode ?? 'workspace-write', network: raw.network ?? false, allowHost: raw.allowHost ?? false,
    writeRoots: (raw.writeRoots ?? []).map(directory), denyRead, operatorDenyRead: (raw.denyRead ?? []).map(p => realpathSync(p)), protectedRoots,
    envAllow, home: realpathSync(home), bwrap, shell, bwrapIdentity, shellIdentity,
    childExtensions: (raw.childExtensions ?? []).map(path => {
      if (!isAbsolute(path) || !statSync(path).isFile()) throw new Error('childExtensions must name existing absolute module files');
      return realpathSync(path);
    }),
  };
  for (const root of config.writeRoots) checkWriteRoot(root, config);
  return Object.freeze(config);
}

export function resourcePath(path, config, kind) {
  if (typeof path !== 'string' || !isAbsolute(path) || !existsSync(path)) throw new Error('Scoped resources must be existing absolute paths');
  const canonical = realpathSync(path);
  if (['/tmp', '/var/tmp'].some(root => contains(canonical, root))) throw new Error('Scoped resource overlaps reserved private scratch mounts');
  if (['/proc', '/dev'].some(root => contains(root, canonical) || contains(canonical, root))) throw new Error('Scoped resource overlaps private virtual filesystem mounts');
  const stat = statSync(canonical);
  if (kind === 'read' && !(stat.isFile() || stat.isDirectory())) throw new Error('Read scopes must name existing files or directories');
  if (kind === 'write' && !(stat.isFile() || stat.isDirectory())) throw new Error('Write scopes must name existing files or directories');
  if (kind === 'socket' && !stat.isSocket()) throw new Error('Unix socket scopes must name existing AF_UNIX sockets');
  if (config.operatorDenyRead.some(root => contains(root, canonical) || contains(canonical, root))) throw new Error('Operator denyRead blocks granular access');
  if (kind === 'read' && stat.isDirectory() && config.denyRead.some(root => root !== canonical && contains(canonical, root))) throw new Error('Read directory would contain masked descendants');
  if (kind === 'write') {
    if (config.protectedRoots.some(root => contains(root, canonical) || contains(canonical, root))) throw new Error('Scoped resource overlaps a protected path');
    if (config.denyRead.some(root => contains(root, canonical) || contains(canonical, root))) throw new Error('Scoped resource overlaps a hidden path');
    if (canonical === '/' || ['/etc', '/bin', '/sbin', '/usr', '/nix', '/proc', '/dev', '/run', '/boot'].some(root => contains(root, canonical) || contains(canonical, root))) throw new Error('Scoped resource overlaps a protected or system path');
    if (path.split(sep).includes('.pi') || canonical.split(sep).includes('.pi')) throw new Error('Scoped resource overlaps protected .pi metadata');
    if (contains(canonical, config.home)) throw new Error('Scoped resource overlaps the home root');
    if (protectedGitGrant(canonical) || protectedGitGrant(canonical, path)) throw new Error('Scoped resource overlaps protected Git config or hooks');
  }
  return canonical;
}

export function resourceType(path) {
  const stat = statSync(realpathSync(path));
  return stat.isFile() ? 'file' : stat.isDirectory() ? 'directory' : stat.isSocket() ? 'socket' : 'other';
}

export function normalizeScopes(input, config) {
  const resourceTypes = [];
  const list = (key, kind) => {
    const values = input[key] ?? [];
    if (!Array.isArray(values)) throw new Error(`${key} must be an array`);
    const paths = [...new Set(values.map(path => resourcePath(path, config, kind)))].sort();
    for (const path of paths) resourceTypes.push({ path, kind, type: resourceType(path) });
    return paths;
  };
  const env = input.env ?? [];
  if (!Array.isArray(env) || env.some(name => typeof name !== 'string' || !ENV_NAME.test(name) || EXECUTION_ENV.test(name) || RESERVED_ENV.test(name))) {
    throw new Error('env contains an invalid or execution-control variable name');
  }
  return { readPaths: list('readPaths', 'read'), writePaths: list('writePaths', 'write'), unixSockets: list('unixSockets', 'socket'), env: [...new Set(env)].sort(), resourceTypes: resourceTypes.sort((a, b) => `${a.kind}:${a.path}`.localeCompare(`${b.kind}:${b.path}`)) };
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

export function safeEnvironment(config, env = process.env, scopedNames = []) {
  const result = { HOME: '/tmp/home', TMPDIR: '/tmp', TMP: '/tmp', TEMP: '/tmp', LANG: 'C.UTF-8' };
  result.PATH = [...new Set((env.PATH ?? '').split(delimiter).filter(isAbsolute).flatMap(p => {
    try { return [realpathSync(p)]; } catch { return []; }
  }))].join(delimiter);
  for (const key of ['TERM', 'TZ', 'LANG', 'LC_ALL', 'SSL_CERT_FILE', 'NIX_SSL_CERT_FILE', ...config.envAllow, ...scopedNames]) {
    if (typeof env[key] === 'string') result[key] = env[key];
  }
  return result;
}

// Host approval includes the host environment, but not implicit loader/startup execution.
export function hostEnvironment(env = process.env) {
  return Object.fromEntries(Object.entries(env).filter(([key, value]) => typeof value === 'string' && !EXECUTION_ENV.test(key)));
}

function protectedGitGrant(canonicalPath, originalPath = canonicalPath) {
  let current = originalPath;
  while (true) {
    const marker = join(current, '.git');
    if (existsSync(marker)) {
      let git = marker;
      if (statSync(marker).isFile()) {
        const match = /^gitdir: (.+)\s*$/m.exec(readFileSync(marker, 'utf8'));
        if (match) git = resolve(dirname(marker), match[1]);
      }
      const metadataRoot = realpathSync(git);
      const protectedPaths = [join(metadataRoot, 'config'), join(metadataRoot, 'hooks')].filter(existsSync).map(path => realpathSync(path));
      if (canonicalPath === metadataRoot || protectedPaths.some(protectedPath => contains(protectedPath, canonicalPath))) return true;
    }
    const parent = dirname(current);
    if (parent === current) return false;
    current = parent;
  }
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
