import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig } from '../src/config.mjs';

export function fixture(t, override = {}, base = tmpdir()) {
  const root = mkdtempSync(join(base, '.scope-fixture-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const paths = Object.fromEntries(['home', 'agent', 'extension', 'workspace', 'external', 'scratch'].map(k => [k, join(root, k)]));
  for (const path of Object.values(paths)) mkdirSync(path, { recursive: true });
  return { root, ...paths, config: loadConfig(paths.agent, paths.home, paths.extension, override) };
}

export const FakeType = {
  String: () => ({}), Boolean: () => ({}), Array: x => ({ items: x }), Optional: x => x,
  Object: properties => ({ properties }),
};
export const context = (cwd, sessionId = 'session-a') => ({
  cwd,
  sessionManager: { getSessionId: () => sessionId },
  ui: { setStatus() {}, notify() {} },
});
