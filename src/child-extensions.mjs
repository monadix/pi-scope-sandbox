import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { contains } from './config.mjs';

// Read a package's public Pi resource manifest, not its private runtime layout.
export function packageExtensionEntries(packageName, entryUrl) {
  let root = dirname(fileURLToPath(entryUrl));
  while (true) {
    const manifestPath = join(root, 'package.json');
    if (existsSync(manifestPath)) {
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
      if (manifest.name === packageName) {
        const entries = manifest.pi?.extensions;
        if (!Array.isArray(entries) || !entries.length) throw new Error('Required package has no explicit Pi extension entries');
        return entries.map(entry => {
          if (typeof entry !== 'string' || /[*?!]/.test(entry)) throw new Error('Required child extensions need literal module paths');
          const path = realpathSync(resolve(root, entry));
          if (!contains(realpathSync(root), path) || !statSync(path).isFile()) throw new Error('Invalid required child extension path');
          return path;
        });
      }
    }
    const parent = dirname(root);
    if (parent === root) throw new Error(`Could not locate public resource manifest for ${packageName}`);
    root = parent;
  }
}
