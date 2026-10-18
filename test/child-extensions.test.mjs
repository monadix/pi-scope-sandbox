import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import { packageExtensionEntries } from '../src/child-extensions.mjs';
import { fixture } from './helpers.mjs';

test('child entry paths come from a literal public Pi package manifest', t => {
  const f = fixture(t);
  const entry = join(f.extension, 'index.ts');
  writeFileSync(entry, 'export default function() {}');
  const manifest = join(f.extension, 'package.json');
  writeFileSync(manifest, JSON.stringify({ name: 'fake-permissions', pi: { extensions: ['./index.ts'] } }));
  assert.deepEqual(packageExtensionEntries('fake-permissions', pathToFileURL(entry).href), [entry]);
  writeFileSync(manifest, JSON.stringify({ name: 'fake-permissions', pi: { extensions: ['*.ts'] } }));
  assert.throws(() => packageExtensionEntries('fake-permissions', pathToFileURL(entry).href), /literal/);
  writeFileSync(manifest, JSON.stringify({ name: 'fake-permissions', pi: { extensions: ['../workspace'] } }));
  assert.throws(() => packageExtensionEntries('fake-permissions', pathToFileURL(entry).href), /Invalid/);
});
