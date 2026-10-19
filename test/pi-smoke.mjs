// Real Pi SDK + permission-system gates, synthetic assistant responses only.
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAssistantMessageEventStream } from '@earendil-works/pi-ai';
import { createAgentSession, DefaultResourceLoader, ModelRuntime, SessionManager, SettingsManager } from '@earendil-works/pi-coding-agent';
import { createJiti } from 'jiti';

const root = mkdtempSync(join(tmpdir(), 'scope-pi-sdk-'));
const workspace = join(root, 'workspace'), external = join(root, 'external'), agentDir = join(root, 'agent');
for (const dir of [workspace, external, agentDir, join(agentDir, 'extensions/pi-permission-system')]) mkdirSync(dir, { recursive: true });
const previous = { agent: process.env.PI_CODING_AGENT_DIR, policy: process.env.PI_PERMISSION_SYSTEM_POLICY_AGENT_DIR };
process.env.PI_CODING_AGENT_DIR = agentDir;
process.env.PI_PERMISSION_SYSTEM_POLICY_AGENT_DIR = agentDir;
process.env.PI_OFFLINE = '1';
process.env.PI_TELEMETRY = '0';
let session;
try {
  writeFileSync(join(agentDir, 'extensions/pi-permission-system/config.json'), JSON.stringify({
    authorizerChain: ['scope-offline-test'],
    permission: { '*': 'deny', bash: 'allow', scope_sandbox_authorize: 'ask', scope_host_authorize: 'ask', path: 'allow', external_directory: 'allow' },
  }));
  mkdirSync(join(agentDir, 'extensions/pi-scope-sandbox'), { recursive: true });
  writeFileSync(join(agentDir, 'extensions/pi-scope-sandbox/config.json'), JSON.stringify({ allowHost: true }));
  const jiti = createJiti(import.meta.url);
  const permissionsUrl = import.meta.resolve('@gotgenes/pi-permission-system');
  const { getPermissionsService } = await jiti.import(permissionsUrl);
  let allow = true;
  const reviewed = [];
  const settingsManager = SettingsManager.inMemory({ compaction: { enabled: false }, retry: { enabled: false }, packages: [] });
  const loader = new DefaultResourceLoader({
    cwd: workspace, agentDir, settingsManager, noExtensions: true, noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
    additionalExtensionPaths: [fileURLToPath(new URL('./index.ts', permissionsUrl)), resolve('index.ts')],
    extensionFactories: [pi => {
      const registered = new WeakSet();
      pi.events.on('permissions:ready', event => {
        const service = getPermissionsService(event.sessionId);
        if (!service || registered.has(service)) return;
        registered.add(service);
        service.registerAuthorizer('scope-offline-test', async details => {
          reviewed.push(details);
          return allow ? { kind: 'allow' } : { kind: 'deny', reason: 'offline test refused scope' };
        });
      });
    }],
  });
  await loader.reload();
  assert.deepEqual(loader.getExtensions().errors, [], 'extensions must load without errors');
  const runtime = await ModelRuntime.create({ authPath: join(agentDir, 'auth.json'), modelsPath: null, modelsStorePath: join(agentDir, 'models-cache.json'), refreshOnCreate: false, allowModelNetwork: false });
  const model = runtime.getModels()[0];
  assert.ok(model, 'static model metadata available');
  await runtime.setRuntimeApiKey(model.provider, 'offline-test-not-a-credential');
  ({ session } = await createAgentSession({ cwd: workspace, agentDir, modelRuntime: runtime, model, thinkingLevel: 'off', settingsManager, resourceLoader: loader, sessionManager: SessionManager.inMemory(workspace), tools: ['bash', 'scope_sandbox_authorize', 'scope_host_authorize'] }));
  const errors = [];
  await session.bindExtensions({ mode: 'json', onError: error => errors.push(error) });
  const { registerRequiredChildExtensions } = await jiti.import(import.meta.resolve('pi-subagents/required-child-extensions'));
  const sessionId = session.sessionManager.getSessionId();
  let probe;
  try {
    assert.throws(() => { probe = registerRequiredChildExtensions({ sessionId, extensions: [] }); }, /already registered/, 'adapter must register required child extensions via the real public API');
  } finally { probe?.dispose(); }
  let pending, sequence = 0;
  session.agent.streamFunction = () => {
    const stream = createAssistantMessageEventStream();
    const call = pending;
    pending = undefined;
    const message = {
      role: 'assistant', api: model.api, provider: model.provider, model: model.id,
      content: call ? [{ type: 'toolCall', id: call.id, name: 'bash', arguments: call.args }] : [{ type: 'text', text: 'offline test done' }],
      usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
      stopReason: call ? 'toolUse' : 'stop', timestamp: Date.now(),
    };
    stream.push({ type: 'done', reason: message.stopReason, message });
    stream.end(message);
    return stream;
  };
  async function invoke(args) {
    const id = `offline-${++sequence}`;
    pending = { id, args };
    await session.prompt('Execute the synthetic local sandbox test. No network/model request is needed.');
    const result = session.messages.findLast(message => message.role === 'toolResult' && message.toolCallId === id);
    assert.ok(result, 'root tool result must be recorded');
    return result;
  }
  let result = await invoke({ command: 'printf baseline > baseline' });
  assert.equal(result.isError, false, JSON.stringify(result.content));
  assert.equal(readFileSync(join(workspace, 'baseline'), 'utf8'), 'baseline');
  assert.equal(reviewed.length, 0);

  const quote = value => `'${value.replaceAll("'", "'\\''")}'`;
  const target = join(external, 'scoped');
  result = await invoke({ command: `printf scoped > ${quote(target)}`, writeRoot: external });
  assert.equal(result.isError, false, JSON.stringify(result.content));
  assert.equal(readFileSync(target, 'utf8'), 'scoped');
  assert.ok(reviewed.length > 0, 'nested scope request must reach real authorizer chain');
  assert.ok(result.nestedCalls?.calls.some(call => call.name === 'scope_sandbox_authorize'), 'Pi must record nested call provenance');

  allow = false;
  const denied = join(external, 'denied');
  result = await invoke({ command: `printf denied > ${quote(denied)}`, writeRoot: external });
  assert.equal(result.isError, true);
  assert.equal(existsSync(denied), false);
  const deniedHost = join(workspace, 'denied-host');
  result = await invoke({ command: `printf denied > ${quote(deniedHost)}`, host: true });
  assert.equal(result.isError, true);
  assert.equal(existsSync(deniedHost), false);

  allow = true;
  const hidden = join(agentDir, 'mock-host-resource');
  writeFileSync(hidden, 'mock-only-host-resource');
  const command = `cat ${quote(hidden)}`;
  result = await invoke({ command });
  assert.equal(result.isError, true, 'baseline must keep the agent directory masked');
  result = await invoke({ command, readPaths: [hidden] });
  assert.equal(result.isError, false, JSON.stringify(result.content));
  assert.match(JSON.stringify(result.content), /mock-only-host-resource/);
  assert.ok(result.nestedCalls?.calls.some(call => call.name === 'scope_sandbox_authorize'), 'granular resource gate must retain nested provenance');
  result = await invoke({ command });
  assert.equal(result.isError, true, 'granular grant must not persist');
  for (let i = 0; i < 2; i++) {
    const before = reviewed.length;
    result = await invoke({ command, host: true });
    assert.equal(result.isError, false, JSON.stringify(result.content));
    assert.match(JSON.stringify(result.content), /mock-only-host-resource/);
    assert.ok(reviewed.length > before, 'each host call must reach the real permission chain');
    assert.ok(result.nestedCalls?.calls.some(call => call.name === 'scope_host_authorize'));
  }
  result = await invoke({ command });
  assert.equal(result.isError, true, 'host scope must not persist');
  assert.deepEqual(errors, []);
  console.log('PASS: real Pi load, nested scope/host approval and refusal, one-call execution, baseline isolation, and nested provenance (zero model calls)');
} finally {
  if (session) {
    await session.extensionRunner.emit({ type: 'session_shutdown' });
    session.dispose();
  }
  for (const [key, value] of [['PI_CODING_AGENT_DIR', previous.agent], ['PI_PERMISSION_SYSTEM_POLICY_AGENT_DIR', previous.policy]]) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
  rmSync(root, { recursive: true, force: true });
}
