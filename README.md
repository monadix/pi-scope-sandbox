# pi-scope-sandbox

A Linux-first, fail-closed Bash sandbox adapter for Pi 1.2 and
`@gotgenes/pi-permission-system` 40.2.x. The permission system owns decisions;
its configured context-aware authorizer owns model review. This extension makes
no model calls and has no approval policy engine of its own.

**Development status:** local prototype. Do not install it into your production
Pi configuration until its checks pass and its threat model fits your workflow.
It has not been published or enabled by this implementation task.

## How it works

- Replaces Pi's `bash` with Bubblewrap-backed execution. Other built-in tools
  retain the permission system's path gates; they are not OS-sandboxed by this
  extension.
- Root filesystem is read-only; the workspace is writable by default. Each
  invocation has private writable `/tmp` and `/var/tmp`, with an ephemeral HOME.
- Networking is isolated by default. Runtime credentials are not passed in the
  command environment. Shell startup files are not sourced.
- Existing sensitive home locations (SSH, GnuPG, AWS, sops and the Pi agent
  directory), host `/run`, and the Nix daemon socket are hidden from Bash.
  `.pi`, existing root-level Git hooks/config, and this extension's code are
  write-protected. A missing `.pi` directory is created as an empty host mountpoint
  before a writable directory is exposed; it remains between calls to avoid
  concurrent-mount cleanup races. A symlinked `.pi` blocks execution.
- An optional `writeRoot` or `network: true` on Bash triggers a nested
  `scope_sandbox_authorize` call through Pi's public `ctx.executeTool` API. That
  call goes through the normal permission hooks, authorizer chain and human
  fallback. Only after it succeeds does this exact Bash invocation execute with
  the extra scope. No persistent grant, token, replay, or unsandboxed fallback.
- The permission service must exist in the executing session. A policy query or
  a permission event is never treated as approval. Scope requests do not execute
  commands, and obtaining a standalone scope-tool response grants no future call.
- The host backend and shell are resolved to canonical executables at session
  initialization, never selected afresh from an agent-modifiable PATH. The backend
  must be outside the workspace; its directory cannot be granted writable. Its
  captured file identity is checked before launch.
- Configuration/initialization failure blocks execution. Nonzero command results
  are returned normally, without retry. Abort/timeout kills the process group.
- `!`/`!!` user-shell execution is blocked because it bypasses normal tool gates;
  use the agent's Bash tool or an ordinary terminal instead.

## Development and tests

Use Nix to supply missing dependencies (there is no project flake):

```sh
nix shell nixpkgs#nodejs_24 nixpkgs#bubblewrap
npm install --ignore-scripts --legacy-peer-deps
npm test
npm run test:native
npm run test:pi
```

Native tests exercise real Bubblewrap, filesystem and network isolation, private
scratch directories, environment filtering and process cleanup. They require
working unprivileged user namespaces; explicitly invoking `test:native` must fail,
not silently pass, if enforcement is unavailable. `test:pi` loads the extension
and permission system in an isolated, model-free SDK session. No production
configuration, credentials, inference calls, installs into Pi, or activation are
part of the tests.

## Installation and configuration

Install the permission system and one compatible context-aware authorizer as
trusted user-level Pi packages, then load this directory as a package. For a Nix
setup, package the directory immutably and provide its host peers from the same
Pi runtime. The package manager must make the declared peers resolvable; do not
bundle a second Pi runtime.

Do **not** load `@fadouse/pi-permission`, another Bash wrapper, or a second
sandbox adapter alongside this one. Remove the old permission/sandbox wrapper
before enabling the new stack; do not enable two independent decision engines.
No Home Manager or active Pi settings are changed automatically.

Example permission-system rules (merge into your existing policy rather than
replacing it):

```json
{
  "authorizerChain": ["auto-review"],
  "permission": {
    "bash": "ask",
    "scope_sandbox_authorize": "ask"
  }
}
```

`auto-review` is the mzwing authorizer's name; another authorizer has its own name.
Scope decisions also traverse the normal `path`/`external_directory` gates. The
permission system may require a human for those surfaces even after a model allow.
Configure native file-tool restrictions separately: this is not a replacement for
permission-system's path policy.

Only trusted global configuration is read:
`~/.pi/agent/extensions/pi-scope-sandbox/config.json` (respects
`PI_CODING_AGENT_DIR`). Project files cannot loosen the sandbox. Defaults:

```json
{
  "mode": "workspace-write",
  "writeRoots": [],
  "denyRead": [],
  "envAllow": [],
  "network": false
}
```

- `mode`: `workspace-write` or `read-only`; both permit disposable scratch writes.
- `writeRoots`: additional existing absolute writable directories, selected by the
  operator. `read-only` mode does not enable these baseline write roots.
- `denyRead`: additional existing absolute paths to hide; does not remove defaults.
- `envAllow`: explicitly pass additional environment variables. Never put secrets
  here without understanding that Bash and descendants can read/exfiltrate them.
  Shell/loader injection variables are rejected.
- `network`: full host networking for all calls when true, not a domain allowlist.
- `childExtensions`: optional existing absolute extension entry files to require
  in native children as well (for example, your contextual authorizer). They are
  trusted operator configuration, never selected by the model.
- Optional `bwrap` and `shell`: trusted absolute executable paths (useful in Nix).

Reload/new session is needed to apply configuration. Invalid config blocks Bash.
`/scope-sandbox` displays the policy without modifying it. To edit an external
checkout, request `writeRoot` as that checkout's exact directory. Roots overlapping
system directories, the home root, hidden paths, the backend location or
extension/security directories are rejected even if an authorizer would allow
them. Workspace/write roots cannot equal or contain `/tmp` or `/var/tmp`, because
that would cover private scratch mounts. Nested roots such as `/tmp/project`
remain supported.

## Boundaries and limitations

This is confinement of agent-issued **Bash**, not of the Pi host. Trusted
extensions, MCP implementations, native file tools and child initialization run
with host privileges. The permission system must gate those other tools. The root
filesystem is generally readable except for explicit masks; this is not complete
secret-read isolation or a data-loss-prevention boundary. Unix sockets outside
masked locations and explicitly permitted network services remain capabilities.

Network exceptions enable all host networking for one command; no per-domain
broker is implemented. Static deny masks are path-based and do not discover all
hardlink aliases. Scope checks are not a defense against a hostile external
process racing changes to host filesystem topology.

For `pi-subagents` 0.78.x, the adapter registers itself and the permission system
through the public required-child-extensions API, with
`requireForAllRunners: true`. Native child launches must carry those extensions;
unsupported external runners/machines are rejected by pi-subagents. Missing or
incompatible registration blocks the `subagent` tool instead of silently launching
unprotected workers. Lifecycle teardown disposes the registration. No fixed agent
whitelist or Bash-only child-tool ceiling is imposed by this adapter.

Use `childExtensions` to require your contextual authorizer when ambient child
extensions are disabled; otherwise an ask may fail closed in a headless child.
Permission forwarding depends on the permission system's supported child adapter
and is not implemented here. Other delegation tools are not covered. Whole-process
child sandboxing is also not implemented: child Bash is contained, but native file
tools still depend on permission gates. Registration is tested against the real
public API; a paid, end-to-end multi-agent workflow has not been run.

Host daemon IPC (including Nix builds through the host daemon) is deliberately
unavailable in the default Bash sandbox. This extension has no host-execution
escape hatch. Run such operations from your terminal or separately design an
explicit trusted broker rather than automatically retrying failed commands.

## Attribution

The Linux sandbox execution approach is adapted from `@fadouse/pi-permission`
0.1.2 (MIT), particularly `src/sandbox.js` and its Bash operations integration.
The authorization flow uses the public Pi nested-tool API and the permission
system's ordinary tool gates; no private authorizer invocation is used.
See `LICENSE` for attribution and terms.
