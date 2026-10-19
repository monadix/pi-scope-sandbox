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
- Optional per-call `writeRoot`, `network: true`, `readPaths`, `writePaths`, `unixSockets`, or `env` scopes trigger nested `scope_sandbox_authorize` calls through Pi's public `ctx.executeTool` API; each filesystem resource is separately passed through the ordinary scalar `path`/`external_directory` gates. Every request also binds the complete normalized scope for that Bash call. Only after all approvals succeed does this exact call run with the extra scope. No persistent grant, token, replay, or automatic retry. `host: true` remains a separate opt-in full-host mode and cannot be mixed with granular scopes.
- The permission service must exist in the executing session. A policy query or
  a permission event is never treated as approval. Scope requests do not execute
  commands, and obtaining a standalone scope-tool response grants no future call.
- The host backend and shell are resolved to canonical executables at session
  initialization, never selected afresh from an agent-modifiable PATH. The backend
  must be outside the workspace; backend and shell directories cannot be granted
  writable. Captured executable identities are checked before launch.
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
    "scope_sandbox_authorize": "ask",
    "scope_host_authorize": "ask"
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
  "network": false,
  "allowHost": false
}
```

- `mode`: `workspace-write` or `read-only`; both permit disposable scratch writes.
- `writeRoots`: additional existing absolute writable directories, selected by the
  operator. `read-only` mode does not enable these baseline write roots.
- `denyRead`: additional existing absolute paths to hide; does not remove defaults.
- `envAllow`: operator-wide explicitly passed additional environment variables.
  Shell/loader injection and reserved HOME/PATH/temp controls are rejected.
  Per-call `env` names use the same validation and require scope approval. Approval
  requests contain names only, never environment values.
- `network`: full host networking for all sandboxed calls when true, not a domain allowlist.
- `allowHost`: allow explicit, separately permission-gated host execution requests.
  False by default; project policy cannot enable it.
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

## Granular Bash scopes

For one call, request any combination of:

```json
{
  "command": "tool --read /srv/data/item --write report.txt",
  "readPaths": ["/srv/data/item"],
  "writePaths": ["/workspace/report.txt"],
  "unixSockets": ["/run/example/service.sock"],
  "env": ["NIX_REMOTE", "SSH_AUTH_SOCK"]
}
```

Read/write resources must be existing absolute files or directories; directories
are recursive scopes, and writable directories permit creating contained files.
A writable file grant does not make its parent or siblings writable. Each exact
resource retains its requested spelling alongside its canonical identity. For a
symlink alias, both spellings independently pass the permission system's ordinary
path gates, the complete alias/target scope is bound into every approval, and the
approved target is mounted at the requested spelling without unmasking its parent
or siblings. Both spelling and target are revalidated after approval. Absolute
resource paths containing `..` are rejected rather than interpreted through
symlink-sensitive parent traversal. The `env` array grants inherited variable
names only for this call, not arbitrary values. It adds selected names to the safe baseline; it does
not expose variables whose values are unset. Once approved, selected values are
visible to Bash and descendants and may be printed or exfiltrated by the command.

Granular grants cannot overlap `/proc` or `/dev`; these are recreated as private
virtual mounts and are not exposed through host-path overrides. A Unix socket
grant must name an existing AF_UNIX socket node, not a regular file or device.
It grants the capability to communicate with that service as the Pi user;
service-side authority remains whatever the service provides. A readable
directory exposes all contained readable files, which may include IPC endpoints
or other sensitive data. These scopes are capabilities, not content scanning or
DLP. Operator `denyRead` remains a hard limit, and default masks can be opened
only by precise grants without exposing masked siblings. Granular grants cannot
include protected metadata or writable system/protected paths. For unrestricted
host-service access, use the separately gated host mode below.

## Explicit host escalation

For operations needing host services, enable `"allowHost": true` in the trusted
global sandbox config, reload Pi, and request an exact Bash call such as:

```json
{ "command": "nix build .#example", "host": true }
```

This is **unsandboxed execution**, not a narrower filesystem exemption. It runs
as the Pi process's user with the host filesystem, networking, Unix sockets and
normal host environment, including accessible credentials. The adapter does not
add `sudo`, change identity, or request root privileges. Shell startup/loader
injection variables are removed and shell profiles are not sourced. Host commands
can nevertheless modify anything that user may modify, including Pi configuration;
the sandbox's masks and write protections do not apply to them.

Keep `scope_host_authorize` on `ask` with your chosen authorizer: an `allow`
policy skips review. This distinct gate prevents an ordinary sandbox-scope approval
from authorizing host execution, and names the escalation even when input previews
are truncated. Every host invocation traverses that nested gate and binds
the exact command, canonical cwd and host scope. A standalone grant-tool call
cannot authorize a later execution. Do not combine `host` with `writeRoot`,
`network`, or granular scope parameters; host scope already includes networking.
Abort/timeout and process-group cleanup still apply. A failed sandboxed command
never automatically retries on the host. This cannot escape any outer
container/sandbox already confining the Pi process itself.

In the interactive TUI, `/scope-sandbox` reports the configured baseline and
session override. `/scope-sandbox off` asks for explicit confirmation and, only
when trusted global `allowHost` is true, selects unsandboxed host execution as
the default for subsequent Bash calls in this session. Every call still needs its
own `scope_host_authorize` approval; OFF changes execution confinement, not
authorization. Permission-system `yoloMode` can separately auto-approve asks if
the operator chooses to enable it, but this extension never changes that setting.
`/scope-sandbox on` restores the configured sandbox baseline, including
`read-only` mode. These commands do not write settings, change permission policy,
or propagate to children/new sessions; reload and each new session start
sandboxed. Headless contexts cannot change the mode. An in-flight call captures
its starting mode and is stopped if the mode changes before spawn; already-running
commands cannot be retroactively sandboxed, and ON applies to future/not-yet-started
commands. Explicit per-call `host: true` remains available while sandbox mode is
ON and still requires the separate host gate.

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

Host daemon IPC (including Nix builds through the host daemon) remains unavailable
in the default Bash sandbox. Use your terminal or the explicitly opted-in,
permission-gated host mode above; no automatic fallback is provided.

## Attribution

The Linux sandbox execution approach is adapted from `@fadouse/pi-permission`
0.1.2 (MIT), particularly `src/sandbox.js` and its Bash operations integration.
The authorization flow uses the public Pi nested-tool API and the permission
system's ordinary tool gates; no private authorizer invocation is used.
See `LICENSE` for attribution and terms.
