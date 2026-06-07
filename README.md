# pi-claude-permissions

![pi-claude-permissions gallery preview](./gallery.png)

Claude-style permissions for [pi](https://pi.dev), with configurable mode cycling.

This is my personal favorite permission cycling setup. Most of the time I run in `bypassPermissions`, or start work in `default` mode and let the agent execute once things look good. If you prefer silent operation, `acceptEdits` allows writes without prompting.

This is heavily based on and inspired by [`rHedBull/pi-permissions`](https://github.com/rHedBull/pi-permissions). Big shoutout to rHedBull for the original Claude Code-style permission workflow and safety checks. This version stays close to the Claude-style permission experience, defaults to bypass, uses `Shift+Tab`, supports `/permissions`.

## What is different?

- **Three modes**:
  - `default`
  - `acceptEdits`
  - `bypassPermissions`
- **No plan mode**.
- **No `fullAuto` mode**.
- **`bypassPermissions` is the startup default**.
- **Configurable `Shift+Tab` cycle**.
- **`/permissions` always shows all modes** for manual selection.

## Installation

From npm:

```bash
pi install npm:@zackify/pi-claude-permissions
```

Or from GitHub:

```bash
pi install git:github.com/zackify/pi-claude-permissions
```

## Modes

### `default`

Confirmation mode.

- Prompts before every tool call.
- Keeps session-level approvals for prompted operations.
- Still blocks protected paths and catastrophic commands.

### `acceptEdits`

- Allows `write` and `edit` automatically.
- Prompts for bash commands.
- Still blocks protected paths and catastrophic commands.

### `bypassPermissions`

- Allows normal operations without confirmation.
- Still blocks catastrophic commands and protected paths.
- This is the default mode.

## Shortcut and command

By default, `Shift+Tab` cycles all modes:

```text
default → acceptEdits → bypassPermissions → default
```

Use `/permissions` to manually select any mode at any time. If you rarely use one of the modes, set `piClaudePermissions.shiftTabOptions` to keep your `Shift+Tab` cycle faster; `/permissions` will still show all modes.

## Configuration

Set this in `~/.pi/agent/settings.json` or project-local `.pi/settings.json`:

```json
{
  "piClaudePermissions": {
    "defaultMode": "bypassPermissions",
    "allowCatastrophic": false,
    "shiftTabOptions": ["default", "acceptEdits", "bypassPermissions"]
  }
}
```

`defaultMode` controls the startup mode and defaults to `bypassPermissions`. Valid values are `default`, `acceptEdits`, and `bypassPermissions`.

`allowCatastrophic` defaults to `false`. When set to `true`, catastrophic command blocking and critical `rm -rf` detection are allowed. Protected path checks still run.

`shiftTabOptions` defaults to all modes. Valid values are `default`, `acceptEdits`, and `bypassPermissions`. This only changes the `Shift+Tab` cycle; `/permissions` still lists every mode.

## Tool permissions (in `settings.json`)

Beyond modes, you can fine-tune per-tool behavior via the `piClaudePermissions.toolPermissions`
key in **`.pi/settings.json`** (project-local) or **`~/.pi/agent/settings.json`** (global).
Each entry uses the format `toolName:pattern` (e.g., `read:*`, `bash:git.*`) where `*` matches any substring.

| Field | Description |
|-------|-------------|
| `defaultAction` | Fallback when no rule matches (`"allow"` or `"deny"`). Defaults to `"deny"`. |
| **`autoallow`** | Auto-approve across all modes. |
| **`autodeny`** | Always block regardless of active mode. |

Example `.pi/settings.json`:

```json
{
  "piClaudePermissions": {
    "toolPermissions": {
      "defaultAction": "deny",
      "autoallow": ["read:*", "find:**/node_modules/**"],
      "autodeny": ["bash:sudo rm -rf", "write:~/.ssh/*"]
    }
  }
}
```

## Safety checks kept from the inspiration plugin

This keeps the useful always-on protections from `rHedBull/pi-permissions`:

- catastrophic command blocking (unless `piClaudePermissions.allowCatastrophic` is `true`)
- critical `rm -rf` detection (unless `piClaudePermissions.allowCatastrophic` is `true`)
- protected path checks
- session-level approvals for prompted operations

## Files

The active local pi extension lives at:

```text
~/.pi/agent/extensions/pi-claude-permissions.ts
```

This repository copy lives at:

```text
~/Projects/pi/pi-claude-permissions/extensions/index.ts
```

After editing this copy, sync it back to pi with:

```bash
cp ~/Projects/pi/pi-claude-permissions/extensions/index.ts ~/.pi/agent/extensions/pi-claude-permissions.ts
```

Then reload pi with `/reload` or restart pi.
