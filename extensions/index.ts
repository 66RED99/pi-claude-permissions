/**
 * Opinionated Permissions for pi
 *
 * Inspired by rHedBull/pi-permissions, trimmed down for this workflow:
 * - Shift+Tab cycles configurable modes.
 * - Default startup mode is bypassPermissions.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { homedir } from "node:os";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

type PermissionMode = string;
type Pattern = { pattern: string; description: string };
type UiContext = {
  ui: any;
  hasUI?: boolean;
  isIdle?: () => boolean;
  hasPendingMessages?: () => boolean;
  cwd?: string;
};

interface SessionAllow {
  tools: Set<string>;
  commands: Set<string>;
}

interface ToolPermissionsConfig {
  defaultAction?: "allow" | "deny";
  autoallow?: string[];
  autodeny?: string[];
}

// Compiled rule for autoallow/autodeny (applies in all modes)
interface UniversalRule {
  action: "autoallow" | "autodeny";
  toolName: string;
  pattern: string;
  isBash: boolean;
  regex: RegExp | null;
}

interface CustomModePolicy {
  excludedTools?: string[];
  allowedWriteRoots?: Array<"cwd" | "parent" | string>;
  blockedBashPatterns?: Pattern[];
  network?: {
    allowLocalhostOnly?: boolean;
    allowGithubReadOnly?: boolean;
    allowedPorts?: number[];
  };
}

interface ModeDefinition {
  id: PermissionMode;
  label: string;
  description: string;
  status: string;
  policy?: CustomModePolicy;
}

interface PermissionsConfig {
  mode?: string;
  dangerousPatterns?: Pattern[];
  catastrophicPatterns?: Pattern[];
  protectedPaths?: string[];
  allowCatastrophic?: boolean;
  shiftTabOptions?: string[];
  defaultMode?: string;
  hideDefaultMode?: boolean;
  customModes?: ModeDefinition[];
}

interface PiSettingsConfig {
  piClaudePermissions?: {
    allowCatastrophic?: boolean;
    shiftTabOptions?: string[];
    defaultMode?: string;
    hideDefaultMode?: boolean;
    customModes?: ModeDefinition[];
    toolPermissions?: ToolPermissionsConfig;
  };
}

// Module-level config error tracker — reported to user at session start when UI is available.
const _configErrors: string[] = [];

const DEFAULT_MODE: PermissionMode = "bypassPermissions";

const BUILT_IN_MODES: ModeDefinition[] = [
  { id: "default", label: "Default", description: "Ask before write/edit/bash operations", status: "⏵" },
  { id: "acceptEdits", label: "Accept Edits", description: "Allow write/edit silently, confirm bash", status: "⏵⏵" },
  { id: "bypassPermissions", label: "Bypass Permissions", description: "Allow everything except catastrophic/protected operations", status: "⏵⏵⏵⏵" },
];

const GATED_TOOLS = new Set(["write", "edit", "bash"]);

const DEFAULT_DANGEROUS: Pattern[] = [
  { pattern: "chmod -R 777", description: "insecure recursive permissions" },
  { pattern: "chown -R", description: "recursive ownership change" },
  { pattern: "> /dev/", description: "direct device write" },
];

const DEFAULT_CATASTROPHIC: Pattern[] = [
  { pattern: "sudo mkfs", description: "sudo filesystem format" },
  { pattern: "mkfs.", description: "filesystem format" },
  { pattern: "dd if=", description: "raw disk write" },
  { pattern: ":(){ :|:& };:", description: "fork bomb" },
  { pattern: "> /dev/sda", description: "overwrite disk" },
  { pattern: "> /dev/nvme", description: "overwrite disk" },
  { pattern: "sudo dd", description: "sudo raw disk operation" },
];

const CRITICAL_DIRS = [
  "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt",
  "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var",
];

const DEFAULT_PROTECTED_PATHS = [
  "~/.ssh", "~/.aws", "~/.gnupg", "~/.gpg", "~/.bashrc", "~/.bash_profile",
  "~/.profile", "~/.zshrc", "~/.zprofile", "~/.config/git/credentials",
  "~/.netrc", "~/.npmrc", "~/.docker/config.json", "~/.kube/config", "~/.pi/agent/auth.json",
];

const DEFAULT_TOOL_PERMISSIONS: ToolPermissionsConfig = {
  defaultAction: "deny",
  autoallow: ["read:*"],
  autodeny: [
    "write:.env*",
    "edit:.env*",
    "read:.env*",
    "write:*.*env*",
    "edit:*.*env*",
    "read:*.*env*",
  ],
};

export default async function permissionExtension(pi: ExtensionAPI) {
  pi.registerFlag("permission-mode", {
    description: "Permission mode (default, acceptEdits, bypassPermissions)",
    type: "string",
    default: "",
  });
  pi.registerFlag("dangerously-skip-permissions", {
    description: "Bypass all permission checks except catastrophic/protected checks",
    type: "boolean",
    default: false,
  });

  const config = await loadConfig();
  const home = homedir();
  const sessionAllow: SessionAllow = { tools: new Set(), commands: new Set() };

  // Infinite loop breaker — tracks consecutive identical bash commands
  let lastCommandKey = "";
  let consecutiveCount = 0;
  const toolPermissions = await loadToolPermissions();

  const autoDenyRules = compileUniversalRules(toolPermissions, "autodeny");
  const dangerousPatterns = config.dangerousPatterns ?? DEFAULT_DANGEROUS;
  const catastrophicPatterns = config.catastrophicPatterns ?? DEFAULT_CATASTROPHIC;
  const protectedPaths = (config.protectedPaths ?? DEFAULT_PROTECTED_PATHS).map((path) =>
    path.startsWith("~/") ? resolve(home, path.slice(2)) : resolve(path),
  );
  const allowCatastrophic = config.allowCatastrophic === true;
  const modes = buildModeDefinitions(config.customModes);
  const defaultMode = normalizeMode(config.defaultMode, DEFAULT_MODE, modes);
  const hideDefaultMode = config.hideDefaultMode === true;
  const shiftTabModes = normalizeShiftTabOptions(config.shiftTabOptions, modes);

  let mode = normalizeMode(config.mode, defaultMode, modes);

  const clearSessionAllows = () => {
    sessionAllow.tools.clear();
    sessionAllow.commands.clear();
  };

  const updateStatus = (ctx: UiContext) => {
    if (hideDefaultMode && mode === defaultMode) {
      ctx.ui.setStatus("permissions", undefined);
      return;
    }

    const meta = getModeMeta(mode, modes);
    ctx.ui.setStatus("permissions", `${meta.status} ${meta.label}`);
  };

  const applyMode = async (nextMode: PermissionMode, ctx: UiContext) => {
    mode = nextMode;
    clearSessionAllows();
    ctx.ui.notify(`Permission mode: ${getModeMeta(mode, modes).label}`, "info");
    updateStatus(ctx);
  };

  pi.on("session_start", async (_event, ctx) => {
    clearSessionAllows();

    if (pi.getFlag("dangerously-skip-permissions") === true) {
      mode = "bypassPermissions";
    } else {
      const flagMode = pi.getFlag("permission-mode");
      if (typeof flagMode === "string" && flagMode) mode = normalizeMode(flagMode, defaultMode, modes);
    }

    updateStatus(ctx);

    // Report any config parse errors to the user at session start.
    if (ctx.hasUI && _configErrors.length > 0) {
      const message = `⚠️ Configuration warnings (${_configErrors.length}):
${_configErrors.map((e, i) => `${i + 1}. ${e}`).join("\n")}`;
      ctx.ui.notify(message, "warning");
      _configErrors.length = 0; // Clear after showing
    }
  });

  pi.registerShortcut("shift+tab", {
    description: `Cycle permission mode (${shiftTabModes.map((m) => getModeMeta(m, modes).label).join(" → ")})`,
    handler: async (ctx) => {
      const idx = shiftTabModes.findIndex((m) => m === mode);
      await applyMode(shiftTabModes[(idx + 1) % shiftTabModes.length]!, ctx);
    },
  });

  pi.registerCommand("permissions", {
    description: "Select permission mode",
    handler: async (_args, ctx) => {
      if (!ctx.hasUI) {
        ctx.ui.notify("/permissions requires interactive UI", "warning");
        return;
      }

      const options = modes.map((m) => `${m.label} — ${m.description}`);
      const selected = await ctx.ui.select("Select permission mode", options);
      const idx = selected ? options.indexOf(selected) : -1;
      if (idx >= 0) await applyMode(modes[idx]!.id, ctx);
    },
  });

  pi.on("before_agent_start", async () => {
    const modeMeta = getModeMeta(mode, modes);
    if (!modeMeta.policy || !modeMeta.description) return;
    return {
      message: {
        customType: "permission-mode-context",
        content: `[${modeMeta.label.toUpperCase()} MODE ACTIVE]\n${modeMeta.description}`,
        display: true,
      },
    };
  });

  // Check for infinite loops: same exact tool call repeated 3+ times in a row (bash, read, edit, write)
  function checkLoopBreaker(toolName: string, commandOrPath: string): { block: true; reason: string } | null {
    const key = `${toolName}:${commandOrPath}`;
    if (key === lastCommandKey) {
      consecutiveCount++;
      if (consecutiveCount >= 3) {
        return { block: true, reason: `Infinite loop detected: "${commandOrPath}" repeated ${consecutiveCount} times in a row. You may be stuck — try a different approach.` };
      }
    } else {
      lastCommandKey = key;
      consecutiveCount = 1;
    }
    return null;
  }

  pi.on("tool_call", async (event, ctx) => {
    const toolName = event.toolName;

    const modeMeta = getModeMeta(mode, modes);
    const customPolicy = modeMeta.policy;
    if (!customPolicy && mode !== "default" && !GATED_TOOLS.has(toolName)) return;

    const safetyBlock = await enforceAlwaysOnSafety({
      toolName,
      input: event.input,
      ctx,
      home,
      protectedPaths,
      catastrophicPatterns,
      allowCatastrophic,
    });
    if (safetyBlock) return safetyBlock;

    // Universal autodeny — always blocks regardless of mode
    const denied = checkUniversalRules(toolName, event.input, autoDenyRules, ctx.cwd);
    if (denied === "autodeny") {
      return { block: true as const, reason: `Blocked by tool-permissions autodeny rule: ${toolName}` };
    }

    // Loop breaker — track all tools (bash, read, edit, write)
    // Non-tracked tools do NOT reset the counter; they are irrelevant to loop detection.
    if (toolName === "bash" && event.input?.command) {
      const loopResult = checkLoopBreaker(toolName, String(event.input.command));
      if (loopResult) return loopResult;
    } else if ((toolName === "read" || toolName === "edit" || toolName === "write") && event.input?.path) {
      const loopResult = checkLoopBreaker(toolName, String(event.input.path));
      if (loopResult) return loopResult;
    }

    if (customPolicy) return enforceCustomMode(toolName, event.input, ctx, customPolicy);
    if (mode === "bypassPermissions") return;
    if (mode === "acceptEdits" && (toolName === "write" || toolName === "edit")) return;

    // Universal autoallow — reload from settings.json each time so live-updated rules take effect
    const currentToolPermissions = await loadToolPermissions();
    const currentAutoAllowRules = compileUniversalRules(currentToolPermissions, "autoallow");
    const allowed = checkUniversalRules(toolName, event.input, currentAutoAllowRules, ctx.cwd);
    if (allowed === "autoallow") return;

    if (isSessionAllowed(toolName, event.input, sessionAllow)) return;

    // Default mode: always prompt for confirmation
    if (mode === "default") {
      if (!ctx.hasUI) {
        return { block: true as const, reason: `Blocked ${toolName} (no UI for confirmation)` };
      }
      return promptApproval(toolName, event.input, ctx, dangerousPatterns, catastrophicPatterns, sessionAllow, allowCatastrophic);
    }

    // Fallback to defaultAction (deny by default)
    if (toolPermissions.defaultAction === "allow") return;
    if (!ctx.hasUI) {
      return { block: true as const, reason: `Blocked ${toolName} (no UI for confirmation)` };
    }

    return promptApproval(toolName, event.input, ctx, dangerousPatterns, catastrophicPatterns, sessionAllow, allowCatastrophic);
  });
}

async function loadToolPermissions(): Promise<ToolPermissionsConfig> {
  const globalSettingsPath = resolve(homedir(), ".pi/agent/settings.json");
  const localSettingsPath = resolve(process.cwd(), ".pi/settings.json");
  const gs = await readJson<PiSettingsConfig>(globalSettingsPath);
  const ls = await readJson<PiSettingsConfig>(localSettingsPath);

  const globalTp: ToolPermissionsConfig | undefined = gs?.piClaudePermissions?.toolPermissions ?? {};
  const localTp: ToolPermissionsConfig | undefined = ls?.piClaudePermissions?.toolPermissions ?? {};

  // Merge: local overrides global, falls back to DEFAULT_TOOL_PERMISSIONS
  return {
    defaultAction: localTp.defaultAction ?? globalTp.defaultAction ?? DEFAULT_TOOL_PERMISSIONS.defaultAction,
    autoallow: (localTp.autoallow !== undefined ? localTp.autoallow : globalTp.autoallow) ?? DEFAULT_TOOL_PERMISSIONS.autoallow,
    autodeny: (localTp.autodeny !== undefined ? localTp.autodeny : globalTp.autodeny) ?? DEFAULT_TOOL_PERMISSIONS.autodeny,
  };
}

function compileUniversalRules(perms: ToolPermissionsConfig, action: "autoallow" | "autodeny"): UniversalRule[] {
  const rules: UniversalRule[] = [];
  const entries = perms[action] ?? [];

  for (const entry of entries) {
    const { toolName, pattern, isBash } = parseRuleEntry(entry);
    rules.push({ action, toolName, pattern, isBash, regex: isBash ? safeRegex(pattern) : undefined });
  }

  return rules;
}

function checkUniversalRules(
  toolName: string,
  input: Record<string, unknown>,
  universalRules: UniversalRule[],
  cwd: string | undefined,
): "autoallow" | "autodeny" | null {
  const resolvedCwd = cwd ? resolve(cwd) : process.cwd();

  for (const rule of universalRules) {
    // For non-bash rules (like grep:*, find:*), also check if the first word of a bash command matches
    let toolNameMatches = false;
    if (rule.toolName === toolName) {
      toolNameMatches = true;
    } else if (
      rule.toolName !== "*" &&
      toolName === "bash"
    ) {
      // Check if the first word of the bash command matches this non-bash tool name
      const cmdFirstWord = String(input.command ?? "").trim().split(/[\s]+/)[0];
      if (rule.toolName === cmdFirstWord) {
        toolNameMatches = true;
      }
    }
    if (!toolNameMatches) continue;

    if (toolName === "bash" || rule.isBash) {
      const command = String(input.command ?? "");
      // Handle wildcard pattern: * means match anything
      if (rule.pattern === "*") return rule.action as "autoallow" | "autodeny";
      if (rule.regex && rule.regex.test(command)) return rule.action as "autoallow" | "autodeny";
      if (command.includes(rule.pattern)) return rule.action as "autoallow" | "autodeny";
    } else {
      const targetPath = resolve(String(input.path ?? ""));
      if (pathMatchesGlob(targetPath, rule.pattern, resolvedCwd)) return rule.action as "autoallow" | "autodeny";
    }
  }
  return null;
}

function parseRuleEntry(entry: string): { toolName: string; pattern: string; isBash: boolean } {
  const colonIdx = entry.indexOf(":");
  if (colonIdx === -1) {
    return { toolName: "*", pattern: entry, isBash: false };
  }
  const toolName = entry.slice(0, colonIdx);
  const pattern = entry.slice(colonIdx + 1);
  // For file-based tools (read/edit/write), the pattern is always a path, never a command.
  // Only treat as bash-like for grep/find/ls/etc. where patterns can be flags or paths.
  const FILE_BASED_TOOLS = new Set(["read", "edit", "write"]);
  const looksLikeCmdPrefix = /^[a-z]/.test(toolName) && !pattern.includes("/") && !pattern.startsWith("~") && toolName !== "*";
  const isBash = toolName === "bash" || (looksLikeCmdPrefix && !FILE_BASED_TOOLS.has(toolName));
  return { toolName, pattern, isBash };
}

function safeRegex(pattern: string): RegExp | null {
  try {
    return new RegExp(`^${pattern}$`, "u");
  } catch {
    return null;
  }
}

function pathMatchesGlob(path: string, pattern: string, cwd: string): boolean {
  // Simple glob matching: * matches anything
  if (pattern === "*") return true;
  if (pattern === path) return true;
  if (pattern.includes("**/")) {
    const [prefix, suffix] = pattern.split("**/");
    // ** at start means match anywhere in path
    if (!prefix) {
      return matchGlobSegment(path, suffix);
    }
    const prefixHasGlob = prefix.includes("*");
    const suffixHasGlob = suffix.includes("*");
    let searchStart = 0;
    while (searchStart < path.length) {
      const idx = path.indexOf("/" + prefix, searchStart);
      if (idx === -1) break;
      const afterPrefix = path.slice(idx + 1);
      if (prefixHasGlob && suffixHasGlob) {
        // Both have globs: check if any segment matches prefix AND ends with suffix
        const segments = afterPrefix.split("/");
        for (let i = 0; i < segments.length; i++) {
          if (new RegExp('^' + prefix.replace(/\*/g, '.*') + '$').test(segments[i])) {
            if (segments.slice(i).join('/').endsWith(suffix)) return true;
          }
        }
      } else if (prefixHasGlob) {
        // Only prefix has glob
        const segments = afterPrefix.split("/");
        for (let i = 0; i < segments.length; i++) {
          if (new RegExp('^' + prefix.replace(/\*/g, '.*') + '$').test(segments[i])) {
            return true;
          }
        }
      } else if (suffixHasGlob) {
        // Only suffix has glob
        const segments = afterPrefix.split("/");
        for (let i = 0; i < segments.length; i++) {
          const segPath = segments.slice(i).join('/');
          if (new RegExp('^' + suffix.replace(/\*/g, '.*') + '$').test(segPath)) return true;
        }
      } else {
        // No globs in either
        if (afterPrefix.endsWith(suffix)) return true;
      }
      searchStart = idx + 1;
    }
    return false;
  }
  // Handle glob patterns by converting to regex
  try {
    // Escape special regex chars except *
    let esc = pattern.replace(/[.+?^$|(){}]/g, '\\$&');
    // Replace * with .*
    esc = esc.replace(/\*/g, '.*');
    return new RegExp('^' + esc + '$').test(path);
  } catch {
    return false;
  }
}

function matchGlobSegment(fullPath: string, pattern: string): boolean {
  if (pattern === "*") return true;
  // Special case: .env* matches any path containing ".env"
  if (pattern.startsWith(".env")) {
    const escapedPattern = pattern.slice(4).replace(/\*/g, '.*');
    if (!escapedPattern) return fullPath.includes(".env");
    // Match paths containing .env followed by the rest of the pattern
    return new RegExp('\\.' + escapedPattern.replace(/^/, '')).test(fullPath);
  }
  const segments = fullPath.split("/");
  for (const seg of segments) {
    if (new RegExp('^' + pattern.replace(/\*/g, '.*') + '$').test(seg)) return true;
  }
  // Also check full path
  if (new RegExp('^' + pattern.replace(/\*/g, '.*') + '$').test(fullPath)) return true;
  // Check suffixes of segments (for .env* matching filename endings)
  for (const seg of segments) {
    const parts = seg.split(".");
    if (parts.length > 1) {
      const nameWithoutExt = parts.slice(0, -1).join(".");
      if (new RegExp('^' + pattern.replace(/\*/g, '.*') + '$').test(nameWithoutExt)) return true;
    }
  }
  return false;
}

async function loadConfig(): Promise<PermissionsConfig> {
  const globalPath = resolve(homedir(), ".pi/agent/extensions/permissions.json");
  const localPath = resolve(process.cwd(), ".pi/extensions/permissions.json");
  const globalSettingsPath = resolve(homedir(), ".pi/agent/settings.json");
  const localSettingsPath = resolve(process.cwd(), ".pi/settings.json");
  const global = await readJson<PermissionsConfig>(globalPath);
  const local = await readJson<PermissionsConfig>(localPath);
  const globalSettings = await readJson<PiSettingsConfig>(globalSettingsPath);
  const localSettings = await readJson<PiSettingsConfig>(localSettingsPath);

  return {
    mode: stringOrUndefined(local.mode ?? global.mode),
    dangerousPatterns: local.dangerousPatterns ?? global.dangerousPatterns ?? DEFAULT_DANGEROUS,
    catastrophicPatterns: local.catastrophicPatterns ?? global.catastrophicPatterns ?? DEFAULT_CATASTROPHIC,
    protectedPaths: local.protectedPaths ?? global.protectedPaths ?? DEFAULT_PROTECTED_PATHS,
    allowCatastrophic: localSettings.piClaudePermissions?.allowCatastrophic
      ?? globalSettings.piClaudePermissions?.allowCatastrophic
      ?? false,
    shiftTabOptions: localSettings.piClaudePermissions?.shiftTabOptions
      ?? globalSettings.piClaudePermissions?.shiftTabOptions
      ?? local.shiftTabOptions
      ?? global.shiftTabOptions,
    defaultMode: stringOrUndefined(localSettings.piClaudePermissions?.defaultMode
      ?? globalSettings.piClaudePermissions?.defaultMode
      ?? local.defaultMode
      ?? global.defaultMode),
    hideDefaultMode: localSettings.piClaudePermissions?.hideDefaultMode
      ?? globalSettings.piClaudePermissions?.hideDefaultMode
      ?? local.hideDefaultMode
      ?? global.hideDefaultMode,
    customModes: localSettings.piClaudePermissions?.customModes
      ?? globalSettings.piClaudePermissions?.customModes
      ?? local.customModes
      ?? global.customModes,
  };
}

async function readJson<T>(path: string): Promise<T | Record<string, never>> {
  try {
    return JSON.parse(await readFile(path, "utf-8"));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    _configErrors.push(`Failed to parse config file: ${path} (${msg}). Falling back to defaults.`);
    console.warn(`[pi-permissions]`, _configErrors[_configErrors.length - 1]);
    return {};
  }
}

function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function stringArrayOrUndefined(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return;
  const strings = value.filter((item): item is string => typeof item === "string" && item.length > 0);
  return strings.length > 0 ? strings : undefined;
}

function buildModeDefinitions(customModes: unknown): ModeDefinition[] {
  const modes = [...BUILT_IN_MODES];
  if (!Array.isArray(customModes)) return modes;

  for (const customMode of customModes) {
    const mode = normalizeCustomMode(customMode);
    if (!mode) continue;
    const existing = modes.findIndex((candidate) => candidate.id === mode.id);
    if (existing >= 0) modes[existing] = mode;
    else modes.push(mode);
  }

  return modes;
}

function normalizeCustomMode(value: unknown): ModeDefinition | undefined {
  if (!value || typeof value !== "object") return;
  const raw = value as Record<string, any>;
  const id = stringOrUndefined(raw.id);
  const label = stringOrUndefined(raw.label);
  if (!id || !label) return;

  return {
    id,
    label,
    description: stringOrUndefined(raw.description) ?? label,
    status: stringOrUndefined(raw.status) ?? "⏵",
    policy: normalizeCustomModePolicy(raw.policy ?? raw),
  };
}

function normalizeCustomModePolicy(raw: Record<string, any>): CustomModePolicy | undefined {
  const policy: CustomModePolicy = {};
  if (Array.isArray(raw.excludedTools)) policy.excludedTools = raw.excludedTools.filter((tool: unknown): tool is string => typeof tool === "string");
  if (Array.isArray(raw.allowedWriteRoots)) policy.allowedWriteRoots = raw.allowedWriteRoots.filter((root: unknown): root is string => typeof root === "string");
  if (Array.isArray(raw.blockedBashPatterns)) {
    policy.blockedBashPatterns = raw.blockedBashPatterns
      .filter((pattern: unknown): pattern is Pattern => Boolean(pattern) && typeof pattern === "object" && typeof (pattern as Pattern).pattern === "string")
      .map((pattern: Pattern) => ({ pattern: pattern.pattern, description: pattern.description ?? pattern.pattern }));
  }
  if (raw.network && typeof raw.network === "object") {
    policy.network = {
      allowLocalhostOnly: raw.network.allowLocalhostOnly === true,
      allowGithubReadOnly: raw.network.allowGithubReadOnly === true,
      allowedPorts: Array.isArray(raw.network.allowedPorts)
        ? raw.network.allowedPorts.filter((port: unknown): port is number => Number.isInteger(port))
        : undefined,
    };
  }
  return Object.keys(policy).length > 0 ? policy : undefined;
}

function normalizeMode(mode: unknown, fallback: PermissionMode = DEFAULT_MODE, modes: ModeDefinition[] = BUILT_IN_MODES): PermissionMode {
  return parseMode(mode, modes) ?? fallback;
}

function parseMode(mode: unknown, modes: ModeDefinition[]): PermissionMode | undefined {
  if (typeof mode !== "string") return;
  if (modes.some((candidate) => candidate.id === mode)) return mode;
}

function normalizeShiftTabOptions(options: unknown, allModes: ModeDefinition[]): PermissionMode[] {
  if (!Array.isArray(options)) return allModes.map((mode) => mode.id);

  const modes = options
    .map((option) => parseMode(option, allModes))
    .filter((mode): mode is PermissionMode => mode !== undefined)
    .filter((mode, index, all) => all.indexOf(mode) === index);
  return modes.length > 0 ? modes : allModes.map((mode) => mode.id);
}

function getModeMeta(mode: PermissionMode, modes: ModeDefinition[]) {
  return modes.find((m) => m.id === mode) ?? modes.find((m) => m.id === DEFAULT_MODE)!;
}

function enforceCustomMode(toolName: string, input: Record<string, unknown>, ctx: UiContext, policy: CustomModePolicy) {
  if (policy.excludedTools?.includes(toolName)) {
    return { block: true as const, reason: `${toolName} is blocked in this permission mode.` };
  }

  if (toolName === "write" || toolName === "edit") {
    const targetPath = resolve(String(input.path ?? ""));
    if (!isPathInAllowedRoots(targetPath, ctx, policy.allowedWriteRoots)) {
      return { block: true as const, reason: `Write blocked outside allowed roots: ${targetPath}` };
    }
  }

  if (toolName === "bash") {
    const command = String(input.command ?? "");
    const blockedPattern = findCommandPatternMatch(command, policy.blockedBashPatterns ?? []);
    if (blockedPattern) {
      return { block: true as const, reason: blockedPattern.description };
    }

    const pathBlock = findBashPathBlock(command, ctx, policy.allowedWriteRoots);
    if (pathBlock) return { block: true as const, reason: pathBlock };

    const networkBlock = findNetworkBlock(command, policy.network);
    if (networkBlock) return { block: true as const, reason: networkBlock };
  }
}

function isPathInAllowedRoots(targetPath: string, ctx: UiContext, roots: CustomModePolicy["allowedWriteRoots"]): boolean {
  if (!roots || roots.length === 0) return true;
  return getAllowedRoots(ctx, roots).some((root) => targetPath === root || targetPath.startsWith(root + "/"));
}

function getAllowedRoots(ctx: UiContext, roots: CustomModePolicy["allowedWriteRoots"]): string[] {
  const cwd = resolve(ctx.cwd ?? process.cwd());
  return (roots ?? []).map((root) => {
    if (root === "cwd") return cwd;
    if (root === "parent") return resolve(cwd, "..");
    if (root.startsWith("~/")) return resolve(homedir(), root.slice(2));
    return resolve(root);
  });
}

function findBashPathBlock(command: string, ctx: UiContext, roots: CustomModePolicy["allowedWriteRoots"]): string | undefined {
  if (!roots || roots.length === 0) return;
  const allowedRoots = getAllowedRoots(ctx, roots);
  const cwd = resolve(ctx.cwd ?? process.cwd());
  const pathPattern = /(?:^|\s)(~\/?[^\s;&|]*|\.\.?\/?[^\s;&|]*|\/[^\s;&|]*)/g;
  for (const match of command.matchAll(pathPattern)) {
    const token = match[1]?.replace(/["']+$/g, "");
    if (!token || token === "." || token === ".." || token.startsWith("/-")) continue;
    if (token.startsWith("/dev/")) continue;

    const resolved = token.startsWith("~/") || token === "~"
      ? resolve(homedir(), token === "~" ? "" : token.slice(2))
      : token.startsWith("/")
        ? resolve(token)
        : resolve(cwd, token);

    if (!allowedRoots.some((root) => resolved === root || resolved.startsWith(root + "/"))) {
      return `Bash path blocked outside allowed roots: ${token}`;
    }
  }
}

function findCommandPatternMatch(command: string, patterns: Pattern[]): Pattern | undefined {
  return patterns.find((pattern) => {
    try {
      return new RegExp(pattern.pattern).test(command);
    } catch {
      return command.includes(pattern.pattern);
    }
  });
}

function findNetworkBlock(command: string, network: CustomModePolicy["network"]): string | undefined {
  if (!network?.allowLocalhostOnly) return;

  const urls = extractUrls(command);
  for (const url of urls) {
    if (!isAllowedLocalUrl(url, network.allowedPorts) && !isAllowedGithubReadUrl(url, network.allowGithubReadOnly)) {
      return `Network request blocked outside allowed localhost ports/GitHub read-only access: ${url}`;
    }
  }

  if (isAllowedGithubReadCommand(command, network.allowGithubReadOnly)) return;
  if (hasExternalNetworkIntent(command)) return "Network command blocked unless it targets localhost or a read-only GitHub operation.";
  if (!isNetworkCommand(command)) return;
  const localRefs = extractLocalhostRefs(command);
  if (localRefs.length === 0) return "Network command blocked unless it targets an allowed localhost port.";
  for (const ref of localRefs) {
    if (!isAllowedLocalPort(ref.port, network.allowedPorts)) {
      return `Network request blocked outside allowed localhost ports: ${ref.raw}`;
    }
  }
}

function extractUrls(command: string): string[] {
  return Array.from(command.matchAll(/https?:\/\/[^\s'"`<>]+/gi), (match) => match[0]);
}

function extractLocalhostRefs(command: string): Array<{ raw: string; port?: number }> {
  return Array.from(command.matchAll(/\b(?:localhost|127\.0\.0\.1|\[?::1\]?)(?::(\d+))?\b/gi), (match) => ({
    raw: match[0],
    port: match[1] ? Number(match[1]) : undefined,
  }));
}

function isNetworkCommand(command: string): boolean {
  return /\b(curl|wget|http|httpie|nc|netcat|telnet|ssh|scp|rsync|gh\s+api)\b/i.test(command)
    || /\b(?:node|python|python3|ruby|perl|php|deno|bun)\b[^|;&]*(?:fetch|request|requests|urllib|http|https|socket|net\.)/i.test(command)
    || /\b(npm|pnpm|yarn|bun)\s+(install|add|view|info|search|audit|outdated|publish)\b/i.test(command)
    || /\bpip\s+install\b/i.test(command);
}

function hasExternalNetworkIntent(command: string): boolean {
  return /\b(?:ssh|scp|rsync)\s+(?!.*(?:localhost|127\.0\.0\.1|\[?::1\]?))/i.test(command)
    || /\b(?:git\s+(?:clone|fetch|pull|ls-remote)|gh\s+|npm\s+|pnpm\s+|yarn\s+|bun\s+|pip\s+)/i.test(command);
}

function isAllowedGithubReadCommand(command: string, allowGithubReadOnly?: boolean): boolean {
  if (!allowGithubReadOnly) return false;
  const trimmed = command.trim();
  return /\bgh\s+pr\s+(view|list|diff|checks|status)\b/i.test(trimmed)
    || /\bgh\s+issue\s+(view|list|status)\b/i.test(trimmed)
    || /\bgh\s+repo\s+view\b/i.test(trimmed)
    || /\bgh\s+run\s+(view|list)\b/i.test(trimmed)
    || /\bgh\s+release\s+(view|list)\b/i.test(trimmed)
    || /\bgh\s+api\b[^|;&]*\b-X\s+GET\b/i.test(trimmed)
    || /\bgit\s+(?:fetch|pull|ls-remote)\b[^|;&]*(?:github\.com[:/]|https:\/\/github\.com\/)/i.test(trimmed);
}

function isAllowedLocalUrl(rawUrl: string, allowedPorts?: number[]): boolean {
  try {
    const url = new URL(rawUrl);
    const host = url.hostname.toLowerCase();
    if (host !== "localhost" && host !== "127.0.0.1" && host !== "[::1]" && host !== "::1") return false;
    const port = url.port ? Number(url.port) : undefined;
    return isAllowedLocalPort(port, allowedPorts);
  } catch {
    return false;
  }
}

function isAllowedGithubReadUrl(rawUrl: string, allowGithubReadOnly?: boolean): boolean {
  if (!allowGithubReadOnly) return false;
  try {
    const url = new URL(rawUrl);
    const host = url.hostname.toLowerCase();
    return host === "github.com" || host.endsWith(".github.com") || host === "api.github.com";
  } catch {
    return false;
  }
}

function isAllowedLocalPort(port: number | undefined, allowedPorts?: number[]): boolean {
  if (!allowedPorts || allowedPorts.length === 0) return true;
  return port !== undefined && allowedPorts.includes(port);
}

async function enforceAlwaysOnSafety(args: {
  toolName: string;
  input: Record<string, unknown>;
  ctx: UiContext;
  home: string;
  protectedPaths: string[];
  catastrophicPatterns: Pattern[];
  allowCatastrophic: boolean;
}) {
  const { toolName, input, ctx, home, protectedPaths, catastrophicPatterns, allowCatastrophic } = args;

  if (toolName === "bash") {
    const command = String(input.command ?? "");

    if (!allowCatastrophic) {
      const criticalRm = checkCriticalRmRf(command);
      if (criticalRm) {
        ctx.ui.notify(`🚫 Blocked catastrophic command: ${criticalRm}`, "error");
        return { block: true as const, reason: `Catastrophic command blocked: ${criticalRm}. This cannot be overridden.` };
      }

      const catastrophe = findMatch(command, catastrophicPatterns);
      if (catastrophe) {
        ctx.ui.notify(`🚫 Blocked catastrophic command: ${catastrophe.description}`, "error");
        return { block: true as const, reason: `Catastrophic command blocked: ${catastrophe.description}. This cannot be overridden.` };
      }
    }

    const protectedPath = protectedPaths.find((path) => command.includes(path) || command.includes(path.replace(home, "~")));
    if (protectedPath) {
      const readable = protectedPath.replace(home, "~");
      ctx.ui.notify(`🚫 Blocked bash targeting protected path: ${readable}`, "error");
      return { block: true as const, reason: `Bash command references protected path ${readable}. This cannot be overridden.` };
    }
  }

  if (toolName === "write" || toolName === "edit") {
    const targetPath = resolve(String(input.path ?? ""));
    const protectedPath = protectedPaths.find((path) => targetPath === path || targetPath.startsWith(path + "/"));
    if (protectedPath) {
      ctx.ui.notify(`🚫 Blocked write to protected path: ${targetPath}`, "error");
      return { block: true as const, reason: `Protected path blocked: ${targetPath}. This cannot be overridden.` };
    }
  }
}

function isSessionAllowed(toolName: string, input: Record<string, unknown>, sessionAllow: SessionAllow): boolean {
  if (toolName === "bash" && sessionAllow.commands.has(String(input.command ?? ""))) return true;
  return sessionAllow.tools.has(toolName);
}


function checkCriticalRmRf(command: string): string | null {
  for (const pattern of rmRfPatterns()) {
    const match = command.match(pattern);
    if (!match) continue;

    const home = homedir();
    const targets = match[1]!.trim().split(/\s+/).filter((target) => !target.startsWith("-"));

    for (const target of targets) {
      const resolved = resolveAbsoluteShellTarget(target, home);
      if (!resolved) continue;

      const normalized = resolved.replace(/\/+$/, "") || "/";
      if (normalized === "/") return "rm -rf / — recursive delete root";
      if (normalized === home) return "rm -rf ~ — recursive delete entire home directory";
      if (CRITICAL_DIRS.includes(normalized)) return `rm -rf ${normalized} — recursive delete critical system directory`;
    }
  }

  if (/\bsudo\s+/.test(command)) {
    const nested = checkCriticalRmRf(command.replace(/\bsudo\s+/, ""));
    if (nested) return `sudo ${nested}`;
  }

  return null;
}

function checkDangerousRmRf(command: string, cwd: string): { description: string } | null {
  for (const pattern of rmRfPatterns()) {
    const match = command.match(pattern);
    if (!match) continue;

    const rawArgs = match[1]!.trim().split(/\s*(?:&&|\|\||[;|])\s*/)[0]!;
    const targets = rawArgs.split(/\s+/).filter((target) => !target.startsWith("-") && target.length > 0);
    const normalizedCwd = resolve(cwd);

    for (const target of targets) {
      const normalized = resolveShellTarget(target, cwd);
      if (normalized === normalizedCwd || normalized.startsWith(normalizedCwd + "/")) continue;
      return { description: `recursive force delete outside project (${target})` };
    }

    return null;
  }

  return null;
}

function rmRfPatterns() {
  return [
    /\brm\s+(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*)\s+(.*)/i,
    /\brm\s+-r\s+-f\s+(.*)/i,
    /\brm\s+-f\s+-r\s+(.*)/i,
  ];
}

function resolveAbsoluteShellTarget(target: string, home = homedir()): string | null {
  if (target === "~") return home;
  if (target.startsWith("~/")) return resolve(home, target.slice(2));
  if (target === "/*") return "/";
  if (target.startsWith("/")) return target;
  return null;
}

function resolveShellTarget(target: string, cwd: string): string {
  const home = homedir();
  if (target === "~") return home;
  if (target.startsWith("~/")) return resolve(home, target.slice(2));
  if (target.startsWith("/")) return resolve(target);
  return resolve(cwd, target);
}

function findMatch(command: string, patterns: Pattern[]): Pattern | undefined {
  return patterns.find((pattern) => command.includes(pattern.pattern));
}

async function promptApproval(
  toolName: string,
  input: Record<string, unknown>,
  ctx: UiContext,
  dangerousPatterns: Pattern[],
  catastrophicPatterns: Pattern[],
  sessionAllow: SessionAllow,
  allowCatastrophic: boolean,
): Promise<{ block: true; reason: string } | undefined> {
  const { icon, description } = describeApprovalRequest(toolName, input, dangerousPatterns, catastrophicPatterns, allowCatastrophic);

  // Extract prefix for "add to autoallow" option (only for command-based tools)
  let addPrefixOption: string | null = null;
  if (toolName === "bash") {
    const command = String(input.command ?? "");
    const extracted = extractPrefix(toolName, command);
    if (extracted) {
      addPrefixOption = `Add prefix to autoallow → "${extracted}"`;
    }
  }

  // Build options list — insert the prefix option before Deny
  const baseOptions = [
    "Allow once",
    toolName === "bash" ? "Allow this command for session" : `Allow all ${toolName} for session`,
  ];

  let choice: string | undefined;
  if (addPrefixOption) {
    choice = await ctx.ui.select(`${icon} ${description}`, [
      ...baseOptions,
      addPrefixOption,
      "Deny",
    ]);
  } else {
    choice = await ctx.ui.select(`${icon} ${description}`, [...baseOptions, "Deny"]);
  }

  if (choice === baseOptions[0]) return;

  // Handle "Add prefix to autoallow"
  if (addPrefixOption && choice.startsWith("Add prefix")) {
    const command = String(input.command ?? "");
    const extracted = extractPrefix(toolName, command);
    if (extracted) {
      await persistAutoAllowRule(extracted);
      ctx.ui.notify(`✅ Added autoallow rule: "${extracted}"`, "info");
    }
    return;
  }

  if (choice === baseOptions[1]) {
    if (toolName === "bash") sessionAllow.commands.add(String(input.command ?? ""));
    else sessionAllow.tools.add(toolName);
    return;
  }

  return { block: true, reason: `User denied ${toolName}` };
}

/** Extract a meaningful prefix from a command for autoallow rules.
 * For bash commands like "grep -rn 'pattern' file" returns "grep:-r*"
 * Returns tool + first compound flag (e.g., grep:-rn or find:*-name*.ts)
 */
function extractPrefix(toolName: string, command: string): string | null {
  if (!command || !command.trim()) return null;

  // Tokenize the command, respecting quoted strings
  const tokens = tokenizeCommand(command);
  if (tokens.length === 0) return null;

  // For bash commands, extract the actual executable as tool name
  let execTool = toolName;
  let startIdx = 0;
  if (toolName === "bash") {
    const firstToken = stripQuotes(tokens[0]);
    if (firstToken && !/^[\-]/.test(firstToken)) {
      execTool = firstToken;
      startIdx = 1;
    }
  }

  // Find the first compound flag or meaningful arg
  for (let i = startIdx; i < tokens.length; i++) {
    const arg = stripQuotes(tokens[i]);
    if (!arg) continue;

    // Compound flags like -rn, --include=pattern → use as prefix (append * to match anything after)
    if (/^-{1,2}\w+/.test(arg) && !/^-{1,2}\d+$/.test(arg)) {
      return `${execTool}:${arg}:*`;
    }

    // Single-letter flag like -r → skip it and keep looking
    if (/^-[a-zA-Z]$/.test(arg)) continue;

    // First non-flag argument — too specific (file paths, patterns)
    break;
  }

  // No compound flag found — return tool:* so user can add a broad autoallow rule
  return `${execTool}:*`;
}

/** Tokenize a command string respecting quoted strings. */
function tokenizeCommand(cmd: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let inQuote: '"' | "'" | null = null;
  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i];
    if (inQuote) {
      if (ch === inQuote) {
        current += ch;
        tokens.push(current);
        current = "";
        inQuote = null;
      } else {
        current += ch;
      }
    } else if (ch === '"' || ch === "'") {
      if (current.length > 0) tokens.push(current);
      current = ch;
      inQuote = ch;
    } else if (/\s/.test(ch)) {
      if (current.length > 0) tokens.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  if (current.length > 0) tokens.push(current);
  return tokens;
}

/** Strip surrounding quotes from a string. */
function stripQuotes(s: string): string {
  if (
    s.length >= 2 &&
    ((s[0] === '"' && s[s.length - 1] === '"') || (s[0] === "'" && s[s.length - 1] === "'"))
  ) {
    return s.slice(1, -1);
  }
  return s;
}

/** Persist an autoallow rule to the global settings.json. */
async function persistAutoAllowRule(rule: string): Promise<void> {
  const path = resolve(homedir(), ".pi/agent/settings.json");
  try {
    const raw = await readFile(path, "utf-8");
    const config = JSON.parse(raw) as PiSettingsConfig;
    const perms = (config.piClaudePermissions ??= {}).toolPermissions ??= {};
    const autoallow = (perms.autoallow ??= []);

    // Avoid duplicates
    if (autoallow.includes(rule)) return;

    autoallow.push(rule);
    config.piClaudePermissions.toolPermissions = perms;
    await require("fs/promises").writeFile(path, JSON.stringify(config, null, 2) + "\n", "utf-8");
  } catch {
    // Silently fail — user can always add manually
  }
}

function describeApprovalRequest(
  toolName: string,
  input: Record<string, unknown>,
  dangerousPatterns: Pattern[],
  catastrophicPatterns: Pattern[],
  allowCatastrophic: boolean,
): { icon: string; description: string } {
  if (toolName === "write") return { icon: "🔒", description: `write: ${input.path}` };
  if (toolName === "edit") return { icon: "🔒", description: `edit: ${input.path}` };
  if (toolName !== "bash") return { icon: "🔒", description: toolName };

  const command = String(input.command ?? "");
  const catastrophe = allowCatastrophic ? undefined : findMatch(command, catastrophicPatterns);
  const danger = findMatch(command, dangerousPatterns);
  const rmDanger = checkDangerousRmRf(command, process.cwd());

  if (catastrophe) return { icon: "🚫", description: `bash: ${command}\n   🚫 CATASTROPHIC: ${catastrophe.description}` };
  if (danger) return { icon: "⚠️", description: `bash: ${command}\n   ⚠️  DANGEROUS: ${danger.description}` };
  if (rmDanger) return { icon: "⚠️", description: `bash: ${command}\n   ⚠️  DANGEROUS: ${rmDanger.description}` };
  return { icon: "🔒", description: `bash: ${command}` };
}
