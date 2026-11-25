/**
 * GitHub Repository Scanner
 *
 * Scans GitHub repositories for malware signatures, obfuscated code,
 * suspicious dependencies, and postinstall scripts.
 *
 * Uses GitHub API to fetch repo contents without full clone.
 * No chrome.storage dependency — token and signatures are passed as options.
 */

import { franc } from "franc-min"
import type {
  GitHubFinding,
  GitHubRepoInfo,
  GitHubScanResult,
  MaliciousPackage,
  RepoScanOptions,
  SkippedFile,
  SkipReason,
} from "../types/index.js"
import { DEFAULT_DISCLAIMER } from "../types/index.js"
import { collectEvidence } from "../utils/evidence.js"
import { maskRegexLiterals, maskStringLiterals } from "../utils/mask.js"
import {
  githubApiError,
  githubNotFoundError,
  isRateLimitResponse
} from "./api-error.js"
import { fetchHistorySignals } from "./history-signals.js"
import {
  MAX_TARBALL_TREE_BYTES,
  readRepoTarball,
  type TarballFallbackReason,
  type TarballKeep,
} from "./tarball.js"
import { matchOsvFeed, npmDependencies, pythonDependencies, resolveNpmAlias, type DeclaredDependency } from "./osv-feed.js"
import {
  calculateRawRiskScore,
  calculateRiskScore,
  calculateSignalContributions,
  getRiskLevel,
} from "../utils/risk-calculator.js"
import {
  applyYaraRules,
  detectKeyboardCapture,
  isDocumentedAwsExampleKey,
  isObviousPlaceholderSecret,
  isTestFile,
} from "../rules/rule-matcher.js"

// High-risk files to always check
const PRIORITY_FILES = [
  "package.json",
  "package-lock.json",
  "requirements.txt",
  "setup.py",
  "Pipfile",
  ".npmrc",
  ".yarnrc",
  "Makefile",
]

const SCANNABLE_EXTENSIONS = [
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".py",
  ".rb",
  ".php",
  ".go",
  ".sh",
  ".ps1",
  ".psm1",
  ".bat",
  ".cmd",
  ".vbs",
  ".html",
  ".htm",
]
/**
 * Files that are not "source" but are executed or obeyed by developer tools
 * the moment a repo is opened: VS Code tasks (runOn: folderOpen), Claude Code
 * hooks, MCP server configs, CI workflows, and instruction files coding agents
 * read. 2025–2026 campaigns (Contagious Interview task files, Shai-Hulud /
 * CHAINDROP hook persistence, poisoned coding tests) live almost entirely
 * here. They get YARA rules only — the JS-oriented built-in detectors still
 * run on source files alone — and they are read before source files so the
 * per-scan file cap can never push them out.
 */
// `Dockerfile`, `Dockerfile.prod`, `prod.Dockerfile`, `Dockerfile-dev`.
const CONTAINER_BUILD_FILE = /(?:^|\/)(?:[\w.-]+[-.])?(?:Dockerfile|Containerfile)(?:[-.][\w.-]+)?$/i
const COMPOSE_FILE = /(?:^|\/)(?:[\w-]+-)?compose(?:\.[\w-]+)*\.ya?ml$/i

const CONFIG_FILE_PATTERNS: RegExp[] = [
  /(?:^|\/)\.vscode\/(?:tasks|settings|launch|mcp)\.json$/,
  /(?:^|\/)\.claude\/settings(?:\.local)?\.json$/,
  /(?:^|\/)\.(?:cursor|amazonq|gemini|windsurf|roo|kiro)\/(?:mcp|settings)\.json$/,
  /(?:^|\/)\.mcp\.json$/,
  // devcontainer: initializeCommand runs on the host, and
  // onCreate/postCreateCommand the moment an editor opens the folder.
  /(?:^|\/)\.devcontainer\.json$/,
  /(?:^|\/)\.devcontainer\/(?:[^/]+\/)?devcontainer\.json$/,
  // `docker build` / `docker compose up` is a one-command execution path:
  // RUN steps, `command:`, privileged containers, docker-socket mounts.
  CONTAINER_BUILD_FILE,
  COMPOSE_FILE,
  /^\.github\/workflows\/[^/]+\.ya?ml$/,
  /(?:^|\/)README(?:\.md|\.txt|\.rst)?$/i,
  /(?:^|\/)(?:AGENTS|CLAUDE|GEMINI)\.md$/,
  /(?:^|\/)\.(?:cursorrules|windsurfrules|clinerules)$/,
  /(?:^|\/)\.cursor\/rules\/.*\.mdc?$/,
  // Prompts, slash commands, subagents and skills: markdown a coding agent
  // executes on request, with the same reach as a hook.
  /(?:^|\/)\.claude\/(?:commands|agents)\/.*\.md$/,
  /(?:^|\/)\.claude\/skills\/[^/]+\/SKILL\.md$/,
  /^\.github\/copilot-instructions\.md$/,
  /^\.github\/(?:instructions|prompts)\/[^/]+\.md$/,
]

/**
 * Rule scope for configs whose file name, not its extension, says what it is.
 * A Dockerfile's content is shell and a compose file's is YAML, so each keeps
 * the generic suffix (every `.sh` / `.yml` rule still applies) behind a
 * type-specific one, which is how a rule targets just that file type:
 * `.dockerfile.sh` for container builds, `.compose.yml` for compose files.
 * Name lists cannot do this job — `Dockerfile.prod` and `prod.Dockerfile`
 * are the same file type under a different basename.
 */
function configRuleScope(path: string): string {
  if (CONTAINER_BUILD_FILE.test(path)) return `${path}.dockerfile.sh`
  if (COMPOSE_FILE.test(path)) return `${path}.compose.yml`
  return path
}

/**
 * Instruction files an agent obeys and plain docs. They are read, but they
 * claim the config budget only after the configs that a tool executes —
 * a monorepo's nested READMEs must not push out a devcontainer or hook file.
 */
const INSTRUCTION_CONFIG = /(?:^|\/)(?:AGENTS|CLAUDE|GEMINI)\.md$|(?:^|\/)\.(?:cursorrules|windsurfrules|clinerules)$|(?:^|\/)\.cursor\/rules\/|(?:^|\/)\.claude\/(?:commands|agents|skills)\/|^\.github\/(?:copilot-instructions\.md$|(?:instructions|prompts)\/)/
const README_CONFIG = /(?:^|\/)README(?:\.md|\.txt|\.rst)?$/i

/**
 * Stable sort by priority: files of equal priority keep their tree order, so
 * selection stays deterministic for the same commit.
 */
function sortByPriority(
  items: GitHubTreeItem[],
  priority: (path: string) => number
): void {
  const rank = new Map(items.map((item, index) => [item, index]))
  items.sort(
    (a, b) =>
      priority(a.path) - priority(b.path) || rank.get(a)! - rank.get(b)!
  )
}

/** 0 = executed by a tool, 1 = instructions an agent obeys, 2 = docs. */
function configPriority(path: string): number {
  if (README_CONFIG.test(path)) return 2
  if (INSTRUCTION_CONFIG.test(path)) return 1
  return 0
}

const UTF8 = new TextDecoder("utf-8")

function decodeUtf8(binary: string): string {
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index)
  return UTF8.decode(bytes)
}

/**
 * One character per byte, the same string `atob` yields — which is what the
 * font magic-number check reads. `TextDecoder("latin1")` cannot stand in for
 * this: the Encoding spec maps that label to windows-1252, which rewrites
 * 0x80–0x9F and so would corrupt the very bytes being identified.
 */
function latin1(bytes: Uint8Array): string {
  const CHUNK = 8192
  let out = ""
  for (let start = 0; start < bytes.length; start += CHUNK) {
    out += String.fromCharCode(...bytes.subarray(start, start + CHUNK))
  }
  return out
}

export function isConfigFile(path: string): boolean {
  return CONFIG_FILE_PATTERNS.some((pattern) => pattern.test(path))
}

/**
 * Font files are binary. A "font" that is really JavaScript text is the
 * PolinRider / Contagious Interview loader (`node public/fonts/fa-solid-500.woff2`
 * launched from a folderOpen task). Only a few, small ones are read.
 */
const FONT_EXTENSIONS = [".woff", ".woff2", ".ttf", ".otf", ".eot"]
/** Fonts read per scan on the per-file path, where each one is a request. */
const MAX_FONT_FILES = 10
const MAX_FONT_BYTES = 512 * 1024

function isFontFile(path: string): boolean {
  return FONT_EXTENSIONS.some((ext) => path.toLowerCase().endsWith(ext))
}

/**
 * Configs read per scan on the per-file path, on top of MAX_FILES_TO_SCAN.
 * Each one costs a request there, so this is a request budget.
 */
const MAX_CONFIG_FILES = 25

/**
 * Config budget when the whole repo arrives in one request, where a count
 * stops meaning anything: padding a repo with 25 decoy workflows or nested
 * READMEs used to be enough to push a hook file or a poisoned README out of
 * the scan. Bytes are what a config costs once reading is free.
 *
 * It is a budget of its own rather than a share of MAX_SOURCE_BYTES because a
 * config costs far less than a source file of the same size: only sources
 * keep a masked copy for the whole scan and go through the global detectors
 * (the 13-14x overhead described there), while a config is decoded, matched
 * against the config-scoped rules once and dropped. The largest total in the
 * 50-repo reference corpus is nodejs/node at 1.3MB (256 configs, 210 of them
 * READMEs); next.js has 393 configs in 1.0MB. 4MB reads every config of every
 * one of them. Measured in a 384MB heap, reading all 124 of facebook/react's
 * configs instead of 25 left peak heap where it was (205MB either way, within
 * run-to-run noise), and all 188 of prisma/prisma's moved it from 167MB to
 * 169MB. Taking those bytes out of MAX_SOURCE_BYTES instead would have bought
 * nothing in memory and cost up to 1.3MB of source coverage.
 */
const MAX_SNAPSHOT_CONFIG_BYTES = 4 * 1024 * 1024
/**
 * Backstop for pathological trees, not a coverage limit: no corpus repo comes
 * near it. Every config is a pass of the config-scoped rules and an entry in
 * `scannedFiles`, so 4MB of 100-byte files would be 40,000 of each — time and
 * result size that bytes alone do not bound.
 */
const MAX_SNAPSHOT_CONFIG_FILES = 2_000
/**
 * Fonts on the snapshot path: every font is magic-number-checked while the
 * archive streams, so the count bound is a backstop for a tree of tens of
 * thousands of icon fonts (each one is a buffer while its body arrives and an
 * entry in `scannedFiles`). next.js, the most in the corpus, has 50.
 */
const MAX_SNAPSHOT_FONT_FILES = 2_000
/**
 * A real font keeps only its head (FONT_SNIFF_BYTES) once its magic number
 * matches; a "font" that fails the check is kept whole for the masquerade
 * check. This caps those whole ones: past it, the rest are skipped as
 * over-file-limit rather than held — 16 fakes at the 512KB size limit.
 */
const MAX_SNAPSHOT_SUSPECT_FONT_BYTES = 8 * 1024 * 1024
/** Enough for every magic number `isRealFont` reads (EOT's sits at 34). */
const FONT_SNIFF_BYTES = 64

/**
 * Files a config runs with a JS runtime — `node .vscode/spellright.dict`,
 * `node src/assets/card4.jpeg`, a hook's `node .claude/hooks/x.js`, an install
 * script's `node setup.mjs` — are executed as code whatever their extension.
 * They are read on their own budget (even when the source cap or the
 * extension filter skipped them) and scanned as JavaScript. CI workflows are
 * left out: their steps run on CI runners, not on the cloner's machine, and
 * they routinely run test suites that evaluate generated code.
 *
 * The cap holds on the snapshot path too, because a target still costs a
 * request there. Targets are known only once the configs naming them have
 * been read, which is after the archive has streamed past, so a target the
 * archive did not already carry is fetched on its own. Serving targets from
 * the archive would mean holding every blob that might turn out to be one —
 * the whole repo, several times the memory budget — or downloading it twice.
 * Without the cap, one config naming hundreds of targets would spend an
 * unauthenticated caller's 60 requests an hour and leave the scan partial.
 */
const MAX_COMMAND_TARGETS = 10
// CI workflows run on CI runners and container builds inside a container,
// not on the cloner's machine, so their steps are not followed as host
// commands. A devcontainer is not in here: initializeCommand runs on the host.
const CI_WORKFLOW = /^\.github\/workflows\//
function runsOffHost(path: string): boolean {
  return CI_WORKFLOW.test(path) || CONTAINER_BUILD_FILE.test(path) || COMPOSE_FILE.test(path)
}
const RUNTIME_INVOCATION =
  /\b(?:node|nodejs|bun|deno\s+run|tsx|ts-node)((?:\s+-{1,2}[\w-]+(?:=[^\s"'`]*)?)*)\s+\\?["']?([^\s"'`&|;<>()]+)/g
// `node -e <code>` / `-p` take inline code, not a file.
const INLINE_CODE_FLAG = /(?:^|\s)(?:-[ep]|--eval|--print)(?:\s|=|$)/
const RUNTIME_ARGS_FORM =
  /"command"\s*:\s*"(?:node|nodejs|bun|deno|tsx|ts-node)"\s*,\s*"args"\s*:\s*\[\s*"([^"]+)"/g
// Variables that name the folder a config runs from (VS Code, Claude Code).
const PROJECT_DIR_VARIABLE =
  /\\?["']?\$\{?(?:CLAUDE_PROJECT_DIR|workspaceFolder|workspaceRoot|localWorkspaceFolder|containerWorkspaceFolder)\}?\\?["']?(?=\/)/g
// Configs inside these dot-dirs run from the folder that holds the dot-dir.
const DOT_DIR_CONFIG = /^(?:(.*)\/)?\.(?:vscode|claude|cursor|amazonq|gemini|windsurf|roo|kiro|github|devcontainer)\//

/** Repo paths that a config file runs with node/bun/deno/tsx. */
export function extractCommandTargets(content: string, configPath: string): string[] {
  const dotDir = configPath.match(DOT_DIR_CONFIG)
  const base = dotDir
    ? (dotDir[1] ?? "")
    : configPath.includes("/") ? configPath.slice(0, configPath.lastIndexOf("/")) : ""
  const text = content.replace(PROJECT_DIR_VARIABLE, ".")
  const targets = new Set<string>()
  for (const match of text.matchAll(RUNTIME_INVOCATION)) {
    if (INLINE_CODE_FLAG.test(match[1]!)) continue
    const path = resolveRepoPath(base, match[2]!)
    if (path) targets.add(path)
  }
  for (const match of text.matchAll(RUNTIME_ARGS_FORM)) {
    const path = resolveRepoPath(base, match[1]!)
    if (path) targets.add(path)
  }
  return [...targets]
}

function resolveRepoPath(base: string, raw: string): string | null {
  const target = raw.replace(/\\+$/, "")
  if (!target || /^[-/~$]/.test(target) || target.includes("://")) return null
  const segments: string[] = base ? base.split("/") : []
  for (const segment of target.split("/")) {
    if (segment === "" || segment === ".") continue
    if (segment === "..") {
      if (segments.length === 0) return null
      segments.pop()
    } else {
      segments.push(segment)
    }
  }
  return segments.length > 0 ? segments.join("/") : null
}

/**
 * How many file reads are in flight at once.
 *
 * A scan is almost entirely round trips: reading 226 files from
 * facebook/react took 139.8s of network against 436ms of CPU, so the file
 * cap below is really a request budget. Measured on that repo, the same 226
 * files take 137.5s at 1 in flight, 21.3s at 6, 10.6s at 12 and 5.3s at 24.
 *
 * 12 takes most of the win and stays well clear of GitHub's secondary rate
 * limits, which react to burst size and whose guidance is to prefer serial
 * requests. Raising it trades that headroom for diminishing returns.
 */
export const FETCH_CONCURRENCY = 12

/**
 * Run `work` over `items` with at most `limit` in flight, returning results
 * in the order of `items` — never in completion order. Analysis downstream
 * must stay in queue order: findings are deduped by keeping the strongest
 * match, and which description survives depends on the order they arrive in.
 */
async function mapPool<T, R>(
  items: readonly T[],
  limit: number,
  work: (item: T) => Promise<R>
): Promise<R[]> {
  const results = new Array<R>(items.length)
  let next = 0
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const index = next++
      if (index >= items.length) return
      results[index] = await work(items[index]!)
    }
  })
  await Promise.all(workers)
  return results
}

const MAX_FILES_TO_SCAN = 200

/**
 * When a repo has more scannable sources than the cap, which ones to read
 * first. Tree order alone spends the budget alphabetically: a monorepo's
 * `apps/.../*.test.tsx` crowd out `scripts/*.ts` and `postcss.config.js`,
 * which is backwards — every data-driven rule skips test files
 * (`applyYaraRules` returns early on them), while build and install scripts
 * are what actually runs on a clone, and PolinRider-style loaders are
 * appended to next / tailwind / postcss configs. Sorting also sets the fetch
 * order, so a scan that hits the rate limit has already read the files that
 * matter most.
 */
const RUNS_ON_INSTALL_OR_BUILD =
  /^(?:scripts?|bin|tools?)\/|(?:^|\/)(?:pre|post)?install\.(?:[cm]?js|ts)$|(?:^|\/)setup\.(?:[cm]?js|ts|py)$|(?:^|\/)[\w.-]*\.config\.(?:[cm]?js|ts)$|^\.(?:husky|github|vscode|claude|cursor|devcontainer)\//
const GENERATED_OR_VENDORED =
  /(?:^|\/)(?:dist|build|out|vendor|third_party|node_modules|coverage)\/|\.min\.[cm]?js$|\.bundle\.[cm]?js$|(?:^|\/)[\w.-]*\.generated\.[cm]?[jt]sx?$/
const SUPPORTING_SOURCE = /(?:^|\/)(?:__mocks__|mocks?|examples?|samples?|demos?)\//i

/** 0 = runs on install/build, 1 = ordinary source, 2 = tests and samples, 3 = artifacts. */
function sourcePriority(path: string): number {
  if (GENERATED_OR_VENDORED.test(path)) return 3
  if (isTestFile(path) || SUPPORTING_SOURCE.test(path)) return 2
  if (RUNS_ON_INSTALL_OR_BUILD.test(path)) return 0
  return 1
}

/**
 * Source budget when the whole repo arrives in one request.
 *
 * `MAX_FILES_TO_SCAN` is a request budget: a file costs a round trip, so the
 * only way to bound a scan was to bound the file count. Reading the tarball
 * costs one request whatever the count, which leaves bytes as the thing worth
 * bounding — pattern matching is linear in bytes and indifferent to how many
 * files they are spread across.
 *
 * What bounds it is memory rather than time. Each source file's masked copy
 * is retained for the whole scan and the detectors then run global regexes
 * over all of it, so peak heap runs roughly 13-14x the source read. Measured
 * on facebook/react (4,565 eligible source files, 22.7MB): a 4MB cap peaks at
 * 30MB of heap, 8MB at 49MB, 16MB at 217MB, 32MB at 427MB, and a 32MB cap
 * cannot complete the scan in a 256MB heap. The extension runs this in an MV3
 * service worker.
 *
 * 16MB reads 4,373 of react's 4,565 source files, 96% of them against the 226
 * the file cap allowed, in 11.5s within a 384MB heap, and 3,078 of
 * prisma/prisma's 8,226 at a 107MB peak. Doubling it buys the last 4% of
 * react for twice the memory, and the files it adds are the deprioritised
 * tail: tests, fixtures and vendored artifacts the rules skip anyway.
 */
const MAX_SOURCE_BYTES = 16 * 1024 * 1024
// Blobs above this are skipped ("too-large"): almost always bundles or
// vendored artifacts, and fetching them dominates scan time on big repos.
const MAX_FILE_SIZE_BYTES = 1024 * 1024
// skippedFiles list cap — skippedCount stays accurate; this only bounds the
// per-path detail so huge repos don't bloat the result object.
const MAX_SKIPPED_FILES_LISTED = 500
/**
 * Which skips the capped list shows first: the ones that say the verdict
 * rests on less than the scanner meant to read, then the files a budget left
 * out, and only then the file types it never reads. Listed in tree order,
 * the cap filled with images and lockfiles — facebook/react and
 * prisma/prisma both listed 500 `unsupported-type` entries and not one of
 * the files over a budget.
 */
const SKIP_LIST_ORDER: readonly SkipReason[] = [
  "rate-limited",
  "fetch-failed",
  "over-file-limit",
  "too-large",
  "unsupported-type",
]

// npm download count cache (in-memory)
interface NpmDownloadCacheEntry {
  weeklyDownloads: number | null
  fetchedAt: number
}
const NPM_DOWNLOAD_CACHE = new Map<string, NpmDownloadCacheEntry>()
const NPM_CACHE_TTL_MS = 60 * 60 * 1000
const NPM_HIGH_DOWNLOAD_THRESHOLD = 100_000

interface GitHubTreeItem {
  path: string
  type: "blob" | "tree"
  sha: string
  size?: number
  url: string
}

interface GitHubTreeResponse {
  sha: string
  tree: GitHubTreeItem[]
  truncated: boolean
}

/**
 * Preserve inline script text and all newline/character offsets while masking
 * HTML markup and prose. This lets JS detectors inspect templates without
 * turning visible page copy or attributes into executable-code findings.
 */
function maskExceptInlineScripts(content: string): string {
  const masked: string[] = [...content].map((char) =>
    char === "\n" || char === "\r" ? char : " "
  )
  const script = /<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi
  for (const match of content.matchAll(script)) {
    const body = match[1] ?? ""
    const bodyOffset = (match.index ?? 0) + match[0].indexOf(body)
    for (let index = 0; index < body.length; index++) {
      masked[bodyOffset + index] = body[index]!
    }
  }
  return masked.join("")
}

export async function scanGitHubRepo(
  repo: GitHubRepoInfo,
  options: RepoScanOptions
): Promise<GitHubScanResult> {
  const findings: GitHubFinding[] = []
  let filesScanned = 0
  let patternsMatched = 0
  let dependenciesChecked = 0

  try {
    const headers: Record<string, string> = {
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "Flagrix-Extension",
    }

    if (options.githubToken) {
      headers["Authorization"] = `Bearer ${options.githubToken}`
    }

    let branch = repo.branch
    if (!branch) {
      const repoResponse = await fetch(
        `https://api.github.com/repos/${repo.owner}/${repo.repo}`,
        { headers }
      )
      if (repoResponse.status === 404) {
        throw githubNotFoundError(Boolean(options.githubToken))
      }
      if (!repoResponse.ok) {
        throw await githubApiError(repoResponse)
      }
      const repoData = await repoResponse.json()
      branch = repoData.default_branch || "main"
    }

    // Pin the scan to the branch's current commit so the whole read — tree
    // and every file — is one immutable snapshot. Without this, the repo can
    // change between requests (or between scan and clone) while the verdict
    // silently keeps referring to content nobody can see anymore (TOCTOU).
    const commitResponse = await fetch(
      `https://api.github.com/repos/${repo.owner}/${repo.repo}/commits/${encodeURIComponent(branch)}`,
      { headers }
    )
    if (commitResponse.status === 404) {
      throw githubNotFoundError(Boolean(options.githubToken))
    }
    if (!commitResponse.ok) {
      throw await githubApiError(commitResponse)
    }
    const commitSha: string = (await commitResponse.json()).sha

    const treeUrl = `https://api.github.com/repos/${repo.owner}/${repo.repo}/git/trees/${commitSha}?recursive=1`
    const treeResponse = await fetch(treeUrl, { headers })

    if (treeResponse.status === 404) {
      throw githubNotFoundError(Boolean(options.githubToken))
    }
    if (!treeResponse.ok) {
      throw await githubApiError(treeResponse)
    }

    const tree: GitHubTreeResponse = await treeResponse.json()

    // Partition every blob into "scan" vs "skip + why", so the UI can show
    // exactly which files were read and why the rest were not. Skips are kept
    // per reason, each list capped, and joined in SKIP_LIST_ORDER at the end,
    // so a flood of one reason cannot push another out of the list.
    const skippedByReason = new Map<SkipReason, SkippedFile[]>(
      SKIP_LIST_ORDER.map((reason) => [reason, []])
    )
    let skippedCount = 0
    const skip = (path: string, reason: SkipReason) => {
      skippedCount++
      const listed = skippedByReason.get(reason)!
      if (listed.length < MAX_SKIPPED_FILES_LISTED) listed.push({ path, reason })
    }

    // Editor/agent/CI configs and small fonts get their own budget on top of
    // the source budget, so adding them never displaces source coverage
    // (sharing one cap pushed 5–38 source files out of large repos).
    const configCandidates: GitHubTreeItem[] = []
    const fontCandidates: GitHubTreeItem[] = []
    const sourceBlobs: GitHubTreeItem[] = []
    for (const item of tree.tree) {
      if (item.type !== "blob") continue
      // A source extension wins over a config pattern: `Dockerfile.ts` is a
      // script to scan with the full detectors, not a container build.
      const config =
        isConfigFile(item.path) &&
        !SCANNABLE_EXTENSIONS.some((ext) => item.path.endsWith(ext))
      const font = !config && isFontFile(item.path)
      if (config || font) {
        const sizeLimit = font ? MAX_FONT_BYTES : MAX_FILE_SIZE_BYTES
        if (item.size !== undefined && item.size > sizeLimit) {
          skip(item.path, "too-large")
        } else if (font) {
          fontCandidates.push(item)
        } else {
          configCandidates.push(item)
        }
        continue
      }
      const eligible =
        PRIORITY_FILES.some((pf) => item.path.endsWith(pf)) ||
        SCANNABLE_EXTENSIONS.some((ext) => item.path.endsWith(ext))
      if (!eligible) {
        skip(item.path, "unsupported-type")
      } else if (item.size !== undefined && item.size > MAX_FILE_SIZE_BYTES) {
        skip(item.path, "too-large")
      } else {
        sourceBlobs.push(item)
      }
    }
    sortByPriority(sourceBlobs, sourcePriority)
    // Spend the config budget on the configs a tool executes before the ones
    // it merely reads (configPriority), so widening the set never costs
    // coverage of the auto-run files. Tree order is kept inside each tier.
    sortByPriority(configCandidates, configPriority)

    /** The longest prefix of `items` whose sizes fit in `budget` bytes. */
    const bytePrefix = (items: GitHubTreeItem[], budget: number, maxCount = Infinity) => {
      let bytes = 0
      let cut = Math.min(items.length, maxCount)
      for (let index = 0; index < cut; index++) {
        bytes += items[index]!.size ?? 0
        if (bytes > budget) {
          cut = index
          break
        }
      }
      return cut
    }

    /**
     * Which configs, fonts and sources fit the budget. The budget itself
     * depends on how the contents will be read, so this runs once per
     * candidate reader: under byte budgets when the whole repo comes in one
     * request, and under file counts when each file costs its own. Nothing is
     * recorded here — the caller skips the leftovers only for the reader it
     * ends up using, so an abandoned tarball attempt leaves no trace in the
     * summary.
     */
    const selectFiles = (snapshot: boolean) => {
      const configCut = snapshot
        ? bytePrefix(configCandidates, MAX_SNAPSHOT_CONFIG_BYTES, MAX_SNAPSHOT_CONFIG_FILES)
        : MAX_CONFIG_FILES
      // Fonts are not budgeted by bytes on the snapshot path: a real one is
      // trimmed to its magic number as the archive streams (`keepFromArchive`).
      const fontCut = snapshot ? MAX_SNAPSHOT_FONT_FILES : MAX_FONT_FILES
      const sourceCut = snapshot
        ? bytePrefix(sourceBlobs, MAX_SOURCE_BYTES)
        : MAX_FILES_TO_SCAN
      return {
        configs: configCandidates.slice(0, configCut),
        fonts: fontCandidates.slice(0, fontCut),
        sources: sourceBlobs.slice(0, sourceCut),
        overLimit: [
          ...configCandidates.slice(configCut),
          ...fontCandidates.slice(fontCut),
          ...sourceBlobs.slice(sourceCut),
        ],
      }
    }

    // Reading the repo as one tarball is opt-in: in the extension it needs an
    // optional host permission for codeload.github.com, and asking without
    // one costs a round trip before it fails. The caller decides; this only
    // tries, and records how it went so the verdict can say which coverage it
    // rests on.
    let readMode: "tarball" | "per-file" = "per-file"
    let readFallbackReason: TarballFallbackReason | undefined
    let tarballFiles: Map<string, Uint8Array> | null = null
    let selected = selectFiles(false)

    if (options.tarball) {
      const treeBytes = tree.tree.reduce(
        (total, item) => total + (item.type === "blob" ? item.size ?? 0 : 0),
        0
      )
      if (treeBytes > MAX_TARBALL_TREE_BYTES) {
        readFallbackReason = "too-large"
      } else {
        const candidate = selectFiles(true)
        const fontPaths = new Set(candidate.fonts.map((item) => item.path))
        // Every font is checked, but only the ones that fail the check are
        // held whole: a real font is settled by its first bytes, which are
        // all the masquerade check reads of it. The fakes share a byte budget,
        // so a repo stuffed with them cannot hold the archive in memory.
        let suspectFontBytes = 0
        const overBudgetFonts = new Set<string>()
        const keepFromArchive: TarballKeep = (path, body) => {
          if (!fontPaths.has(path)) return body
          const head = body.subarray(0, FONT_SNIFF_BYTES)
          // A copy, so the full body's buffer is released.
          if (isRealFont(latin1(head), path)) return head.slice()
          suspectFontBytes += body.byteLength
          if (suspectFontBytes > MAX_SNAPSHOT_SUSPECT_FONT_BYTES) {
            overBudgetFonts.add(path)
            return null
          }
          return body
        }
        const wanted = new Set(
          [...candidate.configs, ...candidate.fonts, ...candidate.sources].map((item) => item.path)
        )
        const read = await readRepoTarball(
          repo.owner, repo.repo, commitSha, wanted, headers, fetch, keepFromArchive
        )
        if (read.ok) {
          readMode = "tarball"
          tarballFiles = read.files
          selected = {
            ...candidate,
            fonts: candidate.fonts.filter((item) => !overBudgetFonts.has(item.path)),
            overLimit: [
              ...candidate.overLimit,
              ...candidate.fonts.filter((item) => overBudgetFonts.has(item.path)),
            ],
          }
        } else {
          readFallbackReason = read.reason
        }
      }
    }

    for (const item of selected.overLimit) {
      skip(item.path, "over-file-limit")
    }
    const filesToScan = [...selected.configs, ...selected.fonts, ...selected.sources]
    // Command targets discovered while reading configs join the queue later;
    // every blob is either queued or skipped, so a target is moved out of
    // the skipped list when it is queued.
    const blobsByPath = new Map(
      tree.tree.filter((item) => item.type === "blob").map((item) => [item.path, item])
    )
    const queued = new Set(filesToScan.map((item) => item.path))
    const commandTargets = new Set<string>()
    const installHooks: InstallHook[] = []
    const installHookFiles = new Set<string>()
    const unskip = (path: string) => {
      for (const listed of skippedByReason.values()) {
        const index = listed.findIndex((skipped) => skipped.path === path)
        if (index !== -1) {
          listed.splice(index, 1)
          break
        }
      }
      skippedCount--
    }

    // Check for hidden files with suspicious names
    const hiddenFiles = tree.tree.filter(
      (item) =>
        item.path.startsWith(".") &&
        !item.path.startsWith(".github") &&
        !item.path.startsWith(".git") &&
        item.type === "blob"
    )

    for (const hidden of hiddenFiles) {
      const basename = hidden.path.split("/").pop() ?? hidden.path
      if (/^\.(?:backdoor|payload|reverse[-_]?shell)(?:\.|$)/i.test(basename)) {
        findings.push({
          severity: "high",
          type: "HIDDEN_FILE",
          file: hidden.path,
          description: `Suspicious hidden file: ${hidden.path}`,
        })
        patternsMatched++
      }
    }

    const maliciousPackages = options.signatures.maliciousPackages
    const yaraRules = options.signatures.yaraRules
    // Rule ids present in the loaded signatures — built-in checks with a
    // data-driven twin yield to it, so one signal is never counted twice
    // (see BUILTIN_OBFUSCATION_RULE_IDS and the ruleId fields on the
    // pattern tables in the detectors below).
    const loadedRuleIds: ReadonlySet<string> = new Set(yaraRules.map((r) => r.id))

    const fileContents: Array<{ path: string; content: string }> = []
    const scannedFiles: string[] = []
    // Once GitHub starts refusing on budget, every remaining request would be
    // refused too: stop asking and record the rest as unread for that reason,
    // so the result can say the verdict is partial instead of implying the
    // unread files were clean.
    let rateLimited = false
    let fetchFailures = 0
    // Declared dependencies and the package names the repo defines itself,
    // matched against the OSV feed once every manifest has been read.
    const declaredDependencies: DeclaredDependency[] = []
    const localPackageNames = new Set<string>()

    // History signals need only the branch and commit, both known already,
    // so start their two requests now and collect them after the files are
    // read instead of paying for them at the end. Failure yields no signal
    // (it never rejects), so nothing here can fail the scan.
    const historySignals = fetchHistorySignals(
      `${repo.owner}/${repo.repo}`, branch, commitSha, headers
    )

    /**
     * Read one file. Pure I/O — it records nothing, so reads can overlap
     * while the bookkeeping below stays in queue order.
     */
    type FileRead =
      | { state: "read"; content: string }
      | { state: "rate-limited" }
      | { state: "failed" }
    const readFile = async (file: GitHubTreeItem): Promise<FileRead> => {
      // Already in hand from the tarball: no request, and the bytes are raw
      // rather than base64 round-tripped through atob.
      // Each path is queued once, so its bytes are released as soon as they
      // are decoded rather than held for the rest of the scan. A real font
      // arrives as just its head (`keepFromArchive`), which is all the
      // masquerade check reads of one.
      const fromTarball = tarballFiles?.get(file.path)
      if (fromTarball) {
        tarballFiles!.delete(file.path)
        return {
          state: "read",
          content: isFontFile(file.path)
            ? latin1(fromTarball)
            : UTF8.decode(fromTarball),
        }
      }
      // A queued file the tarball did not carry falls through to a request.
      // That is how command targets discovered later get read (they were not
      // in the wanted set), and it covers the entries `git archive` writes
      // without content, such as symlinks — whose target text the contents
      // API returns, exactly as it did before.

      // Once GitHub refuses on budget every later request would be refused
      // too, so queued reads that have not started are abandoned. Reads
      // already in flight are allowed to land: they cost nothing extra and
      // a file read is a file covered.
      if (rateLimited) return { state: "rate-limited" }

      const contentUrl = `https://api.github.com/repos/${repo.owner}/${repo.repo}/contents/${file.path}?ref=${commitSha}`
      const contentResponse = await fetch(contentUrl, { headers })

      if (!contentResponse.ok) {
        if (isRateLimitResponse(contentResponse)) {
          rateLimited = true
          return { state: "rate-limited" }
        }
        return { state: "failed" }
      }

      const fileData = await contentResponse.json()
      // atob() yields one Latin-1 char per byte. Decode text as UTF-8 so
      // non-ASCII detectors (invisible-Unicode payloads, bidi controls,
      // non-English comments) see real code points instead of mojibake.
      // Fonts stay byte strings for the magic-number check.
      const binary = atob(fileData.content || "")
      return {
        state: "read",
        content: isFontFile(file.path) ? binary : decodeUtf8(binary),
      }
    }

    /**
     * Account for and scan one file that has been read. Called strictly in
     * queue order, so every counter, finding and skip reason lands exactly
     * where the former sequential loop put it.
     */
    const analyzeFile = async (file: GitHubTreeItem, read: FileRead): Promise<void> => {
      if (read.state === "rate-limited") {
        skip(file.path, "rate-limited")
        return
      }
      if (read.state === "failed") {
        fetchFailures++
        skip(file.path, "fetch-failed")
        return
      }

      filesScanned++
      scannedFiles.push(file.path)

      const content = read.content

      if (
        (isConfigFile(file.path) && !runsOffHost(file.path)) ||
        file.path.endsWith("package.json")
      ) {
        for (const target of extractCommandTargets(content, file.path)) {
          if (commandTargets.size >= MAX_COMMAND_TARGETS) break
          const item = blobsByPath.get(target)
          if (!item || queued.has(target)) continue
          if (item.size !== undefined && item.size > MAX_FILE_SIZE_BYTES) continue
          unskip(target)
          queued.add(target)
          commandTargets.add(target)
          filesToScan.push(item)
        }
      }

      const isSource = SCANNABLE_EXTENSIONS.some((ext) => file.path.endsWith(ext))
      // A non-source file that a config runs with node is JavaScript.
      const runsAsJs = commandTargets.has(file.path) && !isSource && !isFontFile(file.path)

      // In JS/TS, blank out regex-literal interiors before pattern matching:
      // a regex *describing* a malicious pattern is inert data, and matching
      // it would flag every security tool, linter, and tutorial repo
      // (including this scanner's own source). Masking preserves offsets so
      // evidence line numbers stay true; strings/comments stay scannable.
      const isHtml = /\.html?$/i.test(file.path)
      const isJsTs = runsAsJs || /\.(?:[cm]?js|ts|[jt]sx)$/i.test(file.path)
      const scriptContent = isHtml ? maskExceptInlineScripts(content) : content
      let matchable = isJsTs || isHtml ? maskRegexLiterals(scriptContent) : scriptContent
      // In test files, string literals are fixtures — the inputs that prove
      // detectors work — so mask those too. Real malware in a test file is
      // actual code (the `npm test` attack) and stays fully scannable.
      if (isJsTs && isTestFile(file.path)) {
        matchable = maskStringLiterals(matchable)
      }

      if (isSource || runsAsJs) {
        fileContents.push({ path: file.path, content: matchable })
      }

      if (file.path.endsWith("package.json")) {
        try {
          const pkg = JSON.parse(content) as Record<string, unknown>
          if (typeof pkg.name === "string") localPackageNames.add(pkg.name)
          declaredDependencies.push(...npmDependencies(pkg, file.path))
        } catch {
          // Invalid JSON: nothing to match.
        }
        const pkgFindings = await scanPackageJson(content, maliciousPackages, file.path)
        findings.push(...pkgFindings)
        patternsMatched += pkgFindings.length
        dependenciesChecked += countDependencies(content)

        // A manifest under a test fixture declares lifecycle scripts because
        // that is what it is for: pnpm and npm both keep packages like
        // `test/fixtures/with-many-scripts/package.json` to exercise their
        // own installer. Reading those as a supply-chain attack scored
        // pnpm/pnpm 1.000 and npm/cli 0.617 on the reference corpus. The
        // data-driven rules already skip test paths; this built-in did not.
        // Dependency checks above stay on — a fixture pinning a known
        // malicious package is still worth saying.
        if (!isTestFile(file.path)) {
          const postinstallFindings = checkPostinstallScripts(content, file.path)
          findings.push(...postinstallFindings)
          patternsMatched += postinstallFindings.length
          installHooks.push(...readInstallHooks(content, file.path))
        }
      }

      if (isFontFile(file.path)) {
        const masquerade = detectMasqueradedScript(content, file.path)
        findings.push(...masquerade)
        patternsMatched += masquerade.length
        return
      }

      // Editor/agent/CI configs, docs and package manifests: data-driven
      // rules only (scoped by each rule's fileExtensions / fileNames).
      if (!isSource && (isConfigFile(file.path) || file.path.endsWith("package.json"))) {
        const configFindings = applyYaraRules(
          content,
          yaraRules,
          file.path,
          configRuleScope(file.path)
        )
        findings.push(...configFindings)
        patternsMatched += configFindings.length
        if (/^README/i.test(file.path.split("/").pop() ?? file.path)) {
          const socialFindings = detectSocialEngineering(content, file.path)
          findings.push(...socialFindings)
          patternsMatched += socialFindings.length
        }
      }

      if (file.path.endsWith("requirements.txt") || file.path.endsWith("setup.py")) {
        declaredDependencies.push(...pythonDependencies(content, file.path))
        const pyFindings = scanPythonDeps(content, maliciousPackages, file.path)
        findings.push(...pyFindings)
        patternsMatched += pyFindings.length
      }

      if (isSource || runsAsJs) {
        const ruleScopePath = isHtml || runsAsJs ? `${file.path}.js` : file.path
        const yaraFindings = applyYaraRules(matchable, yaraRules, file.path, ruleScopePath)
        findings.push(...yaraFindings)
        patternsMatched += yaraFindings.length

        const obfuscationFindings = detectObfuscation(matchable, file.path, loadedRuleIds)
        findings.push(...obfuscationFindings)
        patternsMatched += obfuscationFindings.length
      }
    }

    // Read each generation of the queue concurrently, then analyze it in
    // queue order. Analyzing a config or manifest can append the files it
    // runs with node (`commandTargets`) to the queue, so the queue is drained
    // generation by generation rather than in one pass: generation 1 is the
    // configs, fonts and sources chosen above, generation 2 the targets they
    // name, and so on until nothing new is appended (MAX_COMMAND_TARGETS
    // bounds it). Sequencing reads this way keeps the file order — and so
    // every counter, finding and skip reason — identical to reading one by
    // one, while spending a fraction of the wall time.
    let cursor = 0
    const drainQueue = async () => {
      while (cursor < filesToScan.length) {
        const generation = filesToScan.slice(cursor)
        cursor = filesToScan.length
        const reads = await mapPool(generation, FETCH_CONCURRENCY, readFile)
        for (let index = 0; index < generation.length; index++) {
          await analyzeFile(generation[index]!, reads[index]!)
        }
      }
    }
    await drainQueue()

    // Install hooks are scored by what the script they run can do, so read
    // that script and the local modules it imports. A hook target may have
    // been analyzed before its manifest named it, so the closure is worked
    // out here, once everything queued so far has been read.
    const scannedContent = new Map(fileContents.map((file) => [file.path, file.content]))
    for (let depth = 0; depth < MAX_INSTALL_HOOK_IMPORT_DEPTH && installHooks.length > 0; depth++) {
      let queuedMore = false
      for (const path of installHookClosure(installHooks, scannedContent)) {
        if (scannedContent.has(path) || queued.has(path)) continue
        if (installHookFiles.size >= MAX_INSTALL_HOOK_FILES) break
        const item = blobsByPath.get(path)
        if (!item || (item.size !== undefined && item.size > MAX_FILE_SIZE_BYTES)) continue
        installHookFiles.add(path)
        unskip(path)
        queued.add(path)
        commandTargets.add(path)
        filesToScan.push(item)
        queuedMore = true
      }
      if (!queuedMore) break
      await drainQueue()
      for (const file of fileContents) scannedContent.set(file.path, file.content)
    }
    applyInstallHookCapabilities(
      findings,
      installHooks,
      scannedContent,
      (path) => blobsByPath.has(path) || tree.truncated
    )

    if (options.osvFeed) {
      const alreadyFlagged = new Set(
        findings
          .filter((finding) => finding.type === "SUSPICIOUS_DEPENDENCY" && finding.package)
          .map((finding) => finding.package!)
      )
      const osvFindings = matchOsvFeed(options.osvFeed, declaredDependencies, localPackageNames, alreadyFlagged)
      findings.push(...osvFindings)
      patternsMatched += osvFindings.length
    }

    // Non-English comment detection (source files only, not tests)
    const sourceFiles = fileContents.filter((f) => !isTestFile(f.path))
    const languageFindings = await detectNonEnglishComments(sourceFiles, repo)
    findings.push(...languageFindings)
    patternsMatched += languageFindings.length

    // Comprehensive security checks
    for (const file of fileContents) {
      const secretFindings = detectHardcodedSecrets(file.content, file.path, loadedRuleIds)
      findings.push(...secretFindings)
      patternsMatched += secretFindings.length

      const networkFindings = detectNetworkPatterns(file.content, file.path, loadedRuleIds)
      findings.push(...networkFindings)
      patternsMatched += networkFindings.length

      const miningFindings = detectCryptoMining(file.content, file.path, loadedRuleIds)
      findings.push(...miningFindings)
      patternsMatched += miningFindings.length

      const exfiltrationFindings = detectDataExfiltration(file.content, file.path, loadedRuleIds)
      findings.push(...exfiltrationFindings)
      patternsMatched += exfiltrationFindings.length

      const backdoorFindings = detectBackdoors(file.content, file.path, loadedRuleIds)
      findings.push(...backdoorFindings)
      patternsMatched += backdoorFindings.length

      const fileAccessFindings = detectSuspiciousFileAccess(file.content, file.path, loadedRuleIds)
      findings.push(...fileAccessFindings)
      patternsMatched += fileAccessFindings.length

      const socialEngFindings = detectSocialEngineering(file.content, file.path)
      findings.push(...socialEngFindings)
      patternsMatched += socialEngFindings.length
    }

    for (const file of fileContents) {
      if (file.path.endsWith("package.json")) {
        const packageNameFindings = detectSuspiciousPackageNames(file.content, file.path)
        findings.push(...packageNameFindings)
        patternsMatched += packageNameFindings.length

        const supplyChainFindings = detectSupplyChainRisks(file.content, file.path)
        findings.push(...supplyChainFindings)
        patternsMatched += supplyChainFindings.length
      }
    }

    // Pass every path in the tree (not just scanned source) so the
    // LICENSE/README presence checks see non-code files — otherwise they
    // false-positive on every repo.
    const allPaths = tree.tree.filter((i) => i.type === "blob").map((i) => i.path)
    const integrityFindings = await detectCodeIntegrityIssues(fileContents, allPaths, repo)
    findings.push(...integrityFindings)
    patternsMatched += integrityFindings.length

    // Pushes are timestamped by GitHub, not by the committer — compare them
    // with commit dates to catch backdated, force-pushed history. Requested
    // before the file reads; this only collects the answer.
    const historyFindings = await historySignals
    findings.push(...historyFindings)
    patternsMatched += historyFindings.length

    const rawRiskScore = calculateRawRiskScore(findings)
    const riskScore = calculateRiskScore(findings)
    const riskLevel = getRiskLevel(riskScore, findings)
    const cloneBlockingFindings = findings.filter((finding) => finding.cloneBlocking !== false)
    const cloneRiskScore = calculateRiskScore(cloneBlockingFindings)
    const cloneRiskLevel = getRiskLevel(cloneRiskScore, cloneBlockingFindings)

    return {
      riskScore,
      rawRiskScore,
      riskLevel,
      // One factor per deduped signal, carrying the confidence-adjusted
      // weight actually counted — factors always sum to rawRiskScore, so
      // consumers can render a deduction breakdown that reconciles.
      factors: calculateSignalContributions(findings).map((c) => ({
        factor: c.finding.type,
        weight: c.weight,
        description: c.findingCount > 1
          ? `${c.finding.description} (strongest of ${c.findingCount} matches counted once)`
          : c.finding.description,
      })),
      disclaimer: DEFAULT_DISCLAIMER,
      repo,
      commitSha,
      scanSummary: {
        filesScanned,
        patternsMatched,
        dependenciesChecked,
        scannedFiles,
        skippedFiles: SKIP_LIST_ORDER.flatMap((reason) => skippedByReason.get(reason)!)
          .slice(0, MAX_SKIPPED_FILES_LISTED),
        skippedCount,
        treeTruncated: tree.truncated,
        readMode,
        ...(readFallbackReason ? { readFallbackReason } : {}),
        complete: !rateLimited && fetchFailures === 0,
        ...(rateLimited
          ? { incompleteReason: "rate-limit" as const }
          : fetchFailures > 0
            ? { incompleteReason: "fetch-errors" as const }
            : {}),
      },
      findings,
      safeToClone: cloneRiskLevel === "low",
      scannedAt: new Date(),
    }
  } catch (error) {
    throw error
  }
}

// ─── Package scanning ─────────────────────────────────────────────────────────

async function scanPackageJson(
  content: string,
  maliciousPackages: MaliciousPackage[],
  filePath: string
): Promise<GitHubFinding[]> {
  const findings: GitHubFinding[] = []

  try {
    const pkg = JSON.parse(content)
    // Resolve `"alias": "npm:real-package@range"` to what npm installs before
    // any name is checked. The alias key is a local name of the repo's own
    // choosing, so matching it both reports packages the repo never installs
    // and misses the ones it does — see resolveNpmAlias.
    const allDeps = Object.fromEntries(
      Object.entries({ ...pkg.dependencies, ...pkg.devDependencies }).map(([key, raw]) => {
        const { name, spec } = resolveNpmAlias(key, typeof raw === "string" ? raw : "")
        return [name, spec]
      })
    )

    // Typosquat candidates each need a download count from npm. Resolve them
    // together rather than one await per dependency: a manifest with several
    // near-miss names otherwise serializes a request per name. Findings are
    // still appended in dependency order below.
    const typosquatCandidates = Object.keys(allDeps)
      .filter((name) => !name.startsWith("@"))
      .map((name) => ({ name, typosquat: checkTyposquat(name) }))
      .filter((candidate): candidate is { name: string; typosquat: string } =>
        candidate.typosquat !== null
      )
    const downloadsByName = new Map(
      await Promise.all(
        typosquatCandidates.map(
          async ({ name }) => [name, await getNpmWeeklyDownloads(name)] as const
        )
      )
    )
    const typosquatOf = new Map(
      typosquatCandidates.map(({ name, typosquat }) => [name, typosquat])
    )

    for (const [name, declaredVersion] of Object.entries(allDeps)) {
      const malicious = maliciousPackages.find((m) => m.name === name)
      if (malicious && isAffectedPackageVersion(malicious, declaredVersion)) {
        findings.push({
          severity: malicious.severity as GitHubFinding["severity"],
          confidence: "high",
          type: "SUSPICIOUS_DEPENDENCY",
          file: filePath,
          package: name,
          description: `Known malicious package: ${name}`,
        })
      }

      const typosquat = typosquatOf.get(name)
      if (typosquat) {
        const weeklyDownloads = downloadsByName.get(name) ?? null
        const shouldFlag = weeklyDownloads === null || weeklyDownloads < NPM_HIGH_DOWNLOAD_THRESHOLD
        if (shouldFlag) {
          findings.push({
            severity: "medium",
            type: "TYPOSQUAT_PACKAGE",
            file: filePath,
            package: name,
            description: `Possible typosquat of "${typosquat}": ${name}`,
          })
        }
      }
    }
  } catch {
    // Invalid JSON, skip
  }

  return findings
}

function isAffectedPackageVersion(
  malicious: MaliciousPackage,
  declaredVersion: unknown
): boolean {
  const affected = malicious.versions ?? (malicious.version ? [malicious.version] : [])
  if (affected.length === 0) return true
  if (typeof declaredVersion !== "string") return false

  let specifier = declaredVersion.trim()
  if (specifier.startsWith("workspace:")) specifier = specifier.slice("workspace:".length)
  const npmAlias = specifier.match(/^npm:.+@([^@]+)$/)
  if (npmAlias) specifier = npmAlias[1]!

  return specifier.split(/\s*\|\|\s*/).some((part) => {
    const normalized = part.trim().replace(/^[=v~^\s]+/, "")
    return affected.includes(normalized)
  })
}

/**
 * An install script that reaches the network. Substring tests were too blunt:
 * `includes("http")` matched a docs URL in an echo, and `includes("fetch")`
 * matched `prefetch` and `fetch-depth`.
 */
const NETWORK_IN_INSTALL_SCRIPT = /\b(?:curl|wget)\b|https?:\/\/|\bfetch\b/

/**
 * An install script that executes code it builds or downloads at run time.
 *
 * Rated critical, and `includes("exec")` was enough to reach it, so
 * `npm exec`, `pnpm exec`, `yarn exec` and `nub exec --node fumadocs-mdx`
 * all qualified — a package manager running a local binary is the ordinary
 * shape of a postinstall. `includes("eval")` matched `evaluate`.
 *
 * What executes code built or fetched at run time: a shell `eval`, a runtime
 * given inline code (`node -e`, `deno eval`), a `child_process` call, an
 * `exec(` call rather than an `exec` subcommand, or a command substitution
 * feeding a download into the shell.
 */
/**
 * `node -e 'process.exit(0)'` as a lifecycle script is a deliberate no-op —
 * electron uses one to stop `npm install` doing anything — and it executes
 * nothing. Matching it on `node -e` alone made electron's root manifest a
 * critical finding.
 */
const INERT_INLINE_SCRIPT =
  /^(?:node|nodejs|bun|deno)\s+(?:-e|--eval)\s+(['"])\s*process\.exit\(\s*\d*\s*\)\s*;?\s*\1$/

const DYNAMIC_EXECUTION_IN_INSTALL_SCRIPT =
  /(?:^|[\s;&|(`])eval[\s"'`$(]|(?:^|[\s;&|(`])(?:node|nodejs|bun|deno)\s+(?:-e\b|--eval\b|-p\b|--print\b|eval\b)|child_process|\bexec(?:Sync|File|FileSync)?\s*\(|\$\(\s*(?:curl|wget)\b/

// ─── Install hooks scored by capability ───────────────────────────────────────

/**
 * An npm lifecycle script that runs on `npm install`. Having one is not a
 * finding: native addons, platform-binary launchers and build steps all use
 * them. What a hook can do is the finding.
 */
export interface InstallHook {
  manifest: string
  hook: string
  command: string
  /** Repo paths the command runs with node/bun/deno/tsx. */
  targets: string[]
}

const INSTALL_HOOK_NAMES = ["preinstall", "install", "postinstall"] as const
const MAX_INSTALL_HOOK_FILES = 20
const MAX_INSTALL_HOOK_IMPORT_DEPTH = 3

/**
 * Rules that recognise an install hook by its shape alone — a campaign's
 * `preinstall: node setup.mjs` — rather than by anything the hook does. The
 * shape is right, and pnpm's own `@pnpm/exe` has it: `preinstall: node
 * setup.js`, which links the platform binary into place. So these findings
 * are rated by what the script they run can do (see
 * `applyInstallHookCapabilities`).
 */
const INSTALL_HOOK_SHAPE_RULES = new Set(["SUPPLY_CHAIN_PREINSTALL_SETUP_DROPPER"])

export function readInstallHooks(content: string, manifest: string): InstallHook[] {
  let scripts: Record<string, unknown>
  try {
    scripts = (JSON.parse(content) as { scripts?: Record<string, unknown> }).scripts ?? {}
  } catch {
    return []
  }
  const hooks: InstallHook[] = []
  for (const hook of INSTALL_HOOK_NAMES) {
    const command = scripts[hook]
    if (typeof command !== "string" || command.trim() === "") continue
    hooks.push({ manifest, hook, command, targets: extractCommandTargets(command, manifest) })
  }
  return hooks
}

const LOCAL_IMPORT =
  /(?:\bimport\s+(?:[\w*{}\s,$]+\s+from\s+)?|\bimport\s*\(\s*|\brequire\s*\(\s*)['"](\.{1,2}\/[^'"]+)['"]/g
const IMPORT_EXTENSIONS = ["", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", "/index.js", "/index.mjs", "/index.ts"]

/** Hook targets plus every local module they import, as far as has been read. */
export function installHookClosure(
  hooks: readonly InstallHook[],
  contents: ReadonlyMap<string, string>
): string[] {
  const seen = new Set<string>()
  const pending = hooks.flatMap((hook) => hook.targets)
  while (pending.length > 0 && seen.size < MAX_INSTALL_HOOK_FILES * 4) {
    const path = pending.shift()!
    if (seen.has(path)) continue
    seen.add(path)
    const content = contents.get(path)
    if (content === undefined) continue
    const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : ""
    for (const match of content.matchAll(LOCAL_IMPORT)) {
      const base = resolveRepoPath(dir, match[1]!)
      if (!base) continue
      const resolved =
        IMPORT_EXTENSIONS.map((ext) => base + ext).find((candidate) => contents.has(candidate)) ??
        (/\.[cm]?[jt]s$/.test(base) ? base : `${base}.js`)
      pending.push(resolved)
    }
  }
  return [...seen]
}

/**
 * What an install-time script can do that makes running it on `npm install`
 * dangerous. Running local build steps, linking a binary, or writing inside
 * the package is none of these.
 */
const INSTALL_CAPABILITIES: Array<{ label: string; test: (text: string) => boolean }> = [
  {
    label: "downloads and executes code",
    test: (text) =>
      /\bfetch\s*\(|\bhttps?\.(?:get|request)\s*\(|require\s*\(\s*['"](?:node:)?https?['"]\s*\)|from\s+['"](?:node:)?https?['"]|\baxios\b|\bgot\s*\(|\bundici\b|XMLHttpRequest|\bcurl\b|\bwget\b|Invoke-WebRequest|\biwr\b|new\s+WebSocket\b/i.test(text) &&
      /\bchild_process\b|\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(|\beval\s*\(|new\s+Function\b|\bvm\.(?:run\w*|Script)\b|\bBun\.spawn|\|\s*(?:ba|z)?sh\b/i.test(text),
  },
  {
    label: "writes outside the project",
    test: (text) =>
      /\b(?:writeFile\w*|appendFile\w*|copyFile\w*|createWriteStream|cpSync|renameSync|symlinkSync|linkSync|mkdirSync)\s*\(|>>?\s*["']?[~$/]/i.test(text) &&
      /\bhomedir\s*\(|process\.env\.(?:HOME|USERPROFILE|APPDATA|LOCALAPPDATA|XDG_\w+)\b|\$HOME\b|['"`]~\/|['"`]\/(?:etc|usr|Library|var|opt|System)\/|\.(?:bashrc|zshrc|bash_profile|profile)\b|LaunchAgents|crontab|systemd\/|[\\/]\.claude[\\/]|[\\/]\.vscode[\\/]|[\\/]\.ssh[\\/]/i.test(text),
  },
  {
    label: "reads credentials or the environment",
    test: (text) =>
      /JSON\.stringify\s*\(\s*process\.env\s*\)|Object\.(?:keys|entries|values)\s*\(\s*process\.env\s*\)|\bos\.environ\s*(?:\)|\.copy|\.items)|\.npmrc\b|\.ssh[\\/]|\bid_(?:rsa|ed25519)\b|\.aws[\\/]|\.docker[\\/]config|\b(?:NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|NODE_AUTH_TOKEN|AWS_SECRET_ACCESS_KEY)\b|trufflehog|find-(?:generic|internet)-password|Login Data|\bwallet\.dat\b/i.test(text),
  },
  {
    label: "is obfuscated",
    test: (text) =>
      /\b_0x[0-9a-f]{4,}\b|\b(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from)\b|String\.fromCharCode\s*\((?:\s*\d+\s*,){8}|[A-Za-z0-9+/]{400,}={0,2}|(?:\\x[0-9a-f]{2}){24}|(?:\\u[0-9a-f]{4}){24}/i.test(text),
  },
]

export function installHookCapabilities(texts: readonly string[]): string[] {
  const text = texts.join("\n")
  return INSTALL_CAPABILITIES.filter(({ test }) => test(text)).map(({ label }) => label)
}

/**
 * Rate shape-only install-hook findings by what the hook's script can do.
 *
 * - Every file the hook runs is in the repository and was read, and none of
 *   it downloads-and-executes, writes outside the project, reads
 *   credentials or the environment, or is obfuscated: informational.
 * - Any of those capabilities: the rule's own severity, with the capability
 *   named.
 * - A script the hook runs is not in the repository: the rule's own
 *   severity. The code that runs on `npm install` cannot be reviewed from
 *   the source, which is the concealment the rule exists for.
 * - A file that exists but was not read: unchanged — not knowing is not
 *   evidence of safety.
 *
 * Reputation (stars, age, owner) plays no part: a popular repository whose
 * hook gains one of these capabilities is the attack this is here for.
 */
export function applyInstallHookCapabilities(
  findings: GitHubFinding[],
  hooks: readonly InstallHook[],
  contents: ReadonlyMap<string, string>,
  inRepository: (path: string) => boolean
): void {
  for (const finding of findings) {
    if (!finding.pattern || !INSTALL_HOOK_SHAPE_RULES.has(finding.pattern)) continue
    const manifestHooks = hooks.filter((hook) => hook.manifest === finding.file && hook.targets.length > 0)
    if (manifestHooks.length === 0) continue
    const files = installHookClosure(manifestHooks, contents)
    const targets = manifestHooks.flatMap((hook) => hook.targets)
    const missing = targets.filter((path) => !inRepository(path))
    const unread = files.filter((path) => !missing.includes(path) && inRepository(path) && !contents.has(path))
    const names = manifestHooks.map((hook) => `${hook.hook}: ${hook.command}`).join("; ")
    if (missing.length > 0) {
      finding.description += ` The hook runs ${missing.join(", ")}, which is not in the repository, so what it does on install cannot be reviewed.`
      continue
    }
    if (unread.length > 0) continue
    const capabilities = installHookCapabilities([
      ...manifestHooks.map((hook) => hook.command),
      ...files.map((path) => contents.get(path) ?? ""),
    ])
    if (capabilities.length > 0) {
      finding.description += ` The script it runs ${capabilities.join(", ")}.`
      continue
    }
    finding.severity = "info"
    finding.confidence = "high"
    finding.cloneBlocking = false
    finding.description =
      `Install hook (${names}) runs local setup only: no download-and-execute, no writes outside the ` +
      `project, no credential or environment access, no obfuscation in ${files.join(", ")}.`
    finding.codeExplanation =
      "This script runs on `npm install` (not on clone). It was read in full and does only local setup."
  }
}

function checkPostinstallScripts(content: string, filePath: string): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  try {
    const pkg = JSON.parse(content)
    const scripts = pkg.scripts || {}
    const dangerousScripts = ["postinstall", "preinstall", "install"]

    for (const scriptName of dangerousScripts) {
      const script = scripts[scriptName]
      if (script) {
        if (NETWORK_IN_INSTALL_SCRIPT.test(script)) {
          findings.push({
            severity: "high",
            type: "POSTINSTALL_SCRIPT",
            file: filePath,
            description: `${scriptName} script makes network requests: "${script.slice(0, 50)}..."`,
          })
        }
        if (
          DYNAMIC_EXECUTION_IN_INSTALL_SCRIPT.test(script) &&
          !INERT_INLINE_SCRIPT.test(script.trim())
        ) {
          findings.push({
            severity: "critical",
            type: "POSTINSTALL_SCRIPT",
            file: filePath,
            description: `${scriptName} script executes dynamic code`,
          })
        }
      }
    }
  } catch {
    // Invalid JSON
  }

  return findings
}

function scanPythonDeps(
  content: string,
  maliciousPackages: MaliciousPackage[],
  filePath: string
): GitHubFinding[] {
  const findings: GitHubFinding[] = []
  const lines = content.split("\n")

  for (const line of lines) {
    const pkgMatch = line.match(/^([a-zA-Z0-9_-]+)/)
    if (pkgMatch) {
      const name = pkgMatch[1]!
      const malicious = maliciousPackages.find(
        (m) => m.name.toLowerCase() === name.toLowerCase()
      )
      if (malicious) {
        findings.push({
          severity: malicious.severity as GitHubFinding["severity"],
          confidence: "high",
          type: "SUSPICIOUS_DEPENDENCY",
          file: filePath,
          package: name,
          description: `Known malicious Python package: ${name}`,
        })
      }
    }
  }

  return findings
}

// ─── Masqueraded scripts ──────────────────────────────────────────────────────

const FONT_MAGIC = ["wOFF", "wOF2", "\u0000\u0001\u0000\u0000", "OTTO", "true", "ttcf"]
const SCRIPT_TOKENS =
  /\b(?:require\s*\(|import\s+[\w{*]|function\s*\w*\s*\(|const\s+\w+\s*=|let\s+\w+\s*=|var\s+\w+\s*=|eval\s*\(|new\s+Function|module\.exports|process\.env|child_process)/

/**
 * A font file whose bytes are printable text containing JavaScript is not a
 * font: it is a loader waiting for `node <file>` (task file, hook, script).
 */
/**
 * The font's magic number is where it should be. `content` is one character
 * per byte; the first FONT_SNIFF_BYTES are enough.
 */
function isRealFont(content: string, filePath: string): boolean {
  if (FONT_MAGIC.some((magic) => content.startsWith(magic))) return true
  // EOT: "LP" magic at byte offset 34.
  return filePath.toLowerCase().endsWith(".eot") && content.slice(34, 36) === "LP"
}

export function detectMasqueradedScript(content: string, filePath: string): GitHubFinding[] {
  if (isRealFont(content, filePath)) return []
  // Git LFS pointers are text by design.
  if (content.startsWith("version https://git-lfs.github.com/spec/")) return []
  const head = content.slice(0, 8192)
  if (head.length === 0) return []
  let printable = 0
  for (let index = 0; index < head.length; index++) {
    const code = head.charCodeAt(index)
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code < 127)) printable++
  }
  if (printable / head.length < 0.95 || !SCRIPT_TOKENS.test(content)) return []
  return [{
    severity: "critical",
    confidence: "high",
    type: "OBFUSCATED_CODE",
    pattern: "MASQUERADED_SCRIPT_FONT",
    file: filePath,
    description: `JavaScript disguised as a font file: ${filePath}`,
    codeSnippet: content.trimStart().slice(0, 200),
    codeExplanation:
      "🎭 This file has a font extension but contains readable JavaScript, not font data. Fake font files are run with `node <file>` from VS Code tasks or hooks to hide a loader from code review.",
  }]
}

// ─── Obfuscation detection ────────────────────────────────────────────────────

/**
 * Built-in obfuscation checks and their data-driven twins in
 * flagrix-detection-rules (rules/github/obfuscation.yaml). When the loaded
 * signatures ship a rule, the rule owns the signal and the built-in check is
 * skipped — otherwise the same base64 blob (etc.) is flagged twice and the
 * double-counted weight inflates the risk score. The built-ins remain as the
 * fallback for signature sets that lack these rules.
 */
const BUILTIN_OBFUSCATION_RULE_IDS = {
  base64: "OBF_BASE64_HEAVY",
  hex: "OBF_HEX_STRINGS",
  eval: "OBF_EVAL",
  newFunction: "OBF_NEW_FUNCTION",
  timerString: "OBF_SETTIMEOUT_STRING",
  longLine: "OBF_LONG_LINE"
} as const

function detectObfuscation(
  content: string,
  filePath: string,
  coveredRuleIds: ReadonlySet<string> = new Set()
): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  if (isTestFile(filePath)) return findings

  // Heavy Base64 usage
  const base64Matches = coveredRuleIds.has(BUILTIN_OBFUSCATION_RULE_IDS.base64)
    ? null
    : content.match(/[A-Za-z0-9+/]{50,}={0,2}/g)
  if (base64Matches && base64Matches.length > 5) {
    const snippet =
      base64Matches.slice(0, 3).join("\n") + (base64Matches.length > 3 ? "\n... and more" : "")
    findings.push({
      severity: "medium",
      type: "OBFUSCATED_CODE",
      file: filePath,
      description: "Heavy Base64 encoding detected (possible data exfiltration)",
      codeSnippet: snippet,
      codeExplanation:
        "🔓 Multiple Base64-encoded strings found. Base64 is commonly used to hide malicious payloads, URLs, or commands from code reviewers.",
    })
  }

  // Hex-encoded strings
  const hexMatches = coveredRuleIds.has(BUILTIN_OBFUSCATION_RULE_IDS.hex)
    ? null
    : content.match(/\\x[0-9a-fA-F]{2}/g)
  if (hexMatches && hexMatches.length > 20) {
    findings.push({
      severity: "medium",
      type: "OBFUSCATED_CODE",
      file: filePath,
      description: "Extensive hex-encoded strings detected",
      codeSnippet: hexMatches.slice(0, 15).join("") + "...",
      codeExplanation:
        "🔤 Hex-encoded strings detected. This obfuscation technique hides the actual string content, often used to conceal malicious URLs or commands.",
    })
  }

  // eval/Function constructor abuse
  const evalPatterns = [
    // Non-empty argument required: bare "eval()" appears in prose/docs.
    { pattern: /eval\s*\(\s*[^)\s][^)]{0,200}\)/gi, name: "eval", ruleId: BUILTIN_OBFUSCATION_RULE_IDS.eval },
    { pattern: /new\s+Function\s*\([^)]{0,200}\)/gi, name: "Function constructor", ruleId: BUILTIN_OBFUSCATION_RULE_IDS.newFunction },
    { pattern: /setTimeout\s*\(\s*["'`][^"'`]{0,200}["'`]/gi, name: "setTimeout with string", ruleId: BUILTIN_OBFUSCATION_RULE_IDS.timerString },
    { pattern: /setInterval\s*\(\s*["'`][^"'`]{0,200}["'`]/gi, name: "setInterval with string", ruleId: BUILTIN_OBFUSCATION_RULE_IDS.timerString },
  ].filter(({ ruleId }) => !coveredRuleIds.has(ruleId))

  for (const { pattern, name } of evalPatterns) {
    const matches = content.match(pattern)
    if (matches && matches.length > 0) {
      const snippet = matches[0]!
      findings.push({
        severity: "high",
        type: "OBFUSCATED_CODE",
        file: filePath,
        description: `Dynamic code execution pattern detected (${name})`,
        codeSnippet: snippet.length > 200 ? snippet.substring(0, 200) + "..." : snippet,
        codeExplanation: explainSuspiciousCode(snippet, "OBFUSCATED_CODE"),
      })
      break
    }
  }

  // Suspiciously long lines (hidden code attack)
  const hiddenCodePatterns = [
    /eval\s*\(/i,
    /exec\s*\(/i,
    /fetch\s*\(/i,
    /XMLHttpRequest/i,
    /\$\(.+\)\s*\(/,
    /window\.location\s*=/i,
    /document\.write\s*\(/i,
    /\.innerHTML\s*=/i,
    /child_process/i,
    /require\s*\(\s*['"]fs['"]\s*\)/,
    /atob\s*\(/i,
    /fromCharCode/i,
  ]

  const lines = coveredRuleIds.has(BUILTIN_OBFUSCATION_RULE_IDS.longLine)
    ? []
    : content.split("\n")
  const suspiciousLines: Array<{ lineNum: number; length: number; hasMaliciousPattern: boolean }> = []

  lines.forEach((line, index) => {
    if (line.length > 5000) {
      const hasMaliciousPattern = hiddenCodePatterns.some((pattern) => pattern.test(line))
      suspiciousLines.push({ lineNum: index + 1, length: line.length, hasMaliciousPattern })
    }
  })

  if (suspiciousLines.length > 0) {
    const maxLength = Math.max(...suspiciousLines.map((l) => l.length))
    const linesWithMaliciousCode = suspiciousLines.filter((l) => l.hasMaliciousPattern)
    const lineDetails = suspiciousLines
      .slice(0, 3)
      .map(
        (l) =>
          `Line ${l.lineNum} (${l.length.toLocaleString()} chars${l.hasMaliciousPattern ? ", contains suspicious code" : ""})`
      )
      .join(", ")

    // Long lines are common in generated assets and lookup tables. Even when
    // they contain a risky token, length alone does not establish malware.
    const severity = "medium" as const
    const firstLine = lines[suspiciousLines[0]!.lineNum - 1]!
    const codeSnippet = extractCodeSnippet(firstLine)
    const codeExplanation = explainSuspiciousCode(firstLine, "OBFUSCATED_CODE")

    findings.push({
      severity,
      confidence: linesWithMaliciousCode.length > 0 ? "medium" : "low",
      type: "OBFUSCATED_CODE",
      file: filePath,
      line: suspiciousLines[0]!.lineNum,
      description: `Extremely long line detected (${maxLength.toLocaleString()} characters). ${linesWithMaliciousCode.length > 0 ? "Contains suspicious code patterns like eval/exec/fetch. " : ""}Malicious code may be hidden far to the right. Affected: ${lineDetails}`,
      codeSnippet,
      codeExplanation,
    })
  }

  return findings
}

function explainSuspiciousCode(code: string, type: string): string {
  const explanations: string[] = []

  if (/eval\s*\(/i.test(code)) explanations.push("⚠️ Uses eval() to execute dynamic code - can run arbitrary malicious commands")
  if (/exec\s*\(/i.test(code)) explanations.push("⚠️ Executes system commands - can run shell scripts and steal data")
  if (/child_process/i.test(code)) explanations.push("⚠️ Spawns child processes - can execute arbitrary programs on your system")
  if (/atob\s*\(/i.test(code)) explanations.push("🔓 Decodes Base64 data - often used to hide malicious payloads")
  if (/fromCharCode/i.test(code)) explanations.push("🔤 Constructs strings from character codes - obfuscation technique to hide malicious code")
  if (/fetch\s*\(|XMLHttpRequest|axios\./i.test(code)) explanations.push("🌐 Makes network requests - could send your data to attacker's server")
  if (/document\.write|\.innerHTML\s*=/i.test(code)) explanations.push("📝 Injects HTML/scripts into page - can steal credentials or modify the page")
  if (/window\.location\s*=/i.test(code)) explanations.push("🔀 Redirects browser - can send you to phishing sites")
  if (/require\s*\(\s*['"]fs['"]\s*\)/i.test(code)) explanations.push("📁 Accesses file system - can read/write/delete files on your computer")
  if (/process\.env/i.test(code)) explanations.push("🔐 Accesses environment variables - can steal API keys and credentials")
  if (/crypto|password|token|api[_-]?key/i.test(code)) explanations.push("🔑 References sensitive data - may be attempting to steal credentials")
  if (/discord\.gg|pastebin\.com|bit\.ly|tinyurl/i.test(code)) explanations.push("🔗 Contains suspicious URLs - likely data exfiltration endpoint")
  if (type === "OBFUSCATED_CODE" && code.length > 1000) explanations.push("📏 Extremely long/complex code - intentionally obfuscated to hide malicious intent")

  return explanations.length > 0
    ? explanations.join("\n")
    : "This code contains suspicious patterns that may indicate malicious intent. Review carefully before running."
}

function extractCodeSnippet(line: string, maxLength = 500): string {
  if (line.length > maxLength) {
    const patterns = [
      /eval\s*\([^)]{0,200}\)/i,
      /exec\s*\([^)]{0,200}\)/i,
      /atob\s*\([^)]{0,200}\)/i,
      /fetch\s*\([^)]{0,200}\)/i,
      /require\s*\(\s*['"][^'"]+['"]\s*\)/i,
    ]

    for (const pattern of patterns) {
      const match = line.match(pattern)
      if (match) {
        const matchStart = match.index || 0
        const start = Math.max(0, matchStart - 100)
        const end = Math.min(line.length, matchStart + match[0].length + 100)
        const snippet = line.substring(start, end)
        return (start > 0 ? "..." : "") + snippet + (end < line.length ? "..." : "")
      }
    }

    return (
      line.substring(0, 250) +
      " ... [" +
      (line.length - 500).toLocaleString() +
      " chars hidden] ... " +
      line.substring(line.length - 250)
    )
  }

  return line
}

// ─── Non-English comment detection ───────────────────────────────────────────

// Which Latin-script language a short code comment is in can't be told
// reliably: franc-min reads plain English ("check if a dev import is already
// present") as Portuguese, and lint directives as French. Script can be told
// reliably. A comment counts as non-English when most of its letters are in a
// non-Latin script (Han, Kana, Hangul, Cyrillic, Arabic, …); franc only names
// that language. Amounts are measured in letters.
const LETTER = /\p{L}/gu
const NON_LATIN_LETTER = /(?!\p{Script=Latin})\p{L}/gu
const NON_LATIN_SHARE_FOR_COMMENT = 0.5
// Conservative: only a substantial volume of clearly non-English comment text.
const MIN_LETTERS_TO_ANALYZE = 150
const NON_ENGLISH_THRESHOLD = 0.25
const MIN_NON_ENGLISH_LETTERS = 40

// Tool directives are not prose (franc reads `eslint-disable …` as French).
const COMMENT_DIRECTIVE =
  /^(?:eslint|@ts-|prettier-ignore|istanbul|c8\s|v8\s|jshint|tslint|biome-ignore|global\s|webpackChunkName|[#@]__PURE__|noinspection|type:\s*ignore|noqa|pylint:|fmt:|shellcheck)/i
// Code inside comments — URLs, inline code, JSDoc tags, paths and dotted or
// cased identifiers, punctuation — makes franc report French, Dutch or
// Italian for English and CJK comments alike. Keep only the prose.
const COMMENT_NON_PROSE = [
  /https?:\/\/\S+/g,
  /`[^`\n]*`/g,
  /@\w+(?:\s*\{[^}\n]{0,80}\})?/g,
  /(?<![\w$-])[\w$-]+(?:[.:/\\][\w$-]+)+/g,
  /\b[a-z]+[A-Z][\w$]*/g,
  /\b[\w$]*_[\w$]*/g,
  /[{}()[\]<>=;*#|"'+&!?^~\\-]+/g,
]

function commentProse(comment: string): string | null {
  if (COMMENT_DIRECTIVE.test(comment)) return null
  let prose = comment
  for (const pattern of COMMENT_NON_PROSE) prose = prose.replace(pattern, " ")
  return prose.replace(/\s+/g, " ").trim()
}

const COMMENT_PATTERNS: Record<string, RegExp[]> = {
  javascript: [/\/\/(.*)$/gm, /\/\*[\s\S]*?\*\//g],
  typescript: [/\/\/(.*)$/gm, /\/\*[\s\S]*?\*\//g],
  python: [/#(.*)$/gm, /"""[\s\S]*?"""/g, /'''[\s\S]*?'''/g],
  shell: [/#(.*)$/gm],
  powershell: [/#(.*)$/gm, /<#[\s\S]*?#>/g],
  batch: [/(?:^|\n)\s*REM\s+(.*)$/gim, /(?:^|\n)\s*::(.*)$/gm],
}

interface LanguageAnalysis {
  totalComments: number
  totalLetters: number
  englishLetters: number
  nonEnglishLetters: number
  nonEnglishPercentage: number
  detectedLanguages: Map<string, number>
  filesWithNonEnglish: Map<string, number>
}

function extractComments(content: string, fileExtension: string): string[] {
  const comments: string[] = []
  let language = ""

  if ([".js", ".jsx", ".mjs", ".cjs"].includes(fileExtension)) language = "javascript"
  else if ([".ts", ".tsx"].includes(fileExtension)) language = "typescript"
  else if ([".py"].includes(fileExtension)) language = "python"
  else if ([".sh", ".bash"].includes(fileExtension)) language = "shell"
  else if ([".ps1"].includes(fileExtension)) language = "powershell"
  else if ([".bat", ".cmd"].includes(fileExtension)) language = "batch"

  if (!language || !COMMENT_PATTERNS[language]) return comments

  for (const pattern of COMMENT_PATTERNS[language]!) {
    const matches = content.match(pattern)
    if (matches) comments.push(...matches)
  }

  return comments
    .map((comment) =>
      comment
        .replace(/^\/\/\s*/, "")
        .replace(/^\/\*\s*|\s*\*\/$/g, "")
        .replace(/^#\s*/, "")
        .replace(/^<#\s*|\s*#>$/g, "")
        .replace(/^"""\s*|\s*"""$/g, "")
        .replace(/^'''\s*|\s*'''$/g, "")
        .replace(/^REM\s+/i, "")
        .replace(/^::\s*/, "")
        .trim()
    )
    .filter((comment) => comment.length > 0)
}

function analyzeCommentLanguages(
  comments: string[],
  filePath: string,
  fileAnalysis: LanguageAnalysis
): void {
  let fileNonEnglishLetters = 0

  for (const raw of comments) {
    const comment = commentProse(raw)
    if (!comment) continue
    const letters = comment.match(LETTER)?.length ?? 0
    if (letters === 0) continue
    fileAnalysis.totalLetters += letters
    fileAnalysis.totalComments += 1

    const nonLatin = comment.match(NON_LATIN_LETTER)?.length ?? 0
    if (nonLatin / letters < NON_LATIN_SHARE_FOR_COMMENT) {
      fileAnalysis.englishLetters += letters
      continue
    }
    const language = franc(comment, { minLength: 3 })
    const code = language === "und" ? "other" : language
    fileAnalysis.nonEnglishLetters += letters
    fileNonEnglishLetters += letters
    fileAnalysis.detectedLanguages.set(code, (fileAnalysis.detectedLanguages.get(code) ?? 0) + letters)
  }

  if (fileNonEnglishLetters > 0) {
    fileAnalysis.filesWithNonEnglish.set(filePath, fileNonEnglishLetters)
  }
}

async function detectNonEnglishComments(
  files: Array<{ path: string; content: string }>,
  _repo: GitHubRepoInfo
): Promise<GitHubFinding[]> {
  const findings: GitHubFinding[] = []

  const analysis: LanguageAnalysis = {
    totalComments: 0,
    totalLetters: 0,
    englishLetters: 0,
    nonEnglishLetters: 0,
    nonEnglishPercentage: 0,
    detectedLanguages: new Map(),
    filesWithNonEnglish: new Map(),
  }

  for (const file of files) {
    const ext = file.path.substring(file.path.lastIndexOf("."))
    const comments = extractComments(file.content, ext)
    if (comments.length > 0) {
      analyzeCommentLanguages(comments, file.path, analysis)
    }
  }

  if (analysis.totalLetters >= MIN_LETTERS_TO_ANALYZE) {
    analysis.nonEnglishPercentage = analysis.nonEnglishLetters / analysis.totalLetters

    if (
      analysis.nonEnglishPercentage >= NON_ENGLISH_THRESHOLD &&
      analysis.nonEnglishLetters >= MIN_NON_ENGLISH_LETTERS
    ) {
      const topFiles = Array.from(analysis.filesWithNonEnglish.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([path]) => path)

      const langBreakdown = Array.from(analysis.detectedLanguages.entries())
        .sort((a, b) => b[1] - a[1])
        .map(([code, count]) => `${getLanguageName(code)}: ${count} characters`)
        .join(", ")

      // Context, not evidence: comments in another language are normal for
      // many legitimate projects, and no benchmark sample depends on this
      // signal. It is shown, but weighs 0.0125 (low × low confidence) and
      // never blocks cloning.
      const percentage = Math.round(analysis.nonEnglishPercentage * 100)
      findings.push({
        severity: "low",
        confidence: "low",
        cloneBlocking: false,
        type: "NON_ENGLISH_COMMENTS",
        description: `${percentage}% of code comment text is in languages other than English (${langBreakdown}). Normal for many projects; shown for context only.`,
        files: topFiles,
      })
    }
  }

  return findings
}

function getLanguageName(code: string): string {
  const names: Record<string, string> = {
    tur: "Turkish", rus: "Russian", zho: "Chinese", cmn: "Chinese", jpn: "Japanese", kor: "Korean",
    ara: "Arabic", deu: "German", fra: "French", spa: "Spanish", por: "Portuguese",
    ita: "Italian", nld: "Dutch", pol: "Polish", ukr: "Ukrainian", vie: "Vietnamese",
    tha: "Thai", ind: "Indonesian", heb: "Hebrew", hin: "Hindi", zlm: "Malay", ron: "Romanian", arb: "Arabic", bel: "Belarusian", other: "Other",
  }
  return names[code] || code
}

// ─── Comprehensive security checks ───────────────────────────────────────────

function detectSuspiciousPackageNames(content: string, filePath: string): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  try {
    const pkg = JSON.parse(content)
    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
      ...pkg.peerDependencies,
      ...pkg.optionalDependencies,
    }

    const suspiciousPackages: string[] = []

    for (const packageName in allDeps) {
      if (/^[a-z0-9]{6,8}$/.test(packageName) && !/[aeiou]{2}/.test(packageName)) {
        suspiciousPackages.push(`${packageName} (random-looking name)`)
      }
      if (/(.)\1{4,}/.test(packageName)) {
        suspiciousPackages.push(`${packageName} (repeated characters)`)
      }
      if (packageName.length === 1) {
        suspiciousPackages.push(`${packageName} (single character)`)
      }
      if (/(test|temp|tmp|debug|hack|crack|backdoor|shell|payload)[_-]?[0-9]*$/.test(packageName)) {
        suspiciousPackages.push(`${packageName} (suspicious name pattern)`)
      }
    }

    if (suspiciousPackages.length > 0) {
      findings.push({
        severity: "medium",
        type: "SUSPICIOUS_PACKAGE_NAME",
        file: filePath,
        description: `Suspicious package names detected: ${suspiciousPackages.slice(0, 5).join(", ")}${suspiciousPackages.length > 5 ? ` and ${suspiciousPackages.length - 5} more` : ""}`,
        codeExplanation:
          "📦 These package names don't follow typical naming conventions and may be malicious packages attempting to hide their purpose.",
      })
    }
  } catch {
    // Not valid JSON
  }

  return findings
}

/**
 * A password-shaped assignment whose value is a stand-in: the word itself
 * (`password: 'password'`, `_password: 'authPassword'`), a selector
 * (`password: "[type=password]"`), a template (`"{{ vault_password }}"`,
 * `` `${PASS}` ``), or one of the documented defaults examples ship with.
 */
export function isPlaceholderPassword(match: string): boolean {
  if (isObviousPlaceholderSecret(match)) return true
  const value = match.match(/['"]([^'"]*)['"]\s*$/)?.[1] ?? ""
  return /pass(?:word|wd)?|secret|changeit|changeme|example|dummy|placeholder|sample|\{\{|\$\{|%\(|<[\w-]+>|\[type=|\*{3,}|x{4,}/i.test(value)
}

function detectHardcodedSecrets(
  content: string,
  filePath: string,
  coveredRuleIds: ReadonlySet<string> = new Set()
): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  if (isTestFile(filePath)) return findings

  const secretPatterns = [
    { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"]([^'"\n]{20,})['"]/gi, type: "API Key", severity: "high" as const, ruleId: "HARDCODED_API_KEY" },
    { pattern: /(?:secret[_-]?key|secret)\s*[:=]\s*['"]([^'"\n]{20,})['"]/gi, type: "Secret Key", severity: "high" as const, ruleId: "HARDCODED_API_KEY" },
    // The value is one string literal on one line. Letting it span lines let
    // a prompt's own closing quote open the "value": npm's
    // `read.password('Password:', creds.password)` matched from `Password:'`
    // to the next quote on a later line.
    { pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"\n]{8,})['"]/gi, type: "Password", severity: "medium" as const, ruleId: null },
    { pattern: /(?:token|auth[_-]?token)\s*[:=]\s*['"]([^'"\n]{20,})['"]/gi, type: "Auth Token", severity: "high" as const, ruleId: "HARDCODED_API_KEY" },
    { pattern: /(?:private[_-]?key|privatekey)\s*[:=]\s*['"]([^'"\n]{20,})['"]/gi, type: "Private Key", severity: "high" as const, ruleId: "HARDCODED_API_KEY" },
    { pattern: /AKIA[0-9A-Z]{16}/g, type: "AWS Access Key", severity: "critical" as const, ruleId: "HARDCODED_AWS_KEY" },
    { pattern: /ghp_[a-zA-Z0-9]{36}/g, type: "GitHub Personal Access Token", severity: "critical" as const, ruleId: "HARDCODED_GITHUB_TOKEN" },
    { pattern: /gho_[a-zA-Z0-9]{36}/g, type: "GitHub OAuth Token", severity: "critical" as const, ruleId: "HARDCODED_GITHUB_TOKEN" },
    { pattern: /sk_live_[a-zA-Z0-9]{24,}/g, type: "Stripe Live Key", severity: "critical" as const, ruleId: "HARDCODED_STRIPE_KEY" },
    { pattern: /(?:mongodb|mongo)[+:\/\/]{0,6}[^@\s]+:[^@\s]+@/gi, type: "MongoDB Connection String", severity: "medium" as const, ruleId: "HARDCODED_DB_CONNECTION" },
    { pattern: /postgres:\/\/[^@\s]+:[^@\s]+@/gi, type: "PostgreSQL Connection String", severity: "medium" as const, ruleId: "HARDCODED_DB_CONNECTION" },
  ].filter(({ ruleId }) => !ruleId || !coveredRuleIds.has(ruleId))

  const foundSecrets: Array<{ type: string; match: string; severity: "critical" | "high" | "medium" }> = []
  const matchedRegexes: RegExp[] = []
  const placeholderRegexes: RegExp[] = []

  for (const { pattern, type, severity } of secretPatterns) {
    const matches = content.match(pattern)
    if (matches && matches.length > 0) {
      const genericSecret = ["API Key", "Secret Key", "Auth Token", "Private Key"].includes(type)
      const actionableMatches = type === "AWS Access Key"
        ? matches.filter((match) => !isDocumentedAwsExampleKey(match))
        : genericSecret
          ? matches.filter((match) => !isObviousPlaceholderSecret(match))
          : type === "Password"
            ? matches.filter((match) => !isPlaceholderPassword(match))
            : matches
      // A password placeholder is not a credential at all, so it is not
      // reported even as a deployment warning: `password: "changeit"` in an
      // example server, a CSS selector `[type=password]`, a template.
      if (actionableMatches.length === 0 && type === "Password") continue
      if (actionableMatches.length === 0) {
        placeholderRegexes.push(pattern)
        continue
      }
      foundSecrets.push({
        type,
        match: actionableMatches[0]!.substring(0, 50) + "...",
        severity,
      })
      matchedRegexes.push(pattern)
    }
  }

  if (placeholderRegexes.length > 0) {
    findings.push({
      severity: "low",
      confidence: "high",
      cloneBlocking: false,
      type: "INSECURE_CONFIGURATION",
      file: filePath,
      description: "Predictable placeholder secret must be replaced before deployment",
      evidence: collectEvidence(content, placeholderRegexes),
    })
  }

  if (foundSecrets.length > 0) {
    const highestSeverity = foundSecrets.some((s) => s.severity === "critical")
      ? "critical"
      : foundSecrets.some((s) => s.severity === "high") ? "high" : "medium"
    findings.push({
      severity: highestSeverity,
      confidence: highestSeverity === "critical" ? "high" : "medium",
      type: "HARDCODED_SECRETS",
      file: filePath,
      description: `Hardcoded credentials detected: ${foundSecrets.map((s) => s.type).join(", ")}`,
      evidence: collectEvidence(content, matchedRegexes),
      codeSnippet: foundSecrets[0]!.match,
      codeExplanation:
        "🔐 Hardcoded credentials expose your application to unauthorized access. API keys, passwords, and tokens should NEVER be committed to source code. Use environment variables or secure credential management instead.",
    })
  }

  return findings
}

function detectNetworkPatterns(
  content: string,
  filePath: string,
  coveredRuleIds: ReadonlySet<string> = new Set()
): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  if (isTestFile(filePath)) return findings

  const suspiciousPatterns = [
    // Valid public IPv4 only: each octet bounded 0–255, not embedded in a longer
    // dotted/number sequence (avoids flagging version strings like "1.2.3.4.5" or
    // impossible IPs like "999.999.999.999"), and excluding private/link-local ranges.
    //
    // It must also be *addressed*, not merely present: introduced by a URL
    // scheme or an opening quote, and closed by a quote, a path separator or a
    // port. A dotted quad on its own is not a network signal, and source files
    // are full of them — compressed SVG path data is the worst offender
    // (`c2.91.83.1` in an icon component reads as 2.91.83.1), and so do
    // version-like and coordinate sequences. What this signal is actually
    // about is a hardcoded endpoint, and a hardcoded endpoint is a string:
    // `fetch("http://185.x.x.x/x")`, `connect(4444, '185.x.x.x')`.
    { pattern: /(?:https?:\/\/|["'`])(?<![\d.])(?!(?:0\.|127\.|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.))(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d.])(?::\d{1,5})?(?=["'`\/\s,;)\]}]|$)/g, type: "Hardcoded IP Address", severity: "medium" as const, confidence: "low" as const },
    { pattern: /https?:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[a-zA-Z0-9_-]+/gi, type: "Discord Webhook", severity: "critical" as const, ruleId: "NETWORK_DISCORD_WEBHOOK" },
    { pattern: /\d{8,10}:[a-zA-Z0-9_-]{35}/g, type: "Telegram Bot Token", severity: "high" as const, ruleId: "NETWORK_TELEGRAM_TOKEN" },
    { pattern: /(?:pastebin\.com|hastebin\.com|paste\.ee)\/[a-zA-Z0-9]+/gi, type: "Pastebin URL", severity: "medium" as const, ruleId: "NETWORK_PASTEBIN" },
    { pattern: /(?:bit\.ly|tinyurl\.com|t\.co)\/[a-zA-Z0-9]+/gi, type: "URL Shortener", severity: "medium" as const, ruleId: "NETWORK_URL_SHORTENER" },
    { pattern: /https?:\/\/[a-zA-Z0-9-]+\.(?:tk|ml|ga|cf|gq|onion|xyz)(?:\/|$)/gi, type: "Suspicious Domain TLD", severity: "high" as const, ruleId: "NETWORK_SUSPICIOUS_TLD" },
    { pattern: /https?:\/\/[a-zA-Z0-9-]+\.ngrok\.io/gi, type: "Ngrok Tunnel", severity: "medium" as const, ruleId: "NETWORK_NGROK_TUNNEL" },
  ].filter((p) => !("ruleId" in p) || !coveredRuleIds.has((p as { ruleId: string }).ruleId))

  for (const { pattern, type, severity, confidence } of suspiciousPatterns) {
    const matches = content.match(pattern)
    if (matches && matches.length > 0) {
      const validMatches = matches.filter((m) => {
        const lines = content.split("\n")
        const lineWithMatch = lines.find((l) => l.includes(m))
        return lineWithMatch && !lineWithMatch.trim().startsWith("//") && !lineWithMatch.trim().startsWith("#")
      })

      if (validMatches.length > 0) {
        findings.push({
          severity,
          confidence: confidence ?? "high",
          type: "NETWORK_COMMUNICATION",
          file: filePath,
          description: `Suspicious network communication detected: ${type} (${validMatches.length} occurrence${validMatches.length > 1 ? "s" : ""})`,
          evidence: collectEvidence(content, pattern),
          codeSnippet: validMatches.slice(0, 3).join("\n"),
          codeExplanation: `🌐 ${type} detected. ${
            type === "Discord Webhook"
              ? "Discord webhooks are commonly used for data exfiltration - stolen data is sent to attacker's Discord server."
              : type === "Hardcoded IP Address"
              ? "Hardcoded IP addresses bypass DNS and make the code harder to audit. Often used to connect to command & control servers."
              : "This URL may be used for data exfiltration or malware distribution."
          }`,
        })
      }
    }
  }

  return findings
}

function detectCryptoMining(
  content: string,
  filePath: string,
  coveredRuleIds: ReadonlySet<string> = new Set()
): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  // The CRYPTO_MINER rule in detection-rules owns this signal when loaded.
  if (coveredRuleIds.has("CRYPTO_MINER")) return findings

  const miningPatterns = [
    /coinhive|coin-hive|crypto-loot|cryptoloot|jsecoin/gi,
    // A mining pool is a host, so require one: `pool.supportxmr.com`,
    // `stratum+tcp://pool.minexmr.com:3333`. Bare `pool.` matched the English
    // word: React describes its event pool as "returned to the pool." in a
    // comment, and four of its reconciler files were reported as
    // critical-severity crypto miners.
    /stratum\+tcp|(?:stratum|pool)\.[a-z0-9-]{2,}\.[a-z]{2,}\b/gi,
    // Word-bounded: `xmr` as a substring appears inside ordinary identifiers
    // and encoded blobs.
    /\bmonero\b|\bxmr\b|\bcryptonight\b/gi,
    /(?:miner|mining)[\w]*\.(?:start|run|init)/gi,
    /\.(?:setNumThreads|setThrottle|getHashesPerSecond)/gi,
  ]

  const miningIndicators: string[] = []
  const matches: string[] = []

  for (const pattern of miningPatterns) {
    const found = content.match(pattern)
    if (found) {
      miningIndicators.push(...found)
      matches.push(...found)
    }
  }

  if (/while\s*\(\s*true\s*\)[\s\S]{0,200}(?:Math\.|crypto|hash)/i.test(content)) {
    miningIndicators.push("Infinite loop with crypto/math operations")
  }

  if (miningIndicators.length > 0) {
    findings.push({
      severity: "critical",
      type: "CRYPTO_MINER",
      file: filePath,
      description: `Cryptocurrency mining code detected: ${miningIndicators.slice(0, 3).join(", ")}`,
      evidence: collectEvidence(content, miningPatterns),
      codeSnippet: matches.slice(0, 2).join("\n"),
      codeExplanation:
        "⛏️ Cryptocurrency miners use your CPU/GPU to mine coins for attackers. This drastically slows down your system and increases electricity costs. Miners are often bundled with legitimate software.",
    })
  }

  return findings
}

const NETWORK_SINK =
  /(?:\bfetch\s*\(|\baxios(?:\.(?:post|put|patch|request))?\s*\(|navigator\.sendBeacon\s*\(|XMLHttpRequest|new\s+WebSocket\s*\(|\bio\s*\()/gi
// A destination that stays on the page's own origin: a path (`/login`,
// `./api`), or a loopback URL. Anything else — an absolute URL to another
// host, or a URL held in a variable — may leave it.
const SAME_ORIGIN_DESTINATION =
  /^\s*(?:(['"`])(?:\/(?!\/)|\.{1,2}\/|https?:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?=[:/'"`])|\1))/

/**
 * Whether `text` contains a network call that can carry data off the page's
 * own origin. `io({...})` with no URL connects back to the serving host.
 */
export function hasCrossOriginSink(text: string): boolean {
  for (const sink of text.matchAll(NETWORK_SINK)) {
    const rest = text.slice((sink.index ?? 0) + sink[0].length)
    if (/XMLHttpRequest/i.test(sink[0])) {
      const open = rest.match(/\.open\s*\(\s*['"`]\w+['"`]\s*,([^]{0,200})/)
      if (!open || !SAME_ORIGIN_DESTINATION.test(open[1]!)) return true
      continue
    }
    // `io()` / `io({ auth })` with no URL connects back to the serving host.
    if (/\bio\s*\($/.test(sink[0]) && /^\s*[{)]/.test(rest)) continue
    if (!SAME_ORIGIN_DESTINATION.test(rest)) return true
  }
  return false
}

function detectDataExfiltration(
  content: string,
  filePath: string,
  coveredRuleIds: ReadonlySet<string> = new Set()
): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  if (isTestFile(filePath)) return findings

  const exfiltrationPatterns = [
    { pattern: /navigator\.clipboard\.read(?:Text)?\s*\(/gi, type: "Clipboard Access", severity: "high" as const, ruleId: "EXFIL_CLIPBOARD" },
    { pattern: /document\.cookie/gi, type: "Cookie Access", severity: "high" as const, ruleId: "EXFIL_COOKIE" },
    { pattern: /new\s+FormData\s*\([^)]*\)[\s\S]{0,100}(?:fetch|axios|XMLHttpRequest)/gi, type: "Form Data Transmission", severity: "medium" as const, ruleId: null },
  ].filter(({ ruleId }) => !ruleId || !coveredRuleIds.has(ruleId))

  const detectedPatterns: string[] = []
  const matchedRegexes: RegExp[] = []
  let highestSeverity: "critical" | "high" | "medium" = "medium"

  for (const { pattern, type, severity } of exfiltrationPatterns) {
    if (pattern.test(content)) {
      detectedPatterns.push(type)
      matchedRegexes.push(pattern)
      if (severity === "high") highestSeverity = "high"
    }
  }

  // Reading an input is how every form in every UI is written: React's own
  // `ReactInputSelection.js` reads `input.value`, and every login page reads
  // its password field. A password read on its own used to count, which
  // flagged every login example — socket.io's passport examples among them.
  // What makes it exfiltration is the value reaching a sink that can leave
  // the origin, so that is what this requires.
  const formFieldRead = /(?:input|email|password|passwd|credential)[\w-]*\.value\b/gi
  for (const match of content.matchAll(formFieldRead)) {
    const start = (match.index ?? 0) + match[0].length
    if (hasCrossOriginSink(content.slice(start, start + 200))) {
      detectedPatterns.push(/pass|credential/i.test(match[0]) ? "Credential Field Transmission" : "Form Data Access")
      matchedRegexes.push(formFieldRead, NETWORK_SINK)
      break
    }
  }

  // Reading a saved theme, locale, or UI preference is not exfiltration.
  // Require a sensitive-looking storage key and a network sink in the same
  // local region before reporting browser-storage transmission.
  const sensitiveStorageRead =
    /(?:localStorage|sessionStorage)\.getItem\s*\(\s*['"][^'"]*(?:token|secret|password|credential|session|auth|wallet|seed|private)[^'"]*['"]\s*\)/gi
  //
  // The sink has to be able to reach another host. A token read from storage
  // and sent as `authorization` to `fetch('/self')` is how a single-page app
  // talks to its own server: socket.io's passport-jwt examples were rated
  // high for exactly that. Storing or using a token locally is not
  // exfiltration; sending it somewhere else is.
  for (const match of content.matchAll(sensitiveStorageRead)) {
    const start = match.index ?? 0
    const region = content.slice(start, start + 2_000)
    if (hasCrossOriginSink(region)) {
      detectedPatterns.push("Sensitive Storage Transmission")
      matchedRegexes.push(sensitiveStorageRead, NETWORK_SINK)
      highestSeverity = "high"
      break
    }
  }

  // Built-in fallback for signature sets that predate the context-aware
  // EXFIL_KEYLOGGER rule. A plain keyboard shortcut/modal handler is benign.
  if (!coveredRuleIds.has("EXFIL_KEYLOGGER")) {
    const keyboardCapture = detectKeyboardCapture(content)
    if (keyboardCapture) {
      detectedPatterns.push("Keyboard Capture and Transmission")
      matchedRegexes.push(...keyboardCapture.evidencePatterns)
      highestSeverity = "critical"
    }
  }

  if (detectedPatterns.length > 0) {
    findings.push({
      severity: highestSeverity,
      confidence: highestSeverity === "medium" ? "low" : "high",
      type: "DATA_EXFILTRATION",
      file: filePath,
      description: `Data exfiltration patterns detected: ${detectedPatterns.join(", ")}`,
      evidence: collectEvidence(content, matchedRegexes),
      codeExplanation:
        "🕵️ This code accesses sensitive user data. Combined with network requests, this could indicate credential theft or data exfiltration to attacker's servers.",
    })
  }

  return findings
}

function detectBackdoors(
  content: string,
  filePath: string,
  coveredRuleIds: ReadonlySet<string> = new Set()
): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  const backdoorPatterns = [
    { pattern: /eval\s*\(\s*(?:request|req)(?:\.|\.body|\.query)/gi, type: "Remote Code Execution Endpoint", severity: "critical" as const, ruleId: "BACKDOOR_RCE_ENDPOINT" },
    { pattern: /exec\s*\(\s*(?:request|req)(?:\.|\.body|\.query)/gi, type: "Command Injection Endpoint", severity: "critical" as const, ruleId: "BACKDOOR_RCE_ENDPOINT" },
    { pattern: /require\s*\(\s*(?:request|req)(?:\.|\.body|\.query)/gi, type: "Dynamic Require", severity: "critical" as const, ruleId: "BACKDOOR_DYNAMIC_REQUIRE" },
    // The request has to be read as data (`req.body`, `req["x"]`), the way
    // the three patterns above all require. Matching a bare `req` flagged
    // `new Function('module', 'exports', 'require', src)` — the CommonJS
    // module wrapper every bundler and module loader writes — as a critical
    // backdoor, because `require` begins with `req`. esbuild's own build
    // script tripped it.
    { pattern: /new\s+Function\s*\([^)]*\b(?:request|req)\s*(?:\.|\[)/gi, type: "Dynamic Function from Request", severity: "critical" as const, ruleId: null },
    { pattern: /(?:password|auth)\s*(?:===?|==)\s*['"][^'"]{0,20}['"]\s*\)/gi, type: "Hardcoded Auth Bypass", severity: "critical" as const, ruleId: "BACKDOOR_HARDCODED_AUTH" },
  ].filter(({ ruleId }) => !ruleId || !coveredRuleIds.has(ruleId))

  for (const { pattern, type, severity } of backdoorPatterns) {
    const matches = content.match(pattern)
    if (matches) {
      findings.push({
        severity,
        type: "BACKDOOR",
        file: filePath,
        description: `Backdoor detected: ${type}`,
        codeSnippet: matches[0],
        codeExplanation: `🚪 ${type} - This code allows remote attackers to execute arbitrary commands or bypass authentication. This is a CRITICAL security vulnerability.`,
        evidence: collectEvidence(content, pattern),
      })
    }
  }

  // Flask debug mode is a deployment vulnerability only when the development
  // debugger is exposed beyond localhost. It is not evidence of a backdoor and
  // does not make source code unsafe to clone.
  const exposedFlaskDebugger =
    /app\.run\s*\((?=[\s\S]{0,400}\bdebug\s*=\s*True)(?=[\s\S]{0,400}\bhost\s*=\s*['"]0\.0\.0\.0['"])[\s\S]{0,400}\)/gi
  const flaskDebugEnabled = /\bdebug\s*=\s*True/gi
  const wildcardBind = /\bhost\s*=\s*['"]0\.0\.0\.0['"]/gi
  if (exposedFlaskDebugger.test(content)) {
    findings.push({
      severity: "low",
      confidence: "high",
      cloneBlocking: false,
      type: "INSECURE_CONFIGURATION",
      file: filePath,
      description: "Flask debugger is exposed on all network interfaces; disable debug mode before deployment",
      evidence: collectEvidence(content, [flaskDebugEnabled, wildcardBind]),
      codeExplanation:
        "Flask's interactive debugger can execute code and must not be exposed in production. This is a deployment configuration issue, not a repository backdoor.",
    })
  }

  return findings
}

function detectSupplyChainRisks(content: string, filePath: string): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  if (!filePath.endsWith("package.json")) return findings

  try {
    const pkg = JSON.parse(content)
    const scripts = pkg.scripts || {}
    const suspiciousScripts: string[] = []

    for (const [scriptName, scriptContent] of Object.entries(scripts)) {
      if (typeof scriptContent === "string") {
        if (/(?:curl|wget|fetch)[\s\S]*\.(?:exe|sh|py|bin|dmg|pkg|msi|dll)/i.test(scriptContent)) {
          suspiciousScripts.push(`${scriptName}: Downloads executable files`)
        }
        if (/(?:cd|pushd)[\s\S]*node_modules/i.test(scriptContent)) {
          suspiciousScripts.push(`${scriptName}: Modifies node_modules`)
        }
        if (/(?:>|>>|tee)[\s\S]*(?:package\.json|index\.js|\.\.\/)/i.test(scriptContent)) {
          suspiciousScripts.push(`${scriptName}: Self-modifying script`)
        }
        if (/(?:preinstall|postinstall|install)/.test(scriptName) && /(?:curl|wget|fetch|http|https)/i.test(scriptContent)) {
          suspiciousScripts.push(`${scriptName}: Network access during installation`)
        }
      }
    }

    if (suspiciousScripts.length > 0) {
      findings.push({
        severity: "critical",
        type: "SUPPLY_CHAIN_RISK",
        file: filePath,
        description: `Supply chain attack patterns in package scripts: ${suspiciousScripts.join("; ")}`,
        codeSnippet: JSON.stringify(scripts, null, 2).substring(0, 300) + "...",
        codeExplanation:
          "📦 Supply chain attacks inject malicious code through package installation scripts. These scripts run automatically when you install the package and can compromise your entire system.",
      })
    }
  } catch {
    // Not valid JSON
  }

  return findings
}

function detectSuspiciousFileAccess(
  content: string,
  filePath: string,
  coveredRuleIds: ReadonlySet<string> = new Set()
): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  if (isTestFile(filePath)) return findings

  const fileAccessPatterns = [
    { pattern: /(?:fs\.read|readFileSync|readFile)\s*\([^)]*(?:\.ssh|\.aws|\.gnupg|\.docker|id_rsa|credentials)/gi, type: "SSH/AWS Credentials Access", severity: "critical" as const, ruleId: "FILE_ACCESS_CREDENTIALS" },
    { pattern: /(?:fs\.read|readFileSync|readFile)\s*\([^)]*(?:etc\/passwd|etc\/shadow|\.bash_history|\.zsh_history)/gi, type: "System File Access", severity: "critical" as const, ruleId: "FILE_ACCESS_SYSTEM" },
    { pattern: /(?:fs\.read|readFileSync|readFile)\s*\([^)]*(?:Chrome|Firefox|Safari|Edge)[\w\s/\\]*(?:Cookies|Login|History)/gi, type: "Browser Data Access", severity: "critical" as const, ruleId: "FILE_ACCESS_BROWSER_DATA" },
    // The destination is the first argument, and it has to be rooted in a
    // system directory. Matching `/bin` anywhere before the next `)` read the
    // *contents* being written — a `#!/usr/bin/env node` or `#!/bin/sh`
    // shebang — as the target: next.js's and pnpm's bin-placeholder scripts.
    { pattern: /(?:fs\.write\w*|writeFileSync|writeFile|appendFileSync|appendFile)\s*\(\s*(?:path\.(?:join|resolve)\s*\(\s*)?['"`](?:\/(?:etc|sys|bin|sbin|usr\/(?:s?bin|lib|local\/bin))\b|[A-Za-z]:\\\\Windows)/gi, type: "System Directory Write", severity: "medium" as const, ruleId: null },
  ].filter(({ ruleId }) => !ruleId || !coveredRuleIds.has(ruleId))

  for (const { pattern, type, severity } of fileAccessPatterns) {
    const matches = content.match(pattern)
    if (matches) {
      findings.push({
        severity,
        confidence: severity === "critical" ? "high" : "medium",
        type: "SUSPICIOUS_FILE_ACCESS",
        file: filePath,
        description: `Suspicious file access detected: ${type}`,
        codeSnippet: matches[0],
        codeExplanation: `📁 ${type} - This code attempts to access or modify sensitive system files. This could be credential theft, system compromise, or destructive malware.`,
        evidence: collectEvidence(content, pattern),
      })
    }
  }

  // Deleting a known temp directory or an application-owned cache is routine
  // cleanup. Only report destructive deletion when the target is a broad or
  // sensitive user/system path.
  //
  // What makes a deletion dangerous is where it is rooted, not whether it
  // globs. The previous `[^\n]*[?*]` alternative flagged any `rm -rf`
  // containing a wildcard, down to a build script clearing its own output
  // directory (`rm -rf "$main_dir"/fp*`). The target now has to start at the
  // filesystem root, the home directory, or a bare glob in the current one.
  const destructiveDeletion =
    /(?:rm\s+-rf\s+["']?(?:(?:\/|~|\$\{?HOME\}?)(?!\/?(?:tmp|var\/tmp)\b)|\*)|(?:fs\.)?(?:unlink|unlinkSync|rmSync)\s*\([^\n)]*(?:\.ssh|\.aws|\.gnupg|\.docker|\/etc|\/usr|\/home|Users[\\/]))/gi
  if (destructiveDeletion.test(content)) {
    findings.push({
      severity: "medium",
      confidence: "medium",
      type: "SUSPICIOUS_FILE_ACCESS",
      file: filePath,
      description: "Suspicious file access detected: Destructive File Deletion",
      codeExplanation:
        "📁 Deletes a broad or sensitive user/system path. Verify that the target cannot escape an application-owned directory.",
      evidence: collectEvidence(content, destructiveDeletion),
    })
  }

  return findings
}

async function detectCodeIntegrityIssues(
  files: Array<{ path: string; content: string }>,
  allPaths: string[],
  _repo: GitHubRepoInfo
): Promise<GitHubFinding[]> {
  const findings: GitHubFinding[] = []

  for (const file of files) {
    if (file.path.endsWith(".min.js") || file.path.endsWith(".min.css")) continue

    const lines = file.content.split("\n")
    const longLines = lines.filter((l) => l.length > 500)
    const avgLineLength = lines.reduce((sum, l) => sum + l.length, 0) / lines.length

    if (longLines.length > 3 && avgLineLength > 200) {
      const shortVars = (file.content.match(/\b[a-z]\b/g) || []).length
      const totalVars = (file.content.match(/\b[a-z][a-zA-Z0-9_]*\b/g) || []).length

      if (shortVars / totalVars > 0.3) {
        findings.push({
          severity: "medium",
          confidence: "low",
          type: "CODE_INTEGRITY_ISSUE",
          file: file.path,
          description: "Minified/obfuscated code detected in source repository",
          codeExplanation:
            "🔍 Source code appears to be minified or obfuscated. Legitimate projects typically commit readable source code, not minified versions. This makes code review difficult and may hide malicious intent.",
        })
      }
    }
  }

  // Presence checks run against the full tree — LICENSE/README aren't in the
  // scanned-source list (wrong extension) and would otherwise always "miss".
  const basename = (p: string) => p.split("/").pop() ?? p
  const hasLicense = allPaths.some((p) => /^(LICENSE|COPYING)/i.test(basename(p)))
  if (!hasLicense && allPaths.length > 5) {
    findings.push({
      severity: "low",
      type: "CODE_INTEGRITY_ISSUE",
      description: "No LICENSE file found in repository",
      codeExplanation:
        "📄 Missing license file. Legitimate open-source projects typically include a license. Absence may indicate a quickly assembled malicious repository.",
    })
  }

  const hasReadme = allPaths.some((p) => /^README/i.test(basename(p)))
  if (!hasReadme && allPaths.length > 5) {
    findings.push({
      severity: "low",
      type: "CODE_INTEGRITY_ISSUE",
      description: "No README file found in repository",
      codeExplanation:
        "📝 Missing README. Legitimate projects typically have documentation. Absence may indicate a hastily created malicious repository.",
    })
  }

  return findings
}

function detectSocialEngineering(content: string, filePath: string): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  if (!/README/i.test(filePath)) return findings

  // "quick" and "fast" are not urgency: they are "Quick start" and "fast"
  // in the README of nearly every project, and paired with any one other
  // pattern ("admin privileges", "100% safe") they flagged python/cpython's
  // Mac, iOS and Windows-installer READMEs, rust's miri and apollo-client's
  // root README once nested READMEs were read. The words a lure leans on
  // are the ones about time running out.
  const socialEngineeringPatterns = [
    { pattern: /\b(?:urgent(?:ly)?|immediately|act now|limited time)\b/gi, type: "Urgency Language", severity: "medium" as const },
    { pattern: /(?:disable|turn off|bypass)[\s\w]*(?:antivirus|firewall|security|protection)/gi, type: "Security Bypass Instructions", severity: "high" as const },
    { pattern: /(?:admin|root|sudo)[\s\w]*(?:rights|privileges|access|permission)/gi, type: "Privilege Escalation Language", severity: "medium" as const },
    { pattern: /(?:100%|totally|completely|absolutely)[\s\w]*(?:safe|secure|trusted|legit)/gi, type: "Over-assurance Language", severity: "low" as const },
    { pattern: /(?:millions?|thousands?)[\s\w]*(?:downloads?|users?|stars?)/gi, type: "Fake Popularity Claims", severity: "low" as const },
  ]

  const detectedPatterns: string[] = []
  let highestSeverity: "high" | "medium" | "low" = "low"

  for (const { pattern, type, severity } of socialEngineeringPatterns) {
    if (pattern.test(content)) {
      detectedPatterns.push(type)
      if (severity === "high" || (severity === "medium" && highestSeverity === "low")) {
        highestSeverity = severity
      }
    }
  }

  if (detectedPatterns.length >= 2) {
    findings.push({
      severity: highestSeverity,
      type: "SOCIAL_ENGINEERING",
      file: filePath,
      description: `Social engineering tactics detected in README: ${detectedPatterns.join(", ")}`,
      codeExplanation:
        "🎣 README contains persuasive language designed to manipulate users. Scammers use urgency, fake credentials, and security bypass instructions to trick users into running malicious code.",
    })
  }

  return findings
}

// ─── Utilities ────────────────────────────────────────────────────────────────

async function getNpmWeeklyDownloads(packageName: string): Promise<number | null> {
  const cached = NPM_DOWNLOAD_CACHE.get(packageName)
  if (cached && Date.now() - cached.fetchedAt < NPM_CACHE_TTL_MS) {
    return cached.weeklyDownloads
  }
  try {
    const url = `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`
    const response = await fetch(url, { signal: AbortSignal.timeout(5000) })
    const weeklyDownloads = response.ok
      ? ((await response.json()) as { downloads: number }).downloads ?? 0
      : 0
    NPM_DOWNLOAD_CACHE.set(packageName, { weeklyDownloads, fetchedAt: Date.now() })
    return weeklyDownloads
  } catch {
    NPM_DOWNLOAD_CACHE.set(packageName, { weeklyDownloads: null, fetchedAt: Date.now() })
    return null
  }
}

function levenshteinDistance(a: string, b: string): number {
  const m = a.length, n = b.length
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  )
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i]![j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1]![j - 1]!
          : 1 + Math.min(dp[i - 1]![j - 1]!, dp[i - 1]![j]!, dp[i]![j - 1]!)
    }
  }
  return dp[m]![n]!
}

function checkTyposquat(packageName: string): string | null {
  const popularPackages = [
    "lodash", "express", "react", "axios", "moment", "webpack", "babel",
    "typescript", "eslint", "prettier", "jest", "mocha", "bcrypt", "crypto", "request",
  ]

  for (const popular of popularPackages) {
    if (packageName === popular) continue
    if (Math.abs(packageName.length - popular.length) > 3) continue
    // Two edits only mean "typo" on a name long enough to still be
    // recognisable after them. On a short name the distance stops carrying
    // signal and starts linking unrelated packages: `jsr` — Deno's registry
    // client — is two edits from `jest`, which made zod a typosquat host.
    const limit = Math.min(packageName.length, popular.length) >= 5 ? 2 : 1
    if (levenshteinDistance(packageName, popular) <= limit) return popular
  }

  return null
}

function countDependencies(content: string): number {
  try {
    const pkg = JSON.parse(content)
    return (
      Object.keys(pkg.dependencies || {}).length +
      Object.keys(pkg.devDependencies || {}).length
    )
  } catch {
    return 0
  }
}

// Export internal helpers for testing
export { checkTyposquat, detectObfuscation, isTestFile }
