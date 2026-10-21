/**
 * OSV malicious-package feed matching.
 *
 * flagrix-detection-rules publishes osv-malicious.json: every npm and PyPI
 * package the OpenSSF malicious-packages project has confirmed malicious
 * (OSV `MAL-*` records), about 230k names. It is matched locally against the
 * dependencies a repo declares, so dependency names never leave the device.
 */

import type { GitHubFinding, OsvMaliciousFeed } from "../types/index.js"

export interface DeclaredDependency {
  ecosystem: "npm" | "pypi"
  name: string
  /** As declared: an npm range/specifier, or a PEP 440 specifier. */
  spec: string
  file: string
}

interface EcosystemIndex {
  all: ReadonlySet<string>
  versions: ReadonlyMap<string, readonly string[]>
}

// Indexing ~230k names takes a few ms. Do it once per feed object, not per scan.
const INDEXES = new WeakMap<OsvMaliciousFeed, { npm: EcosystemIndex; pypi: EcosystemIndex }>()

function indexFeed(feed: OsvMaliciousFeed) {
  let index = INDEXES.get(feed)
  if (!index) {
    const build = (ecosystem: OsvMaliciousFeed["npm"] | undefined): EcosystemIndex => ({
      all: new Set(ecosystem?.all ?? []),
      versions: new Map(Object.entries(ecosystem?.versions ?? {})),
    })
    index = { npm: build(feed.npm), pypi: build(feed.pypi) }
    INDEXES.set(feed, index)
  }
  return index
}

/** PEP 503 normalisation, matching how the feed stores PyPI names. */
export function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-")
}

// Specifiers that resolve inside the repo or to a URL, not to the registry.
const LOCAL_OR_URL_SPEC = /^(?:workspace:|file:|link:|portal:|git\+|git:|github:|gitlab:|bitbucket:|https?:)/

/** Numeric dot-part compare; a pre-release sorts before its release. */
export function compareVersions(a: string, b: string): number {
  const [mainA = "", preA] = a.split("-", 2)
  const [mainB = "", preB] = b.split("-", 2)
  const partsA = mainA.split(".")
  const partsB = mainB.split(".")
  for (let index = 0; index < Math.max(partsA.length, partsB.length); index++) {
    const diff = (Number.parseInt(partsA[index] ?? "0", 10) || 0) - (Number.parseInt(partsB[index] ?? "0", 10) || 0)
    if (diff !== 0) return Math.sign(diff)
  }
  if (preA === preB) return 0
  if (preA === undefined) return 1
  if (preB === undefined) return -1
  return preA < preB ? -1 : 1
}

const VERSION_TOKEN = /\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.]+)?/
const RANGE_PART = /(>=|<=|<|>)\s*(\S+)/g

function inAffected(version: string, entry: string): boolean {
  if (!/[<>]/.test(entry)) return compareVersions(version, entry) === 0
  for (const [, operator, bound] of entry.matchAll(RANGE_PART)) {
    const order = compareVersions(version, bound!)
    if (
      (operator === ">=" && order < 0) || (operator === ">" && order <= 0) ||
      (operator === "<=" && order > 0) || (operator === "<" && order >= 0)
    ) {
      return false
    }
  }
  return true
}

/**
 * Whether the version a dependency declares (the base of each `||`
 * alternative: `^1.2.0` → 1.2.0, `==2.0` → 2.0) is affected. "exact" means
 * the declaration pins that version, so it will be installed as-is.
 */
function declaredMatch(spec: string, affected: readonly string[]): "exact" | "range" | null {
  let specifier = spec.trim()
  const alias = specifier.match(/^npm:.+@([^@]+)$/)
  if (alias) specifier = alias[1]!
  let result: "exact" | "range" | null = null
  for (const part of specifier.split(/\s*\|\|\s*/)) {
    const base = part.match(VERSION_TOKEN)?.[0]
    if (!base || !affected.some((entry) => inAffected(base, entry))) continue
    if (/^\s*(?:={1,3}|v)?\s*\d/.test(part) && !/[\s,]/.test(part.trim().replace(/^={1,3}\s*/, ""))) return "exact"
    result = "range"
  }
  return result
}

/**
 * Findings for declared dependencies in the feed. Names a repo defines itself
 * (its own package.json names, local specifiers) are skipped: a squat of a
 * repo's internal package name on npm is that repo's victimhood, not its
 * malice. `alreadyFlagged` holds names the curated rules already reported.
 */
export function matchOsvFeed(
  feed: OsvMaliciousFeed,
  dependencies: DeclaredDependency[],
  localPackageNames: ReadonlySet<string>,
  alreadyFlagged: ReadonlySet<string>
): GitHubFinding[] {
  const index = indexFeed(feed)
  const findings: GitHubFinding[] = []
  const reported = new Set<string>()
  for (const dependency of dependencies) {
    const { ecosystem, name, spec, file } = dependency
    const key = `${ecosystem}:${name}`
    if (reported.has(key) || alreadyFlagged.has(name) || localPackageNames.has(name)) continue
    if (ecosystem === "npm" && LOCAL_OR_URL_SPEC.test(spec.trim())) continue
    const ecosystemIndex = index[ecosystem]
    const lookup = ecosystem === "pypi" ? normalizePypiName(name) : name
    const everyVersion = ecosystemIndex.all.has(lookup)
    const affected = ecosystemIndex.versions.get(lookup)
    const match = everyVersion ? "exact" : affected ? declaredMatch(spec, affected) : null
    if (!match) continue
    reported.add(key)
    const registry = ecosystem === "npm" ? "npm" : "PyPI"
    findings.push({
      severity: "critical",
      // A caret/tilde/>= range may resolve past the malicious versions.
      confidence: match === "exact" ? "high" : "medium",
      type: "SUSPICIOUS_DEPENDENCY",
      pattern: "OSV_MALICIOUS_PACKAGE",
      file,
      package: name,
      description: `Confirmed malicious ${registry} package (OSV): ${name}`,
      codeExplanation:
        `☠️ The OpenSSF malicious-packages project lists "${name}" as malicious` +
        (everyVersion ? "" : ` in the version this repo declares (${spec.trim()})`) +
        `. Installing it runs the attacker's code. Details: https://osv.dev/list?ecosystem=${registry}&q=${encodeURIComponent(name)}`,
    })
  }
  return findings
}

/** Dependencies a package.json declares (all dependency sections). */
export function npmDependencies(pkg: Record<string, unknown>, file: string): DeclaredDependency[] {
  const out: DeclaredDependency[] = []
  for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    const deps = pkg[section]
    if (!deps || typeof deps !== "object") continue
    for (const [name, spec] of Object.entries(deps as Record<string, unknown>)) {
      out.push({ ecosystem: "npm", name, spec: typeof spec === "string" ? spec : "", file })
    }
  }
  return out
}

const REQUIREMENT = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*([^;#]*)/

/**
 * requirements.txt lines, or the quoted strings in setup.py's
 * install_requires. Options (-r, -e, --index-url), URLs and comments are
 * skipped; setup.py code is never read as package names.
 */
export function pythonDependencies(content: string, file: string): DeclaredDependency[] {
  let lines: string[]
  if (file.endsWith("setup.py")) {
    const block = content.match(/install_requires\s*=\s*\[([^\]]{0,20000})\]/)
    lines = block ? [...block[1]!.matchAll(/["']([^"'\n]+)["']/g)].map((m) => m[1]!) : []
  } else {
    lines = content.split("\n")
  }
  const out: DeclaredDependency[] = []
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-") || trimmed.includes("://")) continue
    const match = trimmed.match(REQUIREMENT)
    if (match) out.push({ ecosystem: "pypi", name: match[1]!, spec: match[2]!.trim(), file })
  }
  return out
}
