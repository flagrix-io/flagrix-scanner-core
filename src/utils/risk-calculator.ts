import type { GitHubFinding, RiskLevel } from "../types/index.js"
import { RISK_THRESHOLDS } from "../types/index.js"

export function getSeverityWeight(severity: GitHubFinding["severity"]): number {
  const weights: Record<GitHubFinding["severity"], number> = {
    critical: 0.4,
    high: 0.25,
    medium: 0.15,
    low: 0.05,
    info: 0.01,
  }
  return weights[severity]
}

export interface SignalContribution {
  /** Dedupe key: rule id when present, else finding type (heuristics merge). */
  signal: string
  /** Confidence-adjusted weight actually counted toward the score. */
  weight: number
  /** The strongest finding for this signal (ties: first seen). */
  finding: GitHubFinding
  /** How many findings collapsed into this signal. */
  findingCount: number
}

/**
 * Collapse findings into independent signals with the contribution each one
 * actually adds to the score. Repeated hits from the same rule/type are one
 * signal, not independent evidence; otherwise a large monorepo reaches High
 * merely by containing the same benign heuristic in many files. Heuristic
 * matches are discounted by confidence (medium ×0.6, low ×0.25).
 *
 * This is the single source of truth for scoring: `calculateRawRiskScore` is
 * the sum of these weights, and `factors[]` on scan results is built from
 * them — so per-signal deductions shown to users reconcile with the score.
 */
export function calculateSignalContributions(findings: GitHubFinding[]): SignalContribution[] {
  const bySignal = new Map<string, SignalContribution>()
  for (const finding of findings) {
    const confidenceMultiplier =
      finding.confidence === "low" ? 0.25 : finding.confidence === "medium" ? 0.6 : 1
    const weight = getSeverityWeight(finding.severity) * confidenceMultiplier
    const obfuscationHeuristic = finding.type === "OBFUSCATED_CODE" ||
      (finding.type === "CODE_INTEGRITY_ISSUE" &&
        /minified|obfuscat/i.test(finding.description)) ||
      /^OBF_(?:BASE64|HEX|EVAL|NEW_FUNCTION|SETTIMEOUT|FROMCHARCODE|CHARCODE)/.test(
        finding.pattern ?? ""
      )
    const signal = obfuscationHeuristic
      ? "OBFUSCATION_HEURISTIC"
      : finding.pattern ?? finding.type
    const existing = bySignal.get(signal)
    if (!existing) {
      bySignal.set(signal, { signal, weight, finding, findingCount: 1 })
    } else {
      existing.findingCount++
      if (weight > existing.weight) {
        existing.weight = weight
        existing.finding = finding
      }
    }
  }
  return [...bySignal.values()]
}

/** Sum of independent signal contributions before the 1.0 clamp. */
export function calculateRawRiskScore(findings: GitHubFinding[]): number {
  return calculateSignalContributions(findings)
    .reduce((sum, contribution) => sum + contribution.weight, 0)
}

export function calculateRiskScore(findings: GitHubFinding[]): number {
  return Math.min(1, calculateRawRiskScore(findings))
}

/**
 * A high-confidence `critical` finding (verified code-execution,
 * credential-theft, or equivalent behavior) always means "high". A heuristic
 * critical match must not override the normal score bands by itself.
 */
export function getRiskLevel(
  score: number,
  findings?: GitHubFinding[],
  executedConfig: (path: string) => boolean = isExecutedConfig
): RiskLevel {
  if (findings?.some((f) =>
    (f.severity === "critical" && (f.confidence ?? "high") === "high") ||
    (f.type === "SUSPICIOUS_DEPENDENCY" &&
      (f.severity === "high" || f.severity === "critical") &&
      (f.confidence ?? "high") === "high")
  )) {
    return "high"
  }
  if (score < RISK_THRESHOLDS.low) {
    return findings?.some((f) => raisesExecutedConfigFloor(f, executedConfig)) ? "medium" : "low"
  }
  if (score < RISK_THRESHOLDS.high) return "medium"
  return "high"
}

/**
 * Configs a tool loads and runs as code the moment it starts, with nobody
 * choosing to run them: bundler, CSS, lint and test configs
 * (`tailwind.config.js`, `next.config.mjs`, `vite.config.ts`,
 * `.eslintrc.cjs`), which `npm run dev` or a build executes, and committed
 * git hooks, which a commit executes. PolinRider-style loaders are appended
 * to exactly these files.
 */
const EXECUTED_CONFIG =
  /(?:^|\/)[\w.-]*\.config\.[cm]?[jt]s$|(?:^|\/)\.(?:eslintrc|babelrc|prettierrc|stylelintrc|mocharc)\.[cm]?js$|(?:^|\/)\.(?:githooks|husky)\/[\w-]+$/

export function isExecutedConfig(path: string): boolean {
  return EXECUTED_CONFIG.test(path)
}

/**
 * The verdict floor for executed configs. One strong signal in a file that
 * runs on `npm run dev` — code pushed off-screen behind whitespace in
 * `tailwind.config.js` — scored 0.15 on its own, under the medium band, so
 * the verdict said low about a file the reader's next command executes. A
 * high or critical finding of medium or high confidence in such a file makes
 * the verdict at least medium. Low-confidence heuristics stay in the score,
 * and a leaked credential says the config exposes a secret, not that it runs
 * anything, so those do not raise the floor.
 */
function raisesExecutedConfigFloor(
  finding: GitHubFinding,
  executedConfig: (path: string) => boolean
): boolean {
  if (finding.severity !== "high" && finding.severity !== "critical") return false
  if ((finding.confidence ?? "high") === "low") return false
  if (finding.type === "HARDCODED_SECRETS" || finding.type === "INSECURE_CONFIGURATION") return false
  if (finding.pattern?.startsWith("HARDCODED_")) return false
  return finding.file !== undefined && executedConfig(finding.file)
}
