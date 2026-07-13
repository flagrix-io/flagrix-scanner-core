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

/**
 * Sum independent signal weights before the 1.0 clamp. Repeated hits from the
 * same rule/type are one signal, not independent evidence; otherwise a large
 * monorepo reaches High merely by containing the same benign heuristic in many
 * files.
 */
export function calculateRawRiskScore(findings: GitHubFinding[]): number {
  const strongestBySignal = new Map<string, number>()
  for (const finding of findings) {
    const confidenceMultiplier =
      finding.confidence === "low" ? 0.25 : finding.confidence === "medium" ? 0.6 : 1
    const contribution = getSeverityWeight(finding.severity) * confidenceMultiplier
    const obfuscationHeuristic = finding.type === "OBFUSCATED_CODE" ||
      (finding.type === "CODE_INTEGRITY_ISSUE" &&
        /minified|obfuscat/i.test(finding.description)) ||
      /^OBF_(?:BASE64|HEX|EVAL|NEW_FUNCTION|SETTIMEOUT|FROMCHARCODE|CHARCODE)/.test(
        finding.pattern ?? ""
      )
    const signal = obfuscationHeuristic
      ? "OBFUSCATION_HEURISTIC"
      : finding.pattern ?? finding.type
    strongestBySignal.set(signal, Math.max(strongestBySignal.get(signal) ?? 0, contribution))
  }
  return [...strongestBySignal.values()].reduce((sum, contribution) => sum + contribution, 0)
}

export function calculateRiskScore(findings: GitHubFinding[]): number {
  return Math.min(1, calculateRawRiskScore(findings))
}

/**
 * A high-confidence `critical` finding (verified code-execution,
 * credential-theft, or equivalent behavior) always means "high". A heuristic
 * critical match must not override the normal score bands by itself.
 */
export function getRiskLevel(score: number, findings?: GitHubFinding[]): RiskLevel {
  if (findings?.some((f) =>
    (f.severity === "critical" && (f.confidence ?? "high") === "high") ||
    (f.type === "SUSPICIOUS_DEPENDENCY" &&
      (f.severity === "high" || f.severity === "critical") &&
      (f.confidence ?? "high") === "high")
  )) {
    return "high"
  }
  if (score < RISK_THRESHOLDS.low) return "low"
  if (score < RISK_THRESHOLDS.high) return "medium"
  return "high"
}
