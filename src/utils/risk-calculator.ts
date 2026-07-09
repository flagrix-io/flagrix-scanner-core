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
 * Sum of finding weights before the 1.0 clamp. Exposed so consumers can
 * reconcile per-finding deductions with the clamped score ("capped").
 */
export function calculateRawRiskScore(findings: GitHubFinding[]): number {
  let score = 0
  for (const finding of findings) {
    score += getSeverityWeight(finding.severity)
  }
  return score
}

export function calculateRiskScore(findings: GitHubFinding[]): number {
  return Math.min(1, calculateRawRiskScore(findings))
}

/**
 * A single `critical` finding (code-execution / credential-theft patterns —
 * see CONTRIBUTING.md) always means "high", regardless of how the additive
 * score lands. Otherwise a lone keylogger or backdoor in an unlucky
 * low-file-count repo could average out to "medium" just because nothing
 * else was flagged alongside it.
 */
export function getRiskLevel(score: number, findings?: GitHubFinding[]): RiskLevel {
  if (findings?.some((f) => f.severity === "critical")) return "high"
  if (score < RISK_THRESHOLDS.low) return "low"
  if (score < RISK_THRESHOLDS.high) return "medium"
  return "high"
}
