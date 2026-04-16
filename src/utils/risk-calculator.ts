import type { GitHubFinding, RiskLevel } from "../types/index"

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

export function calculateRiskScore(findings: GitHubFinding[]): number {
  let score = 0
  for (const finding of findings) {
    score += getSeverityWeight(finding.severity)
  }
  return Math.min(1, score)
}

export function getRiskLevel(score: number): RiskLevel {
  if (score < 0.3) return "low"
  if (score < 0.6) return "medium"
  return "high"
}
