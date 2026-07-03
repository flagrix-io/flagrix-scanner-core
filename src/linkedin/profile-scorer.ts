/**
 * LinkedIn Profile Heuristic Scorer
 *
 * Analyzes LinkedIn profile features and calculates a risk score.
 * Positive weights = increases risk; negative weights = decrease risk (trust signals).
 */

import type {
  LinkedInProfileFeatures,
  LinkedInScanResult,
  RiskFactor,
  RiskLevel,
} from "../types/index"
import { DEFAULT_DISCLAIMER, RISK_THRESHOLDS } from "../types/index"

export function scoreLinkedInProfile(
  features: LinkedInProfileFeatures
): LinkedInScanResult {
  const factors: RiskFactor[] = []
  let totalRisk = 0

  // --- RISK FACTORS (increase risk) ---

  if (features.accountAgeDays !== null) {
    if (features.accountAgeDays < 30) {
      factors.push({ factor: "VERY_NEW_ACCOUNT", weight: 0.25, description: "Account appears to be less than 30 days old" })
      totalRisk += 0.25
    } else if (features.accountAgeDays < 90) {
      factors.push({ factor: "NEW_ACCOUNT", weight: 0.15, description: "Account created within last 90 days" })
      totalRisk += 0.15
    }
  }

  const networkSize = features.connectionCount ?? features.followerCount ?? null
  if (networkSize !== null) {
    if (networkSize < 25) {
      factors.push({ factor: "VERY_LOW_CONNECTIONS", weight: 0.2, description: "Very few connections (under 25)" })
      totalRisk += 0.2
    } else if (networkSize < 100) {
      factors.push({ factor: "LOW_CONNECTIONS", weight: 0.1, description: "Below average connections (under 100)" })
      totalRisk += 0.1
    }
  }

  if (features.mutualConnections === 0) {
    factors.push({ factor: "NO_MUTUAL_CONNECTIONS", weight: 0.15, description: "No mutual connections with you" })
    totalRisk += 0.15
  }

  if (features.postCount === 0 && !features.hasJobPostings) {
    factors.push({ factor: "NO_ACTIVITY", weight: 0.1, description: "No visible posts or activity" })
    totalRisk += 0.1
  }

  if (!features.hasProfilePhoto) {
    factors.push({ factor: "NO_PHOTO", weight: 0.15, description: "No profile photo" })
    totalRisk += 0.15
  }

  if (features.workHistoryCount < 2) {
    factors.push({ factor: "SPARSE_WORK_HISTORY", weight: 0.1, description: "Limited work history (fewer than 2 positions)" })
    totalRisk += 0.1
  }

  if (features.educationCount === 0) {
    factors.push({ factor: "NO_EDUCATION", weight: 0.05, description: "No education listed" })
    totalRisk += 0.05
  }

  if (features.profileCompleteness < 0.5) {
    factors.push({ factor: "LOW_COMPLETENESS", weight: 0.1, description: "Profile appears incomplete" })
    totalRisk += 0.1
  }

  // --- TRUST SIGNALS (decrease risk) ---

  if (features.accountAgeDays !== null && features.accountAgeDays >= 365) {
    factors.push({ factor: "ESTABLISHED_ACCOUNT", weight: -0.15, description: "Established account (over 1 year old)" })
    totalRisk -= 0.15
  }

  if (networkSize !== null && networkSize >= 500) {
    const w = networkSize >= 10000 ? -0.2 : -0.1
    const msg = networkSize >= 10000
      ? `Very large network (${networkSize.toLocaleString()}+ connections/followers)`
      : "Strong network (500+ connections)"
    factors.push({ factor: "HIGH_CONNECTIONS", weight: w, description: msg })
    totalRisk += w
  }

  if (features.followerCount !== null && features.followerCount >= 10000) {
    factors.push({ factor: "HIGH_FOLLOWERS", weight: -0.15, description: `High follower count (${features.followerCount.toLocaleString()})` })
    totalRisk -= 0.15
  }

  if (features.mutualConnections >= 10) {
    const w = features.mutualConnections >= 50 ? -0.15 : -0.08
    factors.push({ factor: "MANY_MUTUAL_CONNECTIONS", weight: w, description: `${features.mutualConnections} mutual connections` })
    totalRisk += w
  }

  if (features.endorsementCount > 0) {
    factors.push({ factor: "HAS_ENDORSEMENTS", weight: -0.05, description: "Has skill endorsements" })
    totalRisk -= 0.05
  }

  if (features.isVerified) {
    factors.push({ factor: "VERIFIED", weight: -0.15, description: "LinkedIn verified identity" })
    totalRisk -= 0.15
  }

  if (features.isTopVoice) {
    factors.push({ factor: "TOP_VOICE", weight: -0.2, description: "LinkedIn Top Voice" })
    totalRisk -= 0.2
  }

  if (features.hasJobPostings) {
    factors.push({ factor: "HAS_JOB_POSTINGS", weight: -0.1, description: "Has active job postings" })
    totalRisk -= 0.1
  }

  const riskScore = Math.max(0, Math.min(1, totalRisk))
  const riskLevel = getRiskLevel(riskScore)

  const riskFactors = factors.filter((f) => f.weight > 0).sort((a, b) => b.weight - a.weight)
  const trustSignals = factors.filter((f) => f.weight < 0).sort((a, b) => a.weight - b.weight)

  return {
    riskScore,
    riskLevel,
    factors: [...riskFactors, ...trustSignals],
    disclaimer: DEFAULT_DISCLAIMER,
    profile: features,
    scannedAt: new Date(),
  }
}

function getRiskLevel(score: number): RiskLevel {
  if (score < RISK_THRESHOLDS.low) return "low"
  if (score < RISK_THRESHOLDS.high) return "medium"
  return "high"
}
