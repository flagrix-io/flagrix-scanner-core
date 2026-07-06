/**
 * GitHub User Profile Scanner
 *
 * Analyzes GitHub user profiles for suspicious patterns and risk indicators.
 * No chrome.storage dependency — token is passed as an option.
 */

import type {
  GitHubUserFeatures,
  GitHubUserScanResult,
  ProfileCondition,
  ProfileRiskRule,
  RiskFactor,
  UserProfileRuleset,
  UserScanOptions
} from "../types/index"
import { githubApiError } from "./api-error"
import { DEFAULT_USER_PROFILE_RULES } from "./user-profile-ruleset"

interface GitHubAPIUser {
  login: string
  avatar_url: string
  name: string | null
  company: string | null
  location: string | null
  bio: string | null
  public_repos: number
  followers: number
  following: number
  created_at: string
}

interface GitHubAPIRepo {
  stargazers_count: number
  fork: boolean
}

interface GitHubAPIEvent {
  created_at: string
}

export async function scanGitHubUser(
  username: string,
  options: UserScanOptions = {}
): Promise<GitHubUserScanResult> {
  const features = await fetchUserFeatures(username, options.githubToken)
  return scoreUserProfile(features, options.userProfileRules)
}

async function fetchUserFeatures(
  username: string,
  githubToken?: string
): Promise<GitHubUserFeatures> {
  const headers: HeadersInit = {
    Accept: "application/vnd.github.v3+json",
    "User-Agent": "Flagrix-Extension",
  }

  if (githubToken) {
    headers["Authorization"] = `Bearer ${githubToken}`
  }

  const userResponse = await fetch(`https://api.github.com/users/${username}`, { headers })
  if (!userResponse.ok) {
    if (userResponse.status === 404) throw new Error(`User "${username}" not found`)
    throw await githubApiError(userResponse)
  }
  const user: GitHubAPIUser = await userResponse.json()

  const reposResponse = await fetch(
    `https://api.github.com/users/${username}/repos?per_page=100&sort=updated`,
    { headers }
  )
  if (!reposResponse.ok) throw await githubApiError(reposResponse, "Failed to fetch repositories")
  const repos: GitHubAPIRepo[] = await reposResponse.json()

  const eventsResponse = await fetch(
    `https://api.github.com/users/${username}/events/public?per_page=30`,
    { headers }
  )
  if (!eventsResponse.ok) throw await githubApiError(eventsResponse, "Failed to fetch events")
  const events: GitHubAPIEvent[] = await eventsResponse.json()

  const now = Date.now()
  const accountAgeDays = Math.floor((now - new Date(user.created_at).getTime()) / 86400000)

  const followerFollowingRatio =
    user.followers === 0 ? (user.following > 0 ? Infinity : 0) : user.following / user.followers

  const ownedRepos = repos.filter((r) => !r.fork)
  const totalStars = repos.reduce((sum, r) => sum + r.stargazers_count, 0)
  const repoStarRatio = ownedRepos.length === 0 ? 0 : totalStars / ownedRepos.length

  const recentEvents = events.filter(
    (e) => (now - new Date(e.created_at).getTime()) / 86400000 <= 90
  )
  const veryRecentEvents = events.filter(
    (e) => (now - new Date(e.created_at).getTime()) / 86400000 <= 30
  )

  return {
    username: user.login,
    accountAgeDays,
    followers: user.followers,
    following: user.following,
    followerFollowingRatio,
    publicRepos: user.public_repos,
    ownedReposCount: ownedRepos.length,
    totalStars,
    repoStarRatio,
    hasProfilePhoto: !user.avatar_url.includes("avatars/u/"),
    isProfileComplete: !!(user.name && user.bio && user.location),
    hasCompany: !!user.company,
    hasBio: !!user.bio,
    recentEventCount: recentEvents.length,
    veryRecentEventCount: veryRecentEvents.length,
    profileUrl: `https://github.com/${username}`,
    scannedAt: new Date().toISOString(),
  }
}

// ─── Data-driven profile scoring ─────────────────────────────────────────────

/** Fill `{fieldName}` tokens in a rule description from the scanned features. */
function interpolate(description: string, features: GitHubUserFeatures): string {
  return description.replace(/\{(\w+)\}/g, (_, key: string) => {
    const value = (features as unknown as Record<string, unknown>)[key]
    return value === undefined ? `{${key}}` : String(value)
  })
}

function compare(
  a: number | boolean,
  operator: string,
  b: number | boolean
): boolean {
  if (operator === "eq") return a === b
  const x = Number(a)
  const y = Number(b)
  switch (operator) {
    case "lt":
      return x < y
    case "lte":
      return x <= y
    case "gt":
      return x > y
    case "gte":
      return x >= y
    default:
      return false // unknown operator → never match (fail safe)
  }
}

function matches(features: GitHubUserFeatures, condition: ProfileCondition): boolean {
  if ("all" in condition) {
    return condition.all.every((c) => matches(features, c))
  }
  const actual = (features as unknown as Record<string, unknown>)[condition.field]
  if (typeof actual !== "number" && typeof actual !== "boolean") return false
  return compare(actual, condition.operator, condition.value)
}

function scoreUserProfile(
  features: GitHubUserFeatures,
  ruleset: UserProfileRuleset = DEFAULT_USER_PROFILE_RULES
): GitHubUserScanResult {
  const riskFactors: RiskFactor[] = []
  const trustSignals: RiskFactor[] = []
  const matched = new Set<string>()
  let riskScore = 0

  const applyRules = (rules: ProfileRiskRule[], bucket: RiskFactor[]) => {
    for (const rule of rules) {
      // Skip rules superseded by a more specific one that already matched.
      if (rule.exclusiveWith && matched.has(rule.exclusiveWith)) continue
      if (!matches(features, rule.condition)) continue
      matched.add(rule.id)
      bucket.push({
        factor: rule.id,
        weight: rule.weight,
        description: interpolate(rule.description, features)
      })
      riskScore += rule.weight
    }
  }

  applyRules(ruleset.riskFactors, riskFactors)
  applyRules(ruleset.trustSignals, trustSignals)

  riskScore = Math.max(0, Math.min(1, riskScore))

  const { mediumMinScore, highMinScore, recommendations } = ruleset.riskLevels
  const riskLevel: "low" | "medium" | "high" =
    riskScore >= highMinScore ? "high" : riskScore >= mediumMinScore ? "medium" : "low"

  return {
    username: features.username,
    riskLevel,
    riskScore,
    riskFactors,
    trustSignals,
    recommendation: recommendations[riskLevel],
    profileUrl: features.profileUrl,
    accountAgeDays: features.accountAgeDays,
    followers: features.followers,
    publicRepos: features.publicRepos,
    scannedAt: features.scannedAt,
  }
}

// Export for testing
export { scoreUserProfile, fetchUserFeatures }
