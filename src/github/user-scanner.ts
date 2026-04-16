/**
 * GitHub User Profile Scanner
 *
 * Analyzes GitHub user profiles for suspicious patterns and risk indicators.
 * No chrome.storage dependency — token is passed as an option.
 */

import type { GitHubUserFeatures, GitHubUserScanResult, RiskFactor, UserScanOptions } from "../types/index"

const WEIGHTS = {
  VERY_NEW_ACCOUNT: 0.3,
  NEW_ACCOUNT: 0.2,
  NO_REPOS: 0.25,
  NO_FOLLOWERS: 0.2,
  HIGH_FOLLOWING_RATIO: 0.2,
  NO_PROFILE_PHOTO: 0.15,
  INCOMPLETE_PROFILE: 0.1,
  NO_RECENT_ACTIVITY: 0.15,
  SINGLE_REPO_CONTRIBUTOR: 0.15,

  ESTABLISHED_ACCOUNT: -0.15,
  VERY_ESTABLISHED: -0.25,
  STRONG_FOLLOWER_BASE: -0.15,
  POPULAR_DEVELOPER: -0.25,
  ACTIVE_CONTRIBUTOR: -0.2,
  PROLIFIC_DEVELOPER: -0.3,
  HAS_POPULAR_REPOS: -0.2,
  CONSISTENT_ACTIVITY: -0.15,
}

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
  return scoreUserProfile(features)
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
    throw new Error(`GitHub API error: ${userResponse.status}`)
  }
  const user: GitHubAPIUser = await userResponse.json()

  const reposResponse = await fetch(
    `https://api.github.com/users/${username}/repos?per_page=100&sort=updated`,
    { headers }
  )
  if (!reposResponse.ok) throw new Error(`Failed to fetch repositories: ${reposResponse.status}`)
  const repos: GitHubAPIRepo[] = await reposResponse.json()

  const eventsResponse = await fetch(
    `https://api.github.com/users/${username}/events/public?per_page=30`,
    { headers }
  )
  if (!eventsResponse.ok) throw new Error(`Failed to fetch events: ${eventsResponse.status}`)
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

function scoreUserProfile(features: GitHubUserFeatures): GitHubUserScanResult {
  const riskFactors: RiskFactor[] = []
  const trustSignals: RiskFactor[] = []
  let riskScore = 0.0

  if (features.accountAgeDays < 30) {
    riskFactors.push({ factor: "VERY_NEW_ACCOUNT", weight: WEIGHTS.VERY_NEW_ACCOUNT, description: `Account created ${features.accountAgeDays} days ago (very new)` })
    riskScore += WEIGHTS.VERY_NEW_ACCOUNT
  } else if (features.accountAgeDays < 90) {
    riskFactors.push({ factor: "NEW_ACCOUNT", weight: WEIGHTS.NEW_ACCOUNT, description: `Account created ${features.accountAgeDays} days ago (new)` })
    riskScore += WEIGHTS.NEW_ACCOUNT
  }

  if (features.ownedReposCount === 0) {
    riskFactors.push({ factor: "NO_REPOS", weight: WEIGHTS.NO_REPOS, description: "No public repositories" })
    riskScore += WEIGHTS.NO_REPOS
  } else if (features.ownedReposCount === 1) {
    riskFactors.push({ factor: "SINGLE_REPO_CONTRIBUTOR", weight: WEIGHTS.SINGLE_REPO_CONTRIBUTOR, description: "Only 1 repository (potential throwaway account)" })
    riskScore += WEIGHTS.SINGLE_REPO_CONTRIBUTOR
  }

  if (features.followers === 0) {
    riskFactors.push({ factor: "NO_FOLLOWERS", weight: WEIGHTS.NO_FOLLOWERS, description: "Zero followers" })
    riskScore += WEIGHTS.NO_FOLLOWERS
  }

  if (features.followerFollowingRatio > 10 && features.following > 10) {
    riskFactors.push({ factor: "HIGH_FOLLOWING_RATIO", weight: WEIGHTS.HIGH_FOLLOWING_RATIO, description: `Following ${features.following} but only ${features.followers} followers (bot pattern)` })
    riskScore += WEIGHTS.HIGH_FOLLOWING_RATIO
  }

  if (!features.hasProfilePhoto) {
    riskFactors.push({ factor: "NO_PROFILE_PHOTO", weight: WEIGHTS.NO_PROFILE_PHOTO, description: "Using default avatar" })
    riskScore += WEIGHTS.NO_PROFILE_PHOTO
  }

  if (!features.isProfileComplete) {
    riskFactors.push({ factor: "INCOMPLETE_PROFILE", weight: WEIGHTS.INCOMPLETE_PROFILE, description: "Missing bio, name, or location" })
    riskScore += WEIGHTS.INCOMPLETE_PROFILE
  }

  if (features.recentEventCount === 0) {
    riskFactors.push({ factor: "NO_RECENT_ACTIVITY", weight: WEIGHTS.NO_RECENT_ACTIVITY, description: "No activity in last 90 days" })
    riskScore += WEIGHTS.NO_RECENT_ACTIVITY
  }

  if (features.accountAgeDays >= 1095) {
    trustSignals.push({ factor: "VERY_ESTABLISHED", weight: WEIGHTS.VERY_ESTABLISHED, description: `Account ${Math.floor(features.accountAgeDays / 365)} years old` })
    riskScore += WEIGHTS.VERY_ESTABLISHED
  } else if (features.accountAgeDays >= 365) {
    trustSignals.push({ factor: "ESTABLISHED_ACCOUNT", weight: WEIGHTS.ESTABLISHED_ACCOUNT, description: `Account ${Math.floor(features.accountAgeDays / 365)} year(s) old` })
    riskScore += WEIGHTS.ESTABLISHED_ACCOUNT
  }

  if (features.followers >= 200) {
    trustSignals.push({ factor: "POPULAR_DEVELOPER", weight: WEIGHTS.POPULAR_DEVELOPER, description: `${features.followers} followers (popular developer)` })
    riskScore += WEIGHTS.POPULAR_DEVELOPER
  } else if (features.followers >= 50) {
    trustSignals.push({ factor: "STRONG_FOLLOWER_BASE", weight: WEIGHTS.STRONG_FOLLOWER_BASE, description: `${features.followers} followers` })
    riskScore += WEIGHTS.STRONG_FOLLOWER_BASE
  }

  if (features.ownedReposCount >= 50) {
    trustSignals.push({ factor: "PROLIFIC_DEVELOPER", weight: WEIGHTS.PROLIFIC_DEVELOPER, description: `${features.ownedReposCount} repositories (prolific developer)` })
    riskScore += WEIGHTS.PROLIFIC_DEVELOPER
  } else if (features.ownedReposCount >= 10) {
    trustSignals.push({ factor: "ACTIVE_CONTRIBUTOR", weight: WEIGHTS.ACTIVE_CONTRIBUTOR, description: `${features.ownedReposCount} repositories` })
    riskScore += WEIGHTS.ACTIVE_CONTRIBUTOR
  }

  if (features.totalStars >= 50) {
    trustSignals.push({ factor: "HAS_POPULAR_REPOS", weight: WEIGHTS.HAS_POPULAR_REPOS, description: `${features.totalStars} total stars across repositories` })
    riskScore += WEIGHTS.HAS_POPULAR_REPOS
  }

  if (features.veryRecentEventCount > 0) {
    trustSignals.push({ factor: "CONSISTENT_ACTIVITY", weight: WEIGHTS.CONSISTENT_ACTIVITY, description: `${features.veryRecentEventCount} events in last 30 days` })
    riskScore += WEIGHTS.CONSISTENT_ACTIVITY
  }

  riskScore = Math.max(0, Math.min(1, riskScore))

  const riskLevel: "low" | "medium" | "high" =
    riskScore >= 0.7 ? "high" : riskScore >= 0.4 ? "medium" : "low"

  const recommendation =
    riskLevel === "high"
      ? "⛔ High risk profile. Exercise extreme caution. Verify identity through other channels before trusting any collaboration requests."
      : riskLevel === "medium"
      ? "⚠️ Moderate risk. Review profile carefully. Check repository quality and recent activity before accepting collaboration."
      : "✅ Profile appears legitimate. Standard caution advised for any collaboration requests."

  return {
    username: features.username,
    riskLevel,
    riskScore,
    riskFactors,
    trustSignals,
    recommendation,
    profileUrl: features.profileUrl,
    accountAgeDays: features.accountAgeDays,
    followers: features.followers,
    publicRepos: features.publicRepos,
    scannedAt: features.scannedAt,
  }
}

// Export for testing
export { scoreUserProfile, fetchUserFeatures }
