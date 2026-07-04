/**
 * Tests for the data-driven GitHub user-profile scorer.
 *
 * The `equivalence` block is the safety net for wiring user-profile.yaml: it
 * reimplements the original hardcoded logic (`legacyScore`) and asserts the new
 * ruleset-driven `scoreUserProfile` produces the identical riskScore, riskLevel,
 * and matched factor ids across a grid of synthetic profiles — so moving the
 * weights into data does not change any verdict.
 */

import { describe, expect, it } from "vitest"
import { scoreUserProfile } from "../src/github/user-scanner"
import type { GitHubUserFeatures } from "../src/types/index"

function makeFeatures(overrides: Partial<GitHubUserFeatures> = {}): GitHubUserFeatures {
  return {
    username: "octocat",
    accountAgeDays: 800,
    followers: 20,
    following: 15,
    followerFollowingRatio: 15 / 20,
    publicRepos: 12,
    ownedReposCount: 12,
    totalStars: 30,
    repoStarRatio: 2.5,
    hasProfilePhoto: true,
    isProfileComplete: true,
    hasCompany: true,
    hasBio: true,
    recentEventCount: 5,
    veryRecentEventCount: 2,
    profileUrl: "https://github.com/octocat",
    scannedAt: "2026-07-04T00:00:00.000Z",
    ...overrides
  }
}

/** The original hardcoded scoring logic, kept here as the equivalence oracle. */
function legacyScore(f: GitHubUserFeatures): {
  riskScore: number
  riskLevel: string
  ids: string[]
} {
  const ids: string[] = []
  let s = 0
  const add = (id: string, w: number) => {
    ids.push(id)
    s += w
  }

  if (f.accountAgeDays < 30) add("VERY_NEW_ACCOUNT", 0.3)
  else if (f.accountAgeDays < 90) add("NEW_ACCOUNT", 0.2)

  if (f.ownedReposCount === 0) add("NO_REPOS", 0.25)
  else if (f.ownedReposCount === 1) add("SINGLE_REPO_CONTRIBUTOR", 0.15)

  if (f.followers === 0) add("NO_FOLLOWERS", 0.2)
  if (f.followerFollowingRatio > 10 && f.following > 10) add("HIGH_FOLLOWING_RATIO", 0.2)
  if (!f.hasProfilePhoto) add("NO_PROFILE_PHOTO", 0.15)
  if (!f.isProfileComplete) add("INCOMPLETE_PROFILE", 0.1)
  if (f.recentEventCount === 0) add("NO_RECENT_ACTIVITY", 0.15)

  if (f.accountAgeDays >= 1095) add("VERY_ESTABLISHED", -0.25)
  else if (f.accountAgeDays >= 365) add("ESTABLISHED_ACCOUNT", -0.15)

  if (f.followers >= 200) add("POPULAR_DEVELOPER", -0.25)
  else if (f.followers >= 50) add("STRONG_FOLLOWER_BASE", -0.15)

  if (f.ownedReposCount >= 50) add("PROLIFIC_DEVELOPER", -0.3)
  else if (f.ownedReposCount >= 10) add("ACTIVE_CONTRIBUTOR", -0.2)

  if (f.totalStars >= 50) add("HAS_POPULAR_REPOS", -0.2)
  if (f.veryRecentEventCount > 0) add("CONSISTENT_ACTIVITY", -0.15)

  const riskScore = Math.max(0, Math.min(1, s))
  const riskLevel = riskScore >= 0.7 ? "high" : riskScore >= 0.4 ? "medium" : "low"
  return { riskScore, riskLevel, ids: ids.sort() }
}

describe("scoreUserProfile — equivalence with legacy logic", () => {
  // A grid crossing every threshold boundary for the key features.
  const ages = [10, 45, 200, 400, 1200]
  const repos = [0, 1, 5, 12, 60]
  const followerSets = [
    { followers: 0, following: 0 },
    { followers: 5, following: 80 }, // high following ratio
    { followers: 75, following: 10 },
    { followers: 300, following: 5 }
  ]
  const flags = [
    { hasProfilePhoto: true, isProfileComplete: true, totalStars: 0, recentEventCount: 5, veryRecentEventCount: 2 },
    { hasProfilePhoto: false, isProfileComplete: false, totalStars: 80, recentEventCount: 0, veryRecentEventCount: 0 }
  ]

  let n = 0
  for (const accountAgeDays of ages) {
    for (const ownedReposCount of repos) {
      for (const fs of followerSets) {
        for (const fl of flags) {
          n++
          it(`matches legacy for age=${accountAgeDays} repos=${ownedReposCount} followers=${fs.followers} flagset=${fl.hasProfilePhoto ? "A" : "B"}`, () => {
            const ratio =
              fs.followers === 0 ? (fs.following > 0 ? Infinity : 0) : fs.following / fs.followers
            const features = makeFeatures({
              accountAgeDays,
              ownedReposCount,
              publicRepos: ownedReposCount,
              followers: fs.followers,
              following: fs.following,
              followerFollowingRatio: ratio,
              ...fl
            })
            const legacy = legacyScore(features)
            const result = scoreUserProfile(features)
            const ids = [...result.riskFactors, ...result.trustSignals].map((r) => r.factor).sort()

            expect(result.riskScore).toBeCloseTo(legacy.riskScore, 10)
            expect(result.riskLevel).toBe(legacy.riskLevel)
            expect(ids).toEqual(legacy.ids)
          })
        }
      }
    }
  }
})

describe("scoreUserProfile — behavior", () => {
  it("flags a throwaway scam account as high risk", () => {
    const features = makeFeatures({
      accountAgeDays: 5,
      ownedReposCount: 0,
      publicRepos: 0,
      followers: 0,
      following: 0,
      followerFollowingRatio: 0,
      hasProfilePhoto: false,
      isProfileComplete: false,
      totalStars: 0,
      recentEventCount: 0,
      veryRecentEventCount: 0
    })
    const r = scoreUserProfile(features)
    expect(r.riskLevel).toBe("high")
    expect(r.riskFactors.map((f) => f.factor)).toContain("VERY_NEW_ACCOUNT")
    expect(r.trustSignals).toHaveLength(0)
  })

  it("treats an established popular developer as low risk", () => {
    const features = makeFeatures({
      accountAgeDays: 2000,
      ownedReposCount: 60,
      followers: 500,
      following: 50,
      followerFollowingRatio: 0.1,
      totalStars: 4000
    })
    const r = scoreUserProfile(features)
    expect(r.riskLevel).toBe("low")
    expect(r.riskScore).toBe(0)
  })

  it("interpolates feature values into descriptions", () => {
    const features = makeFeatures({ accountAgeDays: 12, ownedReposCount: 0, followers: 0, following: 0 })
    const r = scoreUserProfile(features)
    const veryNew = r.riskFactors.find((f) => f.factor === "VERY_NEW_ACCOUNT")
    expect(veryNew?.description).toBe("Account created 12 days ago (very new)")
  })

  it("applies exclusive_with (no double-counting age bands)", () => {
    const features = makeFeatures({ accountAgeDays: 10, ownedReposCount: 12 })
    const r = scoreUserProfile(features)
    const ids = r.riskFactors.map((f) => f.factor)
    expect(ids).toContain("VERY_NEW_ACCOUNT")
    expect(ids).not.toContain("NEW_ACCOUNT")
  })

  it("consumes a supplied ruleset (wiring is live, not hardcoded)", () => {
    // A custom ruleset that only flags accounts with < 5 followers, weight 0.9.
    const custom = {
      riskFactors: [
        {
          id: "FEW_FOLLOWERS",
          name: "Few followers",
          description: "Only {followers} followers",
          weight: 0.9,
          condition: { field: "followers" as const, operator: "lt" as const, value: 5 }
        }
      ],
      trustSignals: [],
      riskLevels: {
        mediumMinScore: 0.4,
        highMinScore: 0.7,
        recommendations: { low: "low", medium: "medium", high: "high" }
      }
    }
    // A profile that the DEFAULT ruleset would rate low, but this custom one rates high.
    const features = makeFeatures({ accountAgeDays: 2000, followers: 2, following: 1, ownedReposCount: 30, totalStars: 100 })
    expect(scoreUserProfile(features).riskLevel).toBe("low")
    const r = scoreUserProfile(features, custom)
    expect(r.riskLevel).toBe("high")
    expect(r.riskFactors[0]?.description).toBe("Only 2 followers")
  })
})
