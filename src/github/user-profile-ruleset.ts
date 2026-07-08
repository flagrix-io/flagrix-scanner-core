/**
 * Default GitHub user-profile scoring ruleset.
 *
 * This is a fallback mirror of `flagrix-detection-rules/rules/github/user-profile.yaml`,
 * used when a scan runs without a fetched SignatureDatabase (offline / first run).
 * When the extension fetches signatures, the compiled `userProfileRules` from the
 * rules repo override this — so profile heuristics can be updated without shipping
 * a new extension build. Keep this in sync with the yaml; the equivalence test in
 * `tests/user-scanner.test.ts` pins the scoring so drift is caught.
 */

import type { UserProfileRuleset } from "../types/index.js"

export const DEFAULT_USER_PROFILE_RULES: UserProfileRuleset = {
  riskFactors: [
    {
      id: "VERY_NEW_ACCOUNT",
      name: "Very New Account",
      description: "Account created {accountAgeDays} days ago (very new)",
      weight: 0.3,
      condition: { field: "accountAgeDays", operator: "lt", value: 30 }
    },
    {
      id: "NEW_ACCOUNT",
      name: "New Account",
      description: "Account created {accountAgeDays} days ago (new)",
      weight: 0.2,
      condition: { field: "accountAgeDays", operator: "lt", value: 90 },
      exclusiveWith: "VERY_NEW_ACCOUNT"
    },
    {
      id: "NO_REPOS",
      name: "No Public Repositories",
      description: "No public repositories",
      weight: 0.25,
      condition: { field: "ownedReposCount", operator: "eq", value: 0 }
    },
    {
      id: "SINGLE_REPO_CONTRIBUTOR",
      name: "Single Repository Only",
      description: "Only 1 repository (potential throwaway account)",
      weight: 0.15,
      condition: { field: "ownedReposCount", operator: "eq", value: 1 },
      exclusiveWith: "NO_REPOS"
    },
    {
      id: "NO_FOLLOWERS",
      name: "Zero Followers",
      description: "Zero followers",
      weight: 0.2,
      condition: { field: "followers", operator: "eq", value: 0 }
    },
    {
      id: "HIGH_FOLLOWING_RATIO",
      name: "High Following-to-Follower Ratio",
      description: "Following {following} but only {followers} followers (bot pattern)",
      weight: 0.2,
      condition: {
        all: [
          { field: "followerFollowingRatio", operator: "gt", value: 10 },
          { field: "following", operator: "gt", value: 10 }
        ]
      }
    },
    {
      id: "NO_PROFILE_PHOTO",
      name: "Default Avatar",
      description: "Using default avatar",
      weight: 0.15,
      condition: { field: "hasProfilePhoto", operator: "eq", value: false }
    },
    {
      id: "INCOMPLETE_PROFILE",
      name: "Incomplete Profile",
      description: "Missing bio, name, or location",
      weight: 0.1,
      condition: { field: "isProfileComplete", operator: "eq", value: false }
    },
    {
      id: "NO_RECENT_ACTIVITY",
      name: "No Recent Activity",
      description: "No activity in last 90 days",
      weight: 0.15,
      condition: { field: "recentEventCount", operator: "eq", value: 0 }
    }
  ],
  trustSignals: [
    {
      id: "VERY_ESTABLISHED",
      name: "Very Established Account",
      description: "Account is {accountAgeDays} days old (very established)",
      weight: -0.25,
      condition: { field: "accountAgeDays", operator: "gte", value: 1095 }
    },
    {
      id: "ESTABLISHED_ACCOUNT",
      name: "Established Account",
      description: "Account is {accountAgeDays} days old (established)",
      weight: -0.15,
      condition: { field: "accountAgeDays", operator: "gte", value: 365 },
      exclusiveWith: "VERY_ESTABLISHED"
    },
    {
      id: "POPULAR_DEVELOPER",
      name: "Popular Developer",
      description: "{followers} followers (popular developer)",
      weight: -0.25,
      condition: { field: "followers", operator: "gte", value: 200 }
    },
    {
      id: "STRONG_FOLLOWER_BASE",
      name: "Strong Follower Base",
      description: "{followers} followers",
      weight: -0.15,
      condition: { field: "followers", operator: "gte", value: 50 },
      exclusiveWith: "POPULAR_DEVELOPER"
    },
    {
      id: "PROLIFIC_DEVELOPER",
      name: "Prolific Developer",
      description: "{ownedReposCount} repositories (prolific developer)",
      weight: -0.3,
      condition: { field: "ownedReposCount", operator: "gte", value: 50 }
    },
    {
      id: "ACTIVE_CONTRIBUTOR",
      name: "Active Contributor",
      description: "{ownedReposCount} repositories",
      weight: -0.2,
      condition: { field: "ownedReposCount", operator: "gte", value: 10 },
      exclusiveWith: "PROLIFIC_DEVELOPER"
    },
    {
      id: "HAS_POPULAR_REPOS",
      name: "Has Popular Repositories",
      description: "{totalStars} total stars across repositories",
      weight: -0.2,
      condition: { field: "totalStars", operator: "gte", value: 50 }
    },
    {
      id: "CONSISTENT_ACTIVITY",
      name: "Consistent Recent Activity",
      description: "{veryRecentEventCount} events in last 30 days",
      weight: -0.15,
      condition: { field: "veryRecentEventCount", operator: "gt", value: 0 }
    }
  ],
  riskLevels: {
    mediumMinScore: 0.4,
    highMinScore: 0.7,
    recommendations: {
      low: "Profile appears legitimate. Standard caution advised for any collaboration requests.",
      medium:
        "Moderate risk. Review profile carefully. Check repository quality and recent activity before accepting collaboration.",
      high: "High risk profile. Exercise extreme caution. Verify identity through other channels before trusting any collaboration requests."
    }
  }
}
