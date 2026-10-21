/**
 * Git-history signals.
 *
 * PolinRider (2026) takes over real maintainer accounts and force-pushes
 * loader code in commits backdated by months (one was dated 267 days before
 * it was pushed), so the repo's visible history looks old and trusted. A
 * commit's own dates can be forged; the time GitHub received the push cannot.
 * The repository activity API records every push to a branch with that time,
 * its before/after SHAs and whether it was a force push.
 */

import type { GitHubFinding } from "../types/index.js"

export interface RepoActivityEvent {
  activity_type: string
  timestamp: string
  ref: string
  before: string
  after: string
}

export interface RepoCommit {
  sha: string
  commit: {
    committer?: { date?: string } | null
    verification?: { verified?: boolean } | null
  }
}

/** A push this long after the pushed commit's own date reads as backdating. */
const BACKDATED_PUSH_DAYS = 30
/** Bare force pushes older than this say nothing about the current code. */
const RECENT_FORCE_PUSH_DAYS = 90
const DAY_MS = 24 * 60 * 60 * 1000
const NULL_SHA = /^0+$/

/**
 * Pure part: given recent activity on `branch` and its recent commits, flag
 * pushes whose head commit claims to be much older than the push itself.
 * Signed (verified) commits are exempt — account takeovers don't carry the
 * owner's signing key. Branch creation and pushes onto an empty ref are
 * exempt too, because importing or mirroring old history looks the same.
 */
export function detectHistoryTampering(
  activity: RepoActivityEvent[],
  commits: RepoCommit[],
  branch: string,
  now = Date.now()
): GitHubFinding[] {
  const ref = `refs/heads/${branch}`
  const onBranch = activity.filter((event) => event.ref === ref)
  const commitsBySha = new Map(commits.map((commit) => [commit.sha, commit]))

  let worst: { event: RepoActivityEvent; committedAt: Date; lagDays: number } | null = null
  for (const event of onBranch) {
    if (event.activity_type !== "push" && event.activity_type !== "force_push") continue
    if (!event.before || NULL_SHA.test(event.before)) continue
    const commit = commitsBySha.get(event.after)
    if (!commit || commit.commit.verification?.verified) continue
    const committed = commit.commit.committer?.date
    if (!committed) continue
    const committedAt = new Date(committed)
    const lagDays = Math.floor((Date.parse(event.timestamp) - committedAt.getTime()) / DAY_MS)
    if (lagDays >= BACKDATED_PUSH_DAYS && (!worst || lagDays > worst.lagDays)) {
      worst = { event, committedAt, lagDays }
    }
  }

  if (worst) {
    const force = worst.event.activity_type === "force_push"
    const sha = worst.event.after.slice(0, 7)
    return [{
      severity: force ? "high" : "medium",
      confidence: "medium",
      type: "GIT_HISTORY_TAMPERING",
      pattern: "BACKDATED_PUSH",
      description:
        `Unsigned commit ${sha} on ${branch} is dated ${worst.committedAt.toISOString().slice(0, 10)} ` +
        `but was ${force ? "force-pushed" : "pushed"} ${worst.lagDays} days later (${worst.event.timestamp.slice(0, 10)})`,
      codeExplanation:
        "🕰️ The commit's date says it is old, but GitHub only received it recently. Account-takeover campaigns (PolinRider) backdate commits and force-push them so new loader code looks like long-standing history. Check what this commit changed before cloning.",
    }]
  }

  const forcePushes = onBranch.filter(
    (event) =>
      event.activity_type === "force_push" &&
      now - Date.parse(event.timestamp) < RECENT_FORCE_PUSH_DAYS * DAY_MS
  )
  if (forcePushes.length > 0) {
    const latest = forcePushes[0]!
    return [{
      severity: "low",
      confidence: "low",
      cloneBlocking: false,
      type: "GIT_HISTORY_TAMPERING",
      pattern: "FORCE_PUSH",
      description:
        `${branch} history was rewritten by a force push on ${latest.timestamp.slice(0, 10)}` +
        (forcePushes.length > 1 ? ` (${forcePushes.length} force pushes in the last ${RECENT_FORCE_PUSH_DAYS} days)` : ""),
      codeExplanation:
        "Force pushes are common in personal repositories, but they also hide which code is new. Compare the current code with what you expected before running it.",
    }]
  }

  return []
}

/**
 * Network part: two extra API calls. Any failure (rate limit, private repo,
 * API unavailable) yields no history signal rather than failing the scan.
 */
export async function fetchHistorySignals(
  repoPath: string,
  branch: string,
  commitSha: string,
  headers: Record<string, string>
): Promise<GitHubFinding[]> {
  try {
    const ref = encodeURIComponent(`refs/heads/${branch}`)
    const [activityResponse, commitsResponse] = await Promise.all([
      fetch(`https://api.github.com/repos/${repoPath}/activity?ref=${ref}&per_page=100`, { headers }),
      fetch(`https://api.github.com/repos/${repoPath}/commits?sha=${commitSha}&per_page=100`, { headers }),
    ])
    if (!activityResponse.ok || !commitsResponse.ok) return []
    const activity: unknown = await activityResponse.json()
    const commits: unknown = await commitsResponse.json()
    if (!Array.isArray(activity) || !Array.isArray(commits)) return []
    return detectHistoryTampering(activity as RepoActivityEvent[], commits as RepoCommit[], branch)
  } catch {
    return []
  }
}
