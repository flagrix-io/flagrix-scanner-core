import { describe, expect, it } from "vitest"
import {
  detectHistoryTampering,
  type RepoActivityEvent,
  type RepoCommit,
} from "../src/github/history-signals"

const A = "a".repeat(40)
const B = "b".repeat(40)
const C = "c".repeat(40)

const event = (
  activity_type: string,
  timestamp: string,
  after: string,
  before = A,
  ref = "refs/heads/main"
): RepoActivityEvent => ({ activity_type, timestamp, ref, before, after })

const commit = (sha: string, date: string, verified = false): RepoCommit => ({
  sha,
  commit: { committer: { date }, verification: { verified } },
})

describe("detectHistoryTampering", () => {
  it("flags an unsigned commit force-pushed months after its own date", () => {
    // PolinRider example: dated 2025-11-06, pushed 2026-07-31.
    const findings = detectHistoryTampering(
      [event("force_push", "2026-07-31T10:00:00Z", B)],
      [commit(B, "2025-11-06T09:00:00Z")],
      "main"
    )
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      severity: "high",
      confidence: "medium",
      type: "GIT_HISTORY_TAMPERING",
      pattern: "BACKDATED_PUSH",
    })
    expect(findings[0]!.description).toContain("267 days later")
  })

  it("rates a backdated ordinary push medium", () => {
    const findings = detectHistoryTampering(
      [event("push", "2026-07-31T10:00:00Z", B)],
      [commit(B, "2026-05-01T09:00:00Z")],
      "main"
    )
    expect(findings[0]).toMatchObject({ severity: "medium", pattern: "BACKDATED_PUSH" })
  })

  it("ignores signed commits, recent commits, branch creation, PR merges and other branches", () => {
    const findings = detectHistoryTampering(
      [
        event("push", "2026-07-31T10:00:00Z", B),                  // signed
        event("push", "2026-07-31T10:00:00Z", C),                  // committed last week
        event("branch_creation", "2026-07-31T10:00:00Z", A, "0".repeat(40)),
        event("push", "2026-07-31T10:00:00Z", A, "0".repeat(40)), // onto an empty ref
        event("pr_merge", "2026-07-31T10:00:00Z", A),
        event("force_push", "2026-07-31T10:00:00Z", A, B, "refs/heads/feature"),
      ],
      [
        commit(A, "2025-01-01T00:00:00Z"),
        commit(B, "2025-01-01T00:00:00Z", true),
        commit(C, "2026-07-24T00:00:00Z"),
      ],
      "main"
    )
    expect(findings).toEqual([])
  })

  it("reports a bare force push as low, non-blocking information", () => {
    const findings = detectHistoryTampering(
      [event("force_push", "2026-07-31T10:00:00Z", C), event("force_push", "2026-07-01T10:00:00Z", B)],
      [commit(C, "2026-07-31T09:00:00Z")],
      "main",
      Date.parse("2026-08-15T00:00:00Z")
    )
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      severity: "low",
      confidence: "low",
      cloneBlocking: false,
      pattern: "FORCE_PUSH",
    })
    expect(findings[0]!.description).toContain("2 force pushes in the last 90 days")
  })

  it("ignores force pushes older than 90 days", () => {
    expect(detectHistoryTampering(
      [event("force_push", "2026-01-01T10:00:00Z", C)],
      [commit(C, "2026-01-01T09:00:00Z")],
      "main",
      Date.parse("2026-10-19T00:00:00Z")
    )).toEqual([])
  })
})
