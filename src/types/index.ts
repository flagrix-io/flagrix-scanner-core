/**
 * Core type definitions for @flagrix/scanner-core
 * Shared across GitHub, LinkedIn, and PDF scanners.
 */

// ─── Risk primitives ────────────────────────────────────────────────────────

export type RiskLevel = "low" | "medium" | "high"

export interface RiskFactor {
  factor: string
  weight: number
  description: string
}

export interface RiskAssessment {
  riskScore: number // 0–1 scale
  riskLevel: RiskLevel
  factors: RiskFactor[]
  disclaimer: string
}

// ─── LinkedIn ────────────────────────────────────────────────────────────────

export interface LinkedInProfileFeatures {
  profileUrl: string
  accountAgeDays: number | null
  connectionCount: number | null
  followerCount: number | null
  hasProfilePhoto: boolean
  workHistoryCount: number
  educationCount: number
  endorsementCount: number
  postCount: number
  mutualConnections: number
  profileCompleteness: number // 0–1 scale
  name: string | null
  headline: string | null
  location: string | null
  isVerified: boolean
  isTopVoice: boolean
  hasJobPostings: boolean
  hasOpenToWork: boolean
}

export interface LinkedInScanResult extends RiskAssessment {
  profile: LinkedInProfileFeatures
  scannedAt: Date
}

// ─── GitHub repo ─────────────────────────────────────────────────────────────

export type ScanDepth = "quick" | "standard" | "deep"

export interface GitHubRepoInfo {
  owner: string
  repo: string
  branch: string
  url: string
}

export interface GitHubFinding {
  severity: "critical" | "high" | "medium" | "low" | "info"
  /**
   * Confidence that the matched code represents the behavior described by
   * the finding. Severity describes impact; confidence describes certainty.
   * Older/custom findings omit this and retain the historical high-confidence
   * scoring behavior.
   */
  confidence?: "high" | "medium" | "low"
  /**
   * Whether this finding should contribute to the "safe to clone" verdict.
   * Runtime/deployment configuration warnings can be important without making
   * the repository contents unsafe to inspect locally.
   */
  cloneBlocking?: boolean
  type:
    | "MALWARE_SIGNATURE"
    | "OBFUSCATED_CODE"
    | "SUSPICIOUS_DEPENDENCY"
    | "POSTINSTALL_SCRIPT"
    | "TYPOSQUAT_PACKAGE"
    | "HIDDEN_FILE"
    | "SUSPICIOUS_URL"
    | "NON_ENGLISH_COMMENTS"
    | "SUSPICIOUS_PACKAGE_NAME"
    | "HARDCODED_SECRETS"
    | "NETWORK_COMMUNICATION"
    | "CRYPTO_MINER"
    | "DATA_EXFILTRATION"
    | "BACKDOOR"
    | "SUPPLY_CHAIN_RISK"
    | "SUSPICIOUS_FILE_ACCESS"
    | "CODE_INTEGRITY_ISSUE"
    | "SOCIAL_ENGINEERING"
    | "INSECURE_CONFIGURATION"
    | "GIT_HISTORY_TAMPERING"
  file?: string
  line?: number
  pattern?: string
  package?: string
  description: string
  files?: string[]
  codeSnippet?: string
  codeExplanation?: string
  /** Matched source lines in `file`, for display and `#L<n>` deep links. */
  evidence?: FindingEvidence[]
}

export interface FindingEvidence {
  /** 1-based line number in the finding's `file`. */
  line: number
  /** The trimmed source line (length-capped). */
  code: string
}

/** Why a file in the repo tree was not content-scanned. */
export type SkipReason =
  | "unsupported-type" // not a code/manifest file type the scanner reads
  | "over-file-limit" // eligible, but past the per-scan file cap
  | "too-large" // eligible, but blob exceeds the size limit
  | "fetch-failed" // selected, but the contents API request failed
  | "rate-limited" // selected, but the GitHub request budget ran out first

export interface SkippedFile {
  path: string
  reason: SkipReason
}

export interface GitHubScanResult extends RiskAssessment {
  repo: GitHubRepoInfo
  /**
   * The commit the verdict applies to. Every file read during the scan is
   * pinned to this SHA, so the assessment can't straddle a push (TOCTOU) —
   * and consumers should surface it: a verdict is a statement about this
   * commit, not about whatever the branch points to later.
   */
  commitSha?: string
  /**
   * Sum of finding weights before the 1.0 clamp. When this exceeds 1,
   * per-finding deductions add up to more than the displayed score —
   * consumers can use it to label the score as "capped".
   */
  rawRiskScore: number
  scanSummary: {
    filesScanned: number
    patternsMatched: number
    dependenciesChecked: number
    /** Paths whose contents were actually scanned. */
    scannedFiles: string[]
    /**
     * Files in the tree that were not content-scanned, with the reason.
     * List is capped (see MAX_SKIPPED_FILES_LISTED); `skippedCount` is the
     * true total.
     */
    skippedFiles: SkippedFile[]
    skippedCount: number
    /** GitHub returned a partial tree (repo too large for one tree call). */
    treeTruncated: boolean
    /**
     * How the repo's contents were read, which decides how much of it was
     * read. `"tarball"` is one request for the whole commit, so the budget is
     * a byte cap and coverage runs to thousands of files; `"per-file"` is one
     * request per file, so the budget is 200 files whatever the repo's size.
     *
     * Consumers must surface this. Two people can get different scores for
     * the same commit depending on which reader ran — the extension's tarball
     * read is behind an optional host permission — and for a security tool a
     * verdict that varies silently is worse than one that is slow.
     */
    readMode: "tarball" | "per-file"
    /**
     * Why the tarball read was not used, when the caller asked for one.
     * Absent on a `"tarball"` read and when the caller never asked.
     */
    readFallbackReason?: "too-large" | "unavailable" | "unreadable"
    /**
     * Whether every file the scan selected was actually read. False means the
     * verdict rests on partial evidence — unread files cannot clear a repo, so
     * a "no findings" result is only as strong as its coverage. Consumers must
     * qualify the verdict when this is false rather than presenting it as a
     * clean bill of health.
     */
    complete: boolean
    /** Why coverage fell short, when `complete` is false. */
    incompleteReason?: "rate-limit" | "fetch-errors"
  }
  findings: GitHubFinding[]
  safeToClone: boolean
  scannedAt: Date
}

// ─── GitHub user ─────────────────────────────────────────────────────────────

export interface GitHubUserFeatures {
  username: string
  accountAgeDays: number
  followers: number
  following: number
  followerFollowingRatio: number
  publicRepos: number
  ownedReposCount: number
  totalStars: number
  repoStarRatio: number
  hasProfilePhoto: boolean
  isProfileComplete: boolean
  hasCompany: boolean
  hasBio: boolean
  recentEventCount: number
  veryRecentEventCount: number
  profileUrl: string
  scannedAt: string
}

export interface GitHubUserScanResult {
  username: string
  riskLevel: RiskLevel
  riskScore: number
  riskFactors: RiskFactor[]
  trustSignals: RiskFactor[]
  recommendation: string
  profileUrl: string
  accountAgeDays: number
  followers: number
  publicRepos: number
  scannedAt: string
}

// ─── PDF / Document ──────────────────────────────────────────────────────────

export interface DocumentMetadata {
  type: string
  sizeBytes: number
  pages?: number
  hash: string
}

export interface StaticAnalysisResult {
  hasJavaScript: boolean
  hasEmbeddedFiles: boolean
  hasLaunchAction: boolean
  hasSuspiciousUrls: boolean
  suspiciousUrls?: string[]
}

export interface VirusTotalResult {
  detected: boolean
  enginesChecked: number
  detections: number
  scanId?: string
}

export interface DocumentScanResult extends RiskAssessment {
  metadata: DocumentMetadata
  staticAnalysis: StaticAnalysisResult
  virusTotal?: VirusTotalResult
  safeToOpen: boolean
  scannedAt: Date
}

// ─── Signature database ──────────────────────────────────────────────────────

export interface MaliciousPackage {
  name: string
  version?: string
  versions?: string[]
  severity: "critical" | "high" | "medium"
  source: string
  description?: string
}

export interface YaraRule {
  id: string
  name: string
  pattern: string
  description: string
  tags: string[]
  severity: "critical" | "high" | "medium" | "low"
  /** Confidence in the rule after its optional context check succeeds. */
  confidence?: "high" | "medium" | "low"
  /** Optional behavioral context required in addition to the primary regex. */
  context?: "keyboard-capture"
  /** Minimum regex matches in one file before the rule fires (default 1). */
  minMatches?: number
  /** Restrict the rule to files with these extensions (default: all scanned files). */
  fileExtensions?: string[]
  /** Restrict the rule to exact file basenames (default: all scanned files). */
  fileNames?: string[]
}

export interface KnownBadHash {
  sha256: string
  type: "pdf" | "js" | "binary"
  malwareFamily?: string
  source: string
}

export interface SignatureDatabase {
  version: string
  lastUpdated: Date
  maliciousPackages: MaliciousPackage[]
  yaraRules: YaraRule[]
  knownBadHashes: KnownBadHash[]
  /** GitHub user-profile scoring ruleset. Optional — falls back to the
   *  scanner's built-in DEFAULT_USER_PROFILE_RULES when absent. */
  userProfileRules?: UserProfileRuleset
}

// ─── GitHub user-profile scoring ruleset ─────────────────────────────────────

/** Feature fields on GitHubUserFeatures that a profile condition may test. */
export type ProfileFeatureField =
  | "accountAgeDays"
  | "followers"
  | "following"
  | "followerFollowingRatio"
  | "ownedReposCount"
  | "totalStars"
  | "recentEventCount"
  | "veryRecentEventCount"
  | "hasProfilePhoto"
  | "isProfileComplete"

export type ProfileOperator = "lt" | "lte" | "gt" | "gte" | "eq"

export interface ProfileSimpleCondition {
  field: ProfileFeatureField
  operator: ProfileOperator
  value: number | boolean
}

/** Compound condition — matches only when every sub-condition matches. */
export interface ProfileCompoundCondition {
  all: ProfileSimpleCondition[]
}

export type ProfileCondition = ProfileSimpleCondition | ProfileCompoundCondition

export interface ProfileRiskRule {
  id: string
  name: string
  /** Supports `{fieldName}` tokens, interpolated from the scanned features. */
  description: string
  weight: number
  condition: ProfileCondition
  /** If the referenced rule id already matched, this rule is skipped. */
  exclusiveWith?: string
}

export interface ProfileRiskLevels {
  /** score ≥ this ⇒ at least medium risk */
  mediumMinScore: number
  /** score ≥ this ⇒ high risk */
  highMinScore: number
  recommendations: { low: string; medium: string; high: string }
}

export interface UserProfileRuleset {
  riskFactors: ProfileRiskRule[]
  trustSignals: ProfileRiskRule[]
  riskLevels: ProfileRiskLevels
}

// ─── Scanner options ─────────────────────────────────────────────────────────

export interface RepoScanOptions {
  githubToken?: string
  signatures: SignatureDatabase
  /**
   * osv-malicious.json from flagrix-detection-rules: every confirmed-malicious
   * npm/PyPI package (OSV MAL-* records). Matched locally against declared
   * dependencies; omit to check only the curated list in `signatures`.
   */
  osvFeed?: OsvMaliciousFeed
  /**
   * Read the whole commit in one request (`/tarball/{sha}`) instead of one
   * request per file. It is faster and reads far more of the repo — react
   * goes from 226 files in 16.5s to 4,565 in 6.7s — and it costs one
   * rate-limit unit instead of hundreds, which is what makes a scan without a
   * token viable at all against the anonymous 60-requests-an-hour limit.
   *
   * Off by default, because asking is not free: the endpoint redirects to
   * codeload.github.com, so a browser extension needs that origin granted,
   * and a request made without it costs a round trip before it fails. Turn it
   * on wherever that host is reachable. Every failure falls back to the
   * per-file path, and `scanSummary.readMode` reports which one ran.
   */
  tarball?: boolean
}

/** Packages malicious in every version (`all`) or in the listed `versions`. */
export interface OsvEcosystemFeed {
  all: string[]
  versions: Record<string, string[]>
}

export interface OsvMaliciousFeed {
  schemaVersion: number
  source?: string
  /** Newest record's modified date. */
  updated?: string
  counts?: { npm: number; pypi: number }
  npm: OsvEcosystemFeed
  /** Names are PEP 503-normalised (lowercase, runs of -_. → -). */
  pypi: OsvEcosystemFeed
}

export interface UserScanOptions {
  githubToken?: string
  /** Profile-scoring ruleset (typically from the fetched SignatureDatabase).
   *  Falls back to DEFAULT_USER_PROFILE_RULES when omitted. */
  userProfileRules?: UserProfileRuleset
}

// ─── Constants ───────────────────────────────────────────────────────────────

/**
 * Score boundaries used by `getRiskLevel` (repo scans) and the LinkedIn profile
 * scorer: a score below `low` is low risk, below `high` is medium risk, and at
 * or above `high` is high risk. The GitHub user scanner applies its own tuned
 * thresholds because profile signals distribute differently from code findings.
 */
export const RISK_THRESHOLDS = {
  low: 0.3,
  high: 0.6,
} as const

export const DEFAULT_DISCLAIMER =
  "Risk assessment only. Not a definitive fraud determination. Always verify through official channels."
