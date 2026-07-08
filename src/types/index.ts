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

export interface GitHubScanResult extends RiskAssessment {
  repo: GitHubRepoInfo
  /**
   * The commit the verdict applies to. Every file read during the scan is
   * pinned to this SHA, so the assessment can't straddle a push (TOCTOU) —
   * and consumers should surface it: a verdict is a statement about this
   * commit, not about whatever the branch points to later.
   */
  commitSha?: string
  scanSummary: {
    filesScanned: number
    patternsMatched: number
    dependenciesChecked: number
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
  /** Minimum regex matches in one file before the rule fires (default 1). */
  minMatches?: number
  /** Restrict the rule to files with these extensions (default: all scanned files). */
  fileExtensions?: string[]
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
