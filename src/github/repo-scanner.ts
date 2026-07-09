/**
 * GitHub Repository Scanner
 *
 * Scans GitHub repositories for malware signatures, obfuscated code,
 * suspicious dependencies, and postinstall scripts.
 *
 * Uses GitHub API to fetch repo contents without full clone.
 * No chrome.storage dependency — token and signatures are passed as options.
 */

import { franc } from "franc-min"
import type {
  GitHubFinding,
  GitHubRepoInfo,
  GitHubScanResult,
  MaliciousPackage,
  RepoScanOptions,
  SkippedFile,
} from "../types/index.js"
import { DEFAULT_DISCLAIMER } from "../types/index.js"
import { collectEvidence } from "../utils/evidence.js"
import { maskRegexLiterals, maskStringLiterals } from "../utils/mask.js"
import { githubApiError } from "./api-error.js"
import {
  calculateRawRiskScore,
  calculateRiskScore,
  getRiskLevel,
  getSeverityWeight,
} from "../utils/risk-calculator.js"
import { applyYaraRules, isTestFile } from "../rules/rule-matcher.js"

// High-risk files to always check
const PRIORITY_FILES = [
  "package.json",
  "package-lock.json",
  "requirements.txt",
  "setup.py",
  "Pipfile",
  ".npmrc",
  ".yarnrc",
  "Makefile",
]

const SCANNABLE_EXTENSIONS = [
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".py",
  ".rb",
  ".php",
  ".go",
  ".sh",
  ".ps1",
  ".psm1",
  ".bat",
  ".cmd",
  ".vbs",
]
const MAX_FILES_TO_SCAN = 200
// Blobs above this are skipped ("too-large"): almost always bundles or
// vendored artifacts, and fetching them dominates scan time on big repos.
const MAX_FILE_SIZE_BYTES = 1024 * 1024
// skippedFiles list cap — skippedCount stays accurate; this only bounds the
// per-path detail so huge repos don't bloat the result object.
const MAX_SKIPPED_FILES_LISTED = 500

// npm download count cache (in-memory)
interface NpmDownloadCacheEntry {
  weeklyDownloads: number | null
  fetchedAt: number
}
const NPM_DOWNLOAD_CACHE = new Map<string, NpmDownloadCacheEntry>()
const NPM_CACHE_TTL_MS = 60 * 60 * 1000
const NPM_HIGH_DOWNLOAD_THRESHOLD = 100_000

interface GitHubTreeItem {
  path: string
  type: "blob" | "tree"
  sha: string
  size?: number
  url: string
}

interface GitHubTreeResponse {
  sha: string
  tree: GitHubTreeItem[]
  truncated: boolean
}

export async function scanGitHubRepo(
  repo: GitHubRepoInfo,
  options: RepoScanOptions
): Promise<GitHubScanResult> {
  const findings: GitHubFinding[] = []
  let filesScanned = 0
  let patternsMatched = 0
  let dependenciesChecked = 0

  try {
    const headers: Record<string, string> = {
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "Flagrix-Extension",
    }

    if (options.githubToken) {
      headers["Authorization"] = `Bearer ${options.githubToken}`
    }

    let branch = repo.branch
    if (!branch) {
      const repoResponse = await fetch(
        `https://api.github.com/repos/${repo.owner}/${repo.repo}`,
        { headers }
      )
      if (repoResponse.status === 404 && !options.githubToken) {
        throw new Error(
          "This appears to be a private repository. To scan private repos, add a GitHub personal access token in Flagrix settings."
        )
      }
      if (!repoResponse.ok) {
        throw await githubApiError(repoResponse)
      }
      const repoData = await repoResponse.json()
      branch = repoData.default_branch || "main"
    }

    // Pin the scan to the branch's current commit so the whole read — tree
    // and every file — is one immutable snapshot. Without this, the repo can
    // change between requests (or between scan and clone) while the verdict
    // silently keeps referring to content nobody can see anymore (TOCTOU).
    const commitResponse = await fetch(
      `https://api.github.com/repos/${repo.owner}/${repo.repo}/commits/${encodeURIComponent(branch)}`,
      { headers }
    )
    if (commitResponse.status === 404 && !options.githubToken) {
      throw new Error(
        "This appears to be a private repository. To scan private repos, add a GitHub personal access token in Flagrix settings."
      )
    }
    if (!commitResponse.ok) {
      throw await githubApiError(commitResponse)
    }
    const commitSha: string = (await commitResponse.json()).sha

    const treeUrl = `https://api.github.com/repos/${repo.owner}/${repo.repo}/git/trees/${commitSha}?recursive=1`
    const treeResponse = await fetch(treeUrl, { headers })

    if (treeResponse.status === 404 && !options.githubToken) {
      throw new Error(
        "This appears to be a private repository. To scan private repos, add a GitHub personal access token in Flagrix settings."
      )
    }
    if (!treeResponse.ok) {
      throw await githubApiError(treeResponse)
    }

    const tree: GitHubTreeResponse = await treeResponse.json()

    // Partition every blob into "scan" vs "skip + why", so the UI can show
    // exactly which files were read and why the rest were not.
    const skippedFiles: SkippedFile[] = []
    let skippedCount = 0
    const skip = (path: string, reason: SkippedFile["reason"]) => {
      skippedCount++
      if (skippedFiles.length < MAX_SKIPPED_FILES_LISTED) {
        skippedFiles.push({ path, reason })
      }
    }

    const filesToScan: GitHubTreeItem[] = []
    for (const item of tree.tree) {
      if (item.type !== "blob") continue
      const eligible =
        PRIORITY_FILES.some((pf) => item.path.endsWith(pf)) ||
        SCANNABLE_EXTENSIONS.some((ext) => item.path.endsWith(ext))
      if (!eligible) {
        skip(item.path, "unsupported-type")
      } else if (item.size !== undefined && item.size > MAX_FILE_SIZE_BYTES) {
        skip(item.path, "too-large")
      } else if (filesToScan.length >= MAX_FILES_TO_SCAN) {
        skip(item.path, "over-file-limit")
      } else {
        filesToScan.push(item)
      }
    }

    // Check for hidden files with suspicious names
    const hiddenFiles = tree.tree.filter(
      (item) =>
        item.path.startsWith(".") &&
        !item.path.startsWith(".github") &&
        !item.path.startsWith(".git") &&
        item.type === "blob"
    )

    for (const hidden of hiddenFiles) {
      if (
        hidden.path.includes("backdoor") ||
        hidden.path.includes("payload") ||
        hidden.path.includes("shell")
      ) {
        findings.push({
          severity: "high",
          type: "HIDDEN_FILE",
          file: hidden.path,
          description: `Suspicious hidden file: ${hidden.path}`,
        })
        patternsMatched++
      }
    }

    const maliciousPackages = options.signatures.maliciousPackages
    const yaraRules = options.signatures.yaraRules
    // Rule ids present in the loaded signatures — built-in checks with a
    // data-driven twin yield to it, so one signal is never counted twice
    // (see BUILTIN_OBFUSCATION_RULE_IDS and the ruleId fields on the
    // pattern tables in the detectors below).
    const loadedRuleIds: ReadonlySet<string> = new Set(yaraRules.map((r) => r.id))

    const fileContents: Array<{ path: string; content: string }> = []
    const scannedFiles: string[] = []

    for (const file of filesToScan) {
      const contentUrl = `https://api.github.com/repos/${repo.owner}/${repo.repo}/contents/${file.path}?ref=${commitSha}`
      const contentResponse = await fetch(contentUrl, { headers })

      if (!contentResponse.ok) {
        skip(file.path, "fetch-failed")
        continue
      }

      filesScanned++
      scannedFiles.push(file.path)

      const fileData = await contentResponse.json()
      const content = atob(fileData.content || "")

      // In JS/TS, blank out regex-literal interiors before pattern matching:
      // a regex *describing* a malicious pattern is inert data, and matching
      // it would flag every security tool, linter, and tutorial repo
      // (including this scanner's own source). Masking preserves offsets so
      // evidence line numbers stay true; strings/comments stay scannable.
      const isJsTs = /\.(?:[cm]?js|ts|[jt]sx)$/.test(file.path)
      let matchable = isJsTs ? maskRegexLiterals(content) : content
      // In test files, string literals are fixtures — the inputs that prove
      // detectors work — so mask those too. Real malware in a test file is
      // actual code (the `npm test` attack) and stays fully scannable.
      if (isJsTs && isTestFile(file.path)) {
        matchable = maskStringLiterals(matchable)
      }

      if (SCANNABLE_EXTENSIONS.some((ext) => file.path.endsWith(ext))) {
        fileContents.push({ path: file.path, content: matchable })
      }

      if (file.path.endsWith("package.json")) {
        const pkgFindings = await scanPackageJson(content, maliciousPackages, file.path)
        findings.push(...pkgFindings)
        patternsMatched += pkgFindings.length
        dependenciesChecked += countDependencies(content)

        const postinstallFindings = checkPostinstallScripts(content, file.path)
        findings.push(...postinstallFindings)
        patternsMatched += postinstallFindings.length
      }

      if (file.path.endsWith("requirements.txt") || file.path.endsWith("setup.py")) {
        const pyFindings = scanPythonDeps(content, maliciousPackages, file.path)
        findings.push(...pyFindings)
        patternsMatched += pyFindings.length
      }

      if (SCANNABLE_EXTENSIONS.some((ext) => file.path.endsWith(ext))) {
        const yaraFindings = applyYaraRules(matchable, yaraRules, file.path)
        findings.push(...yaraFindings)
        patternsMatched += yaraFindings.length

        const obfuscationFindings = detectObfuscation(matchable, file.path, loadedRuleIds)
        findings.push(...obfuscationFindings)
        patternsMatched += obfuscationFindings.length
      }
    }

    // Non-English comment detection (source files only, not tests)
    const sourceFiles = fileContents.filter((f) => !isTestFile(f.path))
    const languageFindings = await detectNonEnglishComments(sourceFiles, repo)
    findings.push(...languageFindings)
    patternsMatched += languageFindings.length

    // Comprehensive security checks
    for (const file of fileContents) {
      const secretFindings = detectHardcodedSecrets(file.content, file.path, loadedRuleIds)
      findings.push(...secretFindings)
      patternsMatched += secretFindings.length

      const networkFindings = detectNetworkPatterns(file.content, file.path, loadedRuleIds)
      findings.push(...networkFindings)
      patternsMatched += networkFindings.length

      const miningFindings = detectCryptoMining(file.content, file.path, loadedRuleIds)
      findings.push(...miningFindings)
      patternsMatched += miningFindings.length

      const exfiltrationFindings = detectDataExfiltration(file.content, file.path, loadedRuleIds)
      findings.push(...exfiltrationFindings)
      patternsMatched += exfiltrationFindings.length

      const backdoorFindings = detectBackdoors(file.content, file.path, loadedRuleIds)
      findings.push(...backdoorFindings)
      patternsMatched += backdoorFindings.length

      const fileAccessFindings = detectSuspiciousFileAccess(file.content, file.path, loadedRuleIds)
      findings.push(...fileAccessFindings)
      patternsMatched += fileAccessFindings.length

      const socialEngFindings = detectSocialEngineering(file.content, file.path)
      findings.push(...socialEngFindings)
      patternsMatched += socialEngFindings.length
    }

    for (const file of fileContents) {
      if (file.path.endsWith("package.json")) {
        const packageNameFindings = detectSuspiciousPackageNames(file.content, file.path)
        findings.push(...packageNameFindings)
        patternsMatched += packageNameFindings.length

        const supplyChainFindings = detectSupplyChainRisks(file.content, file.path)
        findings.push(...supplyChainFindings)
        patternsMatched += supplyChainFindings.length
      }
    }

    // Pass every path in the tree (not just scanned source) so the
    // LICENSE/README presence checks see non-code files — otherwise they
    // false-positive on every repo.
    const allPaths = tree.tree.filter((i) => i.type === "blob").map((i) => i.path)
    const integrityFindings = await detectCodeIntegrityIssues(fileContents, allPaths, repo)
    findings.push(...integrityFindings)
    patternsMatched += integrityFindings.length

    const rawRiskScore = calculateRawRiskScore(findings)
    const riskScore = calculateRiskScore(findings)
    const riskLevel = getRiskLevel(riskScore, findings)

    return {
      riskScore,
      rawRiskScore,
      riskLevel,
      factors: findings.map((f) => ({
        factor: f.type,
        weight: getSeverityWeight(f.severity),
        description: f.description,
      })),
      disclaimer: DEFAULT_DISCLAIMER,
      repo,
      commitSha,
      scanSummary: {
        filesScanned,
        patternsMatched,
        dependenciesChecked,
        scannedFiles,
        skippedFiles,
        skippedCount,
        treeTruncated: tree.truncated,
      },
      findings,
      safeToClone: riskLevel === "low",
      scannedAt: new Date(),
    }
  } catch (error) {
    throw error
  }
}

// ─── Package scanning ─────────────────────────────────────────────────────────

async function scanPackageJson(
  content: string,
  maliciousPackages: MaliciousPackage[],
  filePath: string
): Promise<GitHubFinding[]> {
  const findings: GitHubFinding[] = []

  try {
    const pkg = JSON.parse(content)
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies }

    for (const [name] of Object.entries(allDeps)) {
      const malicious = maliciousPackages.find((m) => m.name === name)
      if (malicious) {
        findings.push({
          severity: malicious.severity as GitHubFinding["severity"],
          type: "SUSPICIOUS_DEPENDENCY",
          file: filePath,
          package: name,
          description: `Known malicious package: ${name}`,
        })
      }

      if (!name.startsWith("@")) {
        const typosquat = checkTyposquat(name)
        if (typosquat) {
          const weeklyDownloads = await getNpmWeeklyDownloads(name)
          const shouldFlag = weeklyDownloads === null || weeklyDownloads < NPM_HIGH_DOWNLOAD_THRESHOLD
          if (shouldFlag) {
            findings.push({
              severity: "medium",
              type: "TYPOSQUAT_PACKAGE",
              file: filePath,
              package: name,
              description: `Possible typosquat of "${typosquat}": ${name}`,
            })
          }
        }
      }
    }
  } catch {
    // Invalid JSON, skip
  }

  return findings
}

function checkPostinstallScripts(content: string, filePath: string): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  try {
    const pkg = JSON.parse(content)
    const scripts = pkg.scripts || {}
    const dangerousScripts = ["postinstall", "preinstall", "install"]

    for (const scriptName of dangerousScripts) {
      const script = scripts[scriptName]
      if (script) {
        if (
          script.includes("curl") ||
          script.includes("wget") ||
          script.includes("http") ||
          script.includes("fetch")
        ) {
          findings.push({
            severity: "high",
            type: "POSTINSTALL_SCRIPT",
            file: filePath,
            description: `${scriptName} script makes network requests: "${script.slice(0, 50)}..."`,
          })
        }
        if (script.includes("eval") || script.includes("exec")) {
          findings.push({
            severity: "critical",
            type: "POSTINSTALL_SCRIPT",
            file: filePath,
            description: `${scriptName} script executes dynamic code`,
          })
        }
      }
    }
  } catch {
    // Invalid JSON
  }

  return findings
}

function scanPythonDeps(
  content: string,
  maliciousPackages: MaliciousPackage[],
  filePath: string
): GitHubFinding[] {
  const findings: GitHubFinding[] = []
  const lines = content.split("\n")

  for (const line of lines) {
    const pkgMatch = line.match(/^([a-zA-Z0-9_-]+)/)
    if (pkgMatch) {
      const name = pkgMatch[1]!
      const malicious = maliciousPackages.find(
        (m) => m.name.toLowerCase() === name.toLowerCase()
      )
      if (malicious) {
        findings.push({
          severity: malicious.severity as GitHubFinding["severity"],
          type: "SUSPICIOUS_DEPENDENCY",
          file: filePath,
          package: name,
          description: `Known malicious Python package: ${name}`,
        })
      }
    }
  }

  return findings
}

// ─── Obfuscation detection ────────────────────────────────────────────────────

/**
 * Built-in obfuscation checks and their data-driven twins in
 * flagrix-detection-rules (rules/github/obfuscation.yaml). When the loaded
 * signatures ship a rule, the rule owns the signal and the built-in check is
 * skipped — otherwise the same base64 blob (etc.) is flagged twice and the
 * double-counted weight inflates the risk score. The built-ins remain as the
 * fallback for signature sets that lack these rules.
 */
const BUILTIN_OBFUSCATION_RULE_IDS = {
  base64: "OBF_BASE64_HEAVY",
  hex: "OBF_HEX_STRINGS",
  eval: "OBF_EVAL",
  newFunction: "OBF_NEW_FUNCTION",
  timerString: "OBF_SETTIMEOUT_STRING",
  longLine: "OBF_LONG_LINE"
} as const

function detectObfuscation(
  content: string,
  filePath: string,
  coveredRuleIds: ReadonlySet<string> = new Set()
): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  if (isTestFile(filePath)) return findings

  // Heavy Base64 usage
  const base64Matches = coveredRuleIds.has(BUILTIN_OBFUSCATION_RULE_IDS.base64)
    ? null
    : content.match(/[A-Za-z0-9+/]{50,}={0,2}/g)
  if (base64Matches && base64Matches.length > 5) {
    const snippet =
      base64Matches.slice(0, 3).join("\n") + (base64Matches.length > 3 ? "\n... and more" : "")
    findings.push({
      severity: "medium",
      type: "OBFUSCATED_CODE",
      file: filePath,
      description: "Heavy Base64 encoding detected (possible data exfiltration)",
      codeSnippet: snippet,
      codeExplanation:
        "🔓 Multiple Base64-encoded strings found. Base64 is commonly used to hide malicious payloads, URLs, or commands from code reviewers.",
    })
  }

  // Hex-encoded strings
  const hexMatches = coveredRuleIds.has(BUILTIN_OBFUSCATION_RULE_IDS.hex)
    ? null
    : content.match(/\\x[0-9a-fA-F]{2}/g)
  if (hexMatches && hexMatches.length > 20) {
    findings.push({
      severity: "medium",
      type: "OBFUSCATED_CODE",
      file: filePath,
      description: "Extensive hex-encoded strings detected",
      codeSnippet: hexMatches.slice(0, 15).join("") + "...",
      codeExplanation:
        "🔤 Hex-encoded strings detected. This obfuscation technique hides the actual string content, often used to conceal malicious URLs or commands.",
    })
  }

  // eval/Function constructor abuse
  const evalPatterns = [
    // Non-empty argument required: bare "eval()" appears in prose/docs.
    { pattern: /eval\s*\(\s*[^)\s][^)]{0,200}\)/gi, name: "eval", ruleId: BUILTIN_OBFUSCATION_RULE_IDS.eval },
    { pattern: /new\s+Function\s*\([^)]{0,200}\)/gi, name: "Function constructor", ruleId: BUILTIN_OBFUSCATION_RULE_IDS.newFunction },
    { pattern: /setTimeout\s*\(\s*["'`][^"'`]{0,200}["'`]/gi, name: "setTimeout with string", ruleId: BUILTIN_OBFUSCATION_RULE_IDS.timerString },
    { pattern: /setInterval\s*\(\s*["'`][^"'`]{0,200}["'`]/gi, name: "setInterval with string", ruleId: BUILTIN_OBFUSCATION_RULE_IDS.timerString },
  ].filter(({ ruleId }) => !coveredRuleIds.has(ruleId))

  for (const { pattern, name } of evalPatterns) {
    const matches = content.match(pattern)
    if (matches && matches.length > 0) {
      const snippet = matches[0]!
      findings.push({
        severity: "high",
        type: "OBFUSCATED_CODE",
        file: filePath,
        description: `Dynamic code execution pattern detected (${name})`,
        codeSnippet: snippet.length > 200 ? snippet.substring(0, 200) + "..." : snippet,
        codeExplanation: explainSuspiciousCode(snippet, "OBFUSCATED_CODE"),
      })
      break
    }
  }

  // Suspiciously long lines (hidden code attack)
  const hiddenCodePatterns = [
    /eval\s*\(/i,
    /exec\s*\(/i,
    /fetch\s*\(/i,
    /XMLHttpRequest/i,
    /\$\(.+\)\s*\(/,
    /window\.location\s*=/i,
    /document\.write\s*\(/i,
    /\.innerHTML\s*=/i,
    /child_process/i,
    /require\s*\(\s*['"]fs['"]\s*\)/,
    /atob\s*\(/i,
    /fromCharCode/i,
  ]

  const lines = coveredRuleIds.has(BUILTIN_OBFUSCATION_RULE_IDS.longLine)
    ? []
    : content.split("\n")
  const suspiciousLines: Array<{ lineNum: number; length: number; hasMaliciousPattern: boolean }> = []

  lines.forEach((line, index) => {
    if (line.length > 5000) {
      const hasMaliciousPattern = hiddenCodePatterns.some((pattern) => pattern.test(line))
      suspiciousLines.push({ lineNum: index + 1, length: line.length, hasMaliciousPattern })
    }
  })

  if (suspiciousLines.length > 0) {
    const maxLength = Math.max(...suspiciousLines.map((l) => l.length))
    const linesWithMaliciousCode = suspiciousLines.filter((l) => l.hasMaliciousPattern)
    const lineDetails = suspiciousLines
      .slice(0, 3)
      .map(
        (l) =>
          `Line ${l.lineNum} (${l.length.toLocaleString()} chars${l.hasMaliciousPattern ? ", contains suspicious code" : ""})`
      )
      .join(", ")

    const severity = linesWithMaliciousCode.length > 0 ? "critical" : "high"
    const firstLine = lines[suspiciousLines[0]!.lineNum - 1]!
    const codeSnippet = extractCodeSnippet(firstLine)
    const codeExplanation = explainSuspiciousCode(firstLine, "OBFUSCATED_CODE")

    findings.push({
      severity,
      type: "OBFUSCATED_CODE",
      file: filePath,
      line: suspiciousLines[0]!.lineNum,
      description: `Extremely long line detected (${maxLength.toLocaleString()} characters). ${linesWithMaliciousCode.length > 0 ? "Contains suspicious code patterns like eval/exec/fetch. " : ""}Malicious code may be hidden far to the right. Affected: ${lineDetails}`,
      codeSnippet,
      codeExplanation,
    })
  }

  return findings
}

function explainSuspiciousCode(code: string, type: string): string {
  const explanations: string[] = []

  if (/eval\s*\(/i.test(code)) explanations.push("⚠️ Uses eval() to execute dynamic code - can run arbitrary malicious commands")
  if (/exec\s*\(/i.test(code)) explanations.push("⚠️ Executes system commands - can run shell scripts and steal data")
  if (/child_process/i.test(code)) explanations.push("⚠️ Spawns child processes - can execute arbitrary programs on your system")
  if (/atob\s*\(/i.test(code)) explanations.push("🔓 Decodes Base64 data - often used to hide malicious payloads")
  if (/fromCharCode/i.test(code)) explanations.push("🔤 Constructs strings from character codes - obfuscation technique to hide malicious code")
  if (/fetch\s*\(|XMLHttpRequest|axios\./i.test(code)) explanations.push("🌐 Makes network requests - could send your data to attacker's server")
  if (/document\.write|\.innerHTML\s*=/i.test(code)) explanations.push("📝 Injects HTML/scripts into page - can steal credentials or modify the page")
  if (/window\.location\s*=/i.test(code)) explanations.push("🔀 Redirects browser - can send you to phishing sites")
  if (/require\s*\(\s*['"]fs['"]\s*\)/i.test(code)) explanations.push("📁 Accesses file system - can read/write/delete files on your computer")
  if (/process\.env/i.test(code)) explanations.push("🔐 Accesses environment variables - can steal API keys and credentials")
  if (/crypto|password|token|api[_-]?key/i.test(code)) explanations.push("🔑 References sensitive data - may be attempting to steal credentials")
  if (/discord\.gg|pastebin\.com|bit\.ly|tinyurl/i.test(code)) explanations.push("🔗 Contains suspicious URLs - likely data exfiltration endpoint")
  if (type === "OBFUSCATED_CODE" && code.length > 1000) explanations.push("📏 Extremely long/complex code - intentionally obfuscated to hide malicious intent")

  return explanations.length > 0
    ? explanations.join("\n")
    : "This code contains suspicious patterns that may indicate malicious intent. Review carefully before running."
}

function extractCodeSnippet(line: string, maxLength = 500): string {
  if (line.length > maxLength) {
    const patterns = [
      /eval\s*\([^)]{0,200}\)/i,
      /exec\s*\([^)]{0,200}\)/i,
      /atob\s*\([^)]{0,200}\)/i,
      /fetch\s*\([^)]{0,200}\)/i,
      /require\s*\(\s*['"][^'"]+['"]\s*\)/i,
    ]

    for (const pattern of patterns) {
      const match = line.match(pattern)
      if (match) {
        const matchStart = match.index || 0
        const start = Math.max(0, matchStart - 100)
        const end = Math.min(line.length, matchStart + match[0].length + 100)
        const snippet = line.substring(start, end)
        return (start > 0 ? "..." : "") + snippet + (end < line.length ? "..." : "")
      }
    }

    return (
      line.substring(0, 250) +
      " ... [" +
      (line.length - 500).toLocaleString() +
      " chars hidden] ... " +
      line.substring(line.length - 250)
    )
  }

  return line
}

// ─── Non-English comment detection ───────────────────────────────────────────

const ENGLISH_CODES = ["eng", "sco"]
const MIN_WORD_LENGTH = 5
// Thresholds are intentionally conservative: language detection on short code
// comments is noisy, so we only flag repos with a substantial volume of comments
// that are clearly (not marginally) non-English, to avoid false-flagging
// legitimate English or internationally-commented projects.
const MIN_WORDS_TO_ANALYZE = 30
const NON_ENGLISH_THRESHOLD = 0.25
const MIN_NON_ENGLISH_WORDS = 8
// Only run language detection on comments long enough for franc to be reliable.
const MIN_COMMENT_LEN_FOR_DETECTION = 40

const COMMENT_PATTERNS: Record<string, RegExp[]> = {
  javascript: [/\/\/(.*)$/gm, /\/\*[\s\S]*?\*\//g],
  typescript: [/\/\/(.*)$/gm, /\/\*[\s\S]*?\*\//g],
  python: [/#(.*)$/gm, /"""[\s\S]*?"""/g, /'''[\s\S]*?'''/g],
  shell: [/#(.*)$/gm],
  powershell: [/#(.*)$/gm, /<#[\s\S]*?#>/g],
  batch: [/(?:^|\n)\s*REM\s+(.*)$/gim, /(?:^|\n)\s*::(.*)$/gm],
}

interface LanguageAnalysis {
  totalComments: number
  totalWords: number
  englishWords: number
  nonEnglishWords: number
  nonEnglishPercentage: number
  detectedLanguages: Map<string, number>
  filesWithNonEnglish: Map<string, number>
}

function extractComments(content: string, fileExtension: string): string[] {
  const comments: string[] = []
  let language = ""

  if ([".js", ".jsx", ".mjs", ".cjs"].includes(fileExtension)) language = "javascript"
  else if ([".ts", ".tsx"].includes(fileExtension)) language = "typescript"
  else if ([".py"].includes(fileExtension)) language = "python"
  else if ([".sh", ".bash"].includes(fileExtension)) language = "shell"
  else if ([".ps1"].includes(fileExtension)) language = "powershell"
  else if ([".bat", ".cmd"].includes(fileExtension)) language = "batch"

  if (!language || !COMMENT_PATTERNS[language]) return comments

  for (const pattern of COMMENT_PATTERNS[language]!) {
    const matches = content.match(pattern)
    if (matches) comments.push(...matches)
  }

  return comments
    .map((comment) =>
      comment
        .replace(/^\/\/\s*/, "")
        .replace(/^\/\*\s*|\s*\*\/$/g, "")
        .replace(/^#\s*/, "")
        .replace(/^<#\s*|\s*#>$/g, "")
        .replace(/^"""\s*|\s*"""$/g, "")
        .replace(/^'''\s*|\s*'''$/g, "")
        .replace(/^REM\s+/i, "")
        .replace(/^::\s*/, "")
        .trim()
    )
    .filter((comment) => comment.length > 0)
}

function analyzeCommentLanguages(
  comments: string[],
  filePath: string,
  fileAnalysis: LanguageAnalysis
): void {
  let fileNonEnglishWords = 0

  for (const comment of comments) {
    const words = comment.split(/\s+/).filter((word) => word.length >= MIN_WORD_LENGTH)
    fileAnalysis.totalWords += words.length
    fileAnalysis.totalComments += 1

    if (comment.length >= MIN_COMMENT_LEN_FOR_DETECTION) {
      const detectedLang = franc(comment)

      if (detectedLang && detectedLang !== "und") {
        if (ENGLISH_CODES.includes(detectedLang)) {
          fileAnalysis.englishWords += words.length
        } else {
          fileAnalysis.nonEnglishWords += words.length
          fileNonEnglishWords += words.length
          const currentCount = fileAnalysis.detectedLanguages.get(detectedLang) || 0
          fileAnalysis.detectedLanguages.set(detectedLang, currentCount + words.length)
        }
      } else {
        fileAnalysis.englishWords += words.length
      }
    } else {
      fileAnalysis.englishWords += words.length
    }
  }

  if (fileNonEnglishWords > 0) {
    fileAnalysis.filesWithNonEnglish.set(filePath, fileNonEnglishWords)
  }
}

async function detectNonEnglishComments(
  files: Array<{ path: string; content: string }>,
  _repo: GitHubRepoInfo
): Promise<GitHubFinding[]> {
  const findings: GitHubFinding[] = []

  const analysis: LanguageAnalysis = {
    totalComments: 0,
    totalWords: 0,
    englishWords: 0,
    nonEnglishWords: 0,
    nonEnglishPercentage: 0,
    detectedLanguages: new Map(),
    filesWithNonEnglish: new Map(),
  }

  for (const file of files) {
    const ext = file.path.substring(file.path.lastIndexOf("."))
    const comments = extractComments(file.content, ext)
    if (comments.length > 0) {
      analyzeCommentLanguages(comments, file.path, analysis)
    }
  }

  if (analysis.totalWords >= MIN_WORDS_TO_ANALYZE) {
    analysis.nonEnglishPercentage = analysis.nonEnglishWords / analysis.totalWords

    if (
      analysis.nonEnglishPercentage >= NON_ENGLISH_THRESHOLD &&
      analysis.nonEnglishWords >= MIN_NON_ENGLISH_WORDS
    ) {
      const topFiles = Array.from(analysis.filesWithNonEnglish.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([path]) => path)

      const langBreakdown = Array.from(analysis.detectedLanguages.entries())
        .map(([code, count]) => `${getLanguageName(code)}: ${count} words`)
        .join(", ")

      let severity: "high" | "medium" = "medium"
      let description = ""

      if (analysis.englishWords === 0) {
        severity = "high"
        description = `100% of code comments are in non-English languages (${langBreakdown}). Repository contains NO English comments, which is highly suspicious for projects claiming international scope.`
      } else {
        const percentage = Math.round(analysis.nonEnglishPercentage * 100)
        description = `${percentage}% of code comments are in non-English languages (${langBreakdown}). This may indicate deceptive code where malicious intent is hidden in foreign language comments.`
      }

      findings.push({ severity, type: "NON_ENGLISH_COMMENTS", description, files: topFiles })
    }
  }

  return findings
}

function getLanguageName(code: string): string {
  const names: Record<string, string> = {
    tur: "Turkish", rus: "Russian", zho: "Chinese", jpn: "Japanese", kor: "Korean",
    ara: "Arabic", deu: "German", fra: "French", spa: "Spanish", por: "Portuguese",
    ita: "Italian", nld: "Dutch", pol: "Polish", ukr: "Ukrainian", vie: "Vietnamese",
    tha: "Thai", ind: "Indonesian", heb: "Hebrew", hin: "Hindi",
  }
  return names[code] || code
}

// ─── Comprehensive security checks ───────────────────────────────────────────

function detectSuspiciousPackageNames(content: string, filePath: string): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  try {
    const pkg = JSON.parse(content)
    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
      ...pkg.peerDependencies,
      ...pkg.optionalDependencies,
    }

    const suspiciousPackages: string[] = []

    for (const packageName in allDeps) {
      if (/^[a-z0-9]{6,8}$/.test(packageName) && !/[aeiou]{2}/.test(packageName)) {
        suspiciousPackages.push(`${packageName} (random-looking name)`)
      }
      if (/(.)\1{4,}/.test(packageName)) {
        suspiciousPackages.push(`${packageName} (repeated characters)`)
      }
      if (packageName.length === 1) {
        suspiciousPackages.push(`${packageName} (single character)`)
      }
      if (/(test|temp|tmp|debug|hack|crack|backdoor|shell|payload)[_-]?[0-9]*$/.test(packageName)) {
        suspiciousPackages.push(`${packageName} (suspicious name pattern)`)
      }
    }

    if (suspiciousPackages.length > 0) {
      findings.push({
        severity: "medium",
        type: "SUSPICIOUS_PACKAGE_NAME",
        file: filePath,
        description: `Suspicious package names detected: ${suspiciousPackages.slice(0, 5).join(", ")}${suspiciousPackages.length > 5 ? ` and ${suspiciousPackages.length - 5} more` : ""}`,
        codeExplanation:
          "📦 These package names don't follow typical naming conventions and may be malicious packages attempting to hide their purpose.",
      })
    }
  } catch {
    // Not valid JSON
  }

  return findings
}

function detectHardcodedSecrets(
  content: string,
  filePath: string,
  coveredRuleIds: ReadonlySet<string> = new Set()
): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  if (isTestFile(filePath)) return findings

  const secretPatterns = [
    { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"]([^'"]{20,})['"]/gi, type: "API Key", severity: "critical" as const, ruleId: "HARDCODED_API_KEY" },
    { pattern: /(?:secret[_-]?key|secret)\s*[:=]\s*['"]([^'"]{20,})['"]/gi, type: "Secret Key", severity: "critical" as const, ruleId: "HARDCODED_API_KEY" },
    { pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{8,})['"]/gi, type: "Password", severity: "critical" as const, ruleId: null },
    { pattern: /(?:token|auth[_-]?token)\s*[:=]\s*['"]([^'"]{20,})['"]/gi, type: "Auth Token", severity: "critical" as const, ruleId: "HARDCODED_API_KEY" },
    { pattern: /(?:private[_-]?key|privatekey)\s*[:=]\s*['"]([^'"]{20,})['"]/gi, type: "Private Key", severity: "critical" as const, ruleId: "HARDCODED_API_KEY" },
    { pattern: /AKIA[0-9A-Z]{16}/g, type: "AWS Access Key", severity: "critical" as const, ruleId: "HARDCODED_AWS_KEY" },
    { pattern: /ghp_[a-zA-Z0-9]{36}/g, type: "GitHub Personal Access Token", severity: "critical" as const, ruleId: "HARDCODED_GITHUB_TOKEN" },
    { pattern: /gho_[a-zA-Z0-9]{36}/g, type: "GitHub OAuth Token", severity: "critical" as const, ruleId: "HARDCODED_GITHUB_TOKEN" },
    { pattern: /sk_live_[a-zA-Z0-9]{24,}/g, type: "Stripe Live Key", severity: "critical" as const, ruleId: "HARDCODED_STRIPE_KEY" },
    { pattern: /(?:mongodb|mongo)[+:\/\/]{0,6}[^@\s]+:[^@\s]+@/gi, type: "MongoDB Connection String", severity: "high" as const, ruleId: "HARDCODED_DB_CONNECTION" },
    { pattern: /postgres:\/\/[^@\s]+:[^@\s]+@/gi, type: "PostgreSQL Connection String", severity: "high" as const, ruleId: "HARDCODED_DB_CONNECTION" },
  ].filter(({ ruleId }) => !ruleId || !coveredRuleIds.has(ruleId))

  const foundSecrets: Array<{ type: string; match: string; severity: "critical" | "high" }> = []
  const matchedRegexes: RegExp[] = []

  for (const { pattern, type, severity } of secretPatterns) {
    const matches = content.match(pattern)
    if (matches && matches.length > 0) {
      foundSecrets.push({ type, match: matches[0].substring(0, 50) + "...", severity })
      matchedRegexes.push(pattern)
    }
  }

  if (foundSecrets.length > 0) {
    const highestSeverity = foundSecrets.some((s) => s.severity === "critical") ? "critical" : "high"
    findings.push({
      severity: highestSeverity,
      type: "HARDCODED_SECRETS",
      file: filePath,
      description: `Hardcoded credentials detected: ${foundSecrets.map((s) => s.type).join(", ")}`,
      evidence: collectEvidence(content, matchedRegexes),
      codeSnippet: foundSecrets[0]!.match,
      codeExplanation:
        "🔐 Hardcoded credentials expose your application to unauthorized access. API keys, passwords, and tokens should NEVER be committed to source code. Use environment variables or secure credential management instead.",
    })
  }

  return findings
}

function detectNetworkPatterns(
  content: string,
  filePath: string,
  coveredRuleIds: ReadonlySet<string> = new Set()
): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  if (isTestFile(filePath)) return findings

  const suspiciousPatterns = [
    // Valid public IPv4 only: each octet bounded 0–255, not embedded in a longer
    // dotted/number sequence (avoids flagging version strings like "1.2.3.4.5" or
    // impossible IPs like "999.999.999.999"), and excluding private/link-local ranges.
    { pattern: /(?:https?:\/\/)?(?<![\d.])(?!(?:127\.|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.))(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d.])(?::\d{1,5})?/g, type: "Hardcoded IP Address", severity: "high" as const },
    { pattern: /https?:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[a-zA-Z0-9_-]+/gi, type: "Discord Webhook", severity: "critical" as const, ruleId: "NETWORK_DISCORD_WEBHOOK" },
    { pattern: /\d{8,10}:[a-zA-Z0-9_-]{35}/g, type: "Telegram Bot Token", severity: "high" as const, ruleId: "NETWORK_TELEGRAM_TOKEN" },
    { pattern: /(?:pastebin\.com|hastebin\.com|paste\.ee)\/[a-zA-Z0-9]+/gi, type: "Pastebin URL", severity: "medium" as const, ruleId: "NETWORK_PASTEBIN" },
    { pattern: /(?:bit\.ly|tinyurl\.com|t\.co)\/[a-zA-Z0-9]+/gi, type: "URL Shortener", severity: "medium" as const, ruleId: "NETWORK_URL_SHORTENER" },
    { pattern: /https?:\/\/[a-zA-Z0-9-]+\.(?:tk|ml|ga|cf|gq|onion|xyz)(?:\/|$)/gi, type: "Suspicious Domain TLD", severity: "high" as const, ruleId: "NETWORK_SUSPICIOUS_TLD" },
    { pattern: /https?:\/\/[a-zA-Z0-9-]+\.ngrok\.io/gi, type: "Ngrok Tunnel", severity: "medium" as const, ruleId: "NETWORK_NGROK_TUNNEL" },
  ].filter((p) => !("ruleId" in p) || !coveredRuleIds.has((p as { ruleId: string }).ruleId))

  for (const { pattern, type, severity } of suspiciousPatterns) {
    const matches = content.match(pattern)
    if (matches && matches.length > 0) {
      const validMatches = matches.filter((m) => {
        const lines = content.split("\n")
        const lineWithMatch = lines.find((l) => l.includes(m))
        return lineWithMatch && !lineWithMatch.trim().startsWith("//") && !lineWithMatch.trim().startsWith("#")
      })

      if (validMatches.length > 0) {
        findings.push({
          severity,
          type: "NETWORK_COMMUNICATION",
          file: filePath,
          description: `Suspicious network communication detected: ${type} (${validMatches.length} occurrence${validMatches.length > 1 ? "s" : ""})`,
          evidence: collectEvidence(content, pattern),
          codeSnippet: validMatches.slice(0, 3).join("\n"),
          codeExplanation: `🌐 ${type} detected. ${
            type === "Discord Webhook"
              ? "Discord webhooks are commonly used for data exfiltration - stolen data is sent to attacker's Discord server."
              : type === "Hardcoded IP Address"
              ? "Hardcoded IP addresses bypass DNS and make the code harder to audit. Often used to connect to command & control servers."
              : "This URL may be used for data exfiltration or malware distribution."
          }`,
        })
      }
    }
  }

  return findings
}

function detectCryptoMining(
  content: string,
  filePath: string,
  coveredRuleIds: ReadonlySet<string> = new Set()
): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  // The CRYPTO_MINER rule in detection-rules owns this signal when loaded.
  if (coveredRuleIds.has("CRYPTO_MINER")) return findings

  const miningPatterns = [
    /coinhive|coin-hive|crypto-loot|cryptoloot|jsecoin/gi,
    /stratum\+tcp|stratum\.|\bpool\./gi,
    /monero|xmr|cryptonight/gi,
    /(?:miner|mining)[\w]*\.(?:start|run|init)/gi,
    /\.(?:setNumThreads|setThrottle|getHashesPerSecond)/gi,
  ]

  const miningIndicators: string[] = []
  const matches: string[] = []

  for (const pattern of miningPatterns) {
    const found = content.match(pattern)
    if (found) {
      miningIndicators.push(...found)
      matches.push(...found)
    }
  }

  if (/while\s*\(\s*true\s*\)[\s\S]{0,200}(?:Math\.|crypto|hash)/i.test(content)) {
    miningIndicators.push("Infinite loop with crypto/math operations")
  }

  if (miningIndicators.length > 0) {
    findings.push({
      severity: "critical",
      type: "CRYPTO_MINER",
      file: filePath,
      description: `Cryptocurrency mining code detected: ${miningIndicators.slice(0, 3).join(", ")}`,
      evidence: collectEvidence(content, miningPatterns),
      codeSnippet: matches.slice(0, 2).join("\n"),
      codeExplanation:
        "⛏️ Cryptocurrency miners use your CPU/GPU to mine coins for attackers. This drastically slows down your system and increases electricity costs. Miners are often bundled with legitimate software.",
    })
  }

  return findings
}

function detectDataExfiltration(
  content: string,
  filePath: string,
  coveredRuleIds: ReadonlySet<string> = new Set()
): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  if (isTestFile(filePath)) return findings

  const exfiltrationPatterns = [
    { pattern: /navigator\.clipboard\.read(?:Text)?\s*\(/gi, type: "Clipboard Access", severity: "high" as const, ruleId: "EXFIL_CLIPBOARD" },
    { pattern: /localStorage\.getItem|sessionStorage\.getItem/gi, type: "Storage Access", severity: "medium" as const, ruleId: null },
    { pattern: /document\.cookie/gi, type: "Cookie Access", severity: "high" as const, ruleId: "EXFIL_COOKIE" },
    { pattern: /(?:addEventListener|on)\s*\(\s*['"](?:keydown|keypress|keyup)['"]/gi, type: "Keylogger Pattern", severity: "critical" as const, ruleId: "EXFIL_KEYLOGGER" },
    { pattern: /(?:input|password|email)[\w-]*\.value/gi, type: "Form Data Access", severity: "medium" as const, ruleId: null },
    { pattern: /new\s+FormData\s*\([^)]*\)[\s\S]{0,100}(?:fetch|axios|XMLHttpRequest)/gi, type: "Form Data Transmission", severity: "high" as const, ruleId: null },
  ].filter(({ ruleId }) => !ruleId || !coveredRuleIds.has(ruleId))

  const detectedPatterns: string[] = []
  const matchedRegexes: RegExp[] = []
  let highestSeverity: "critical" | "high" | "medium" = "medium"

  for (const { pattern, type, severity } of exfiltrationPatterns) {
    if (pattern.test(content)) {
      detectedPatterns.push(type)
      matchedRegexes.push(pattern)
      if (severity === "critical" || (severity === "high" && highestSeverity !== "critical")) {
        highestSeverity = severity
      }
    }
  }

  if (detectedPatterns.length > 0) {
    findings.push({
      severity: highestSeverity,
      type: "DATA_EXFILTRATION",
      file: filePath,
      description: `Data exfiltration patterns detected: ${detectedPatterns.join(", ")}`,
      evidence: collectEvidence(content, matchedRegexes),
      codeExplanation:
        "🕵️ This code accesses sensitive user data. Combined with network requests, this could indicate credential theft or data exfiltration to attacker's servers.",
    })
  }

  return findings
}

function detectBackdoors(
  content: string,
  filePath: string,
  coveredRuleIds: ReadonlySet<string> = new Set()
): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  const backdoorPatterns = [
    { pattern: /eval\s*\(\s*(?:request|req)(?:\.|\.body|\.query)/gi, type: "Remote Code Execution Endpoint", severity: "critical" as const, ruleId: "BACKDOOR_RCE_ENDPOINT" },
    { pattern: /exec\s*\(\s*(?:request|req)(?:\.|\.body|\.query)/gi, type: "Command Injection Endpoint", severity: "critical" as const, ruleId: "BACKDOOR_RCE_ENDPOINT" },
    { pattern: /require\s*\(\s*(?:request|req)(?:\.|\.body|\.query)/gi, type: "Dynamic Require", severity: "critical" as const, ruleId: "BACKDOOR_DYNAMIC_REQUIRE" },
    { pattern: /new\s+Function\s*\([^)]*(?:request|req)/gi, type: "Dynamic Function from Request", severity: "critical" as const, ruleId: null },
    { pattern: /(?:admin|debug|backdoor|shell)[\w]*\s*[:=]\s*(?:true|1|"[^"]*")\s*(?:\/\/|#)?\s*(?:TODO|FIXME|HACK)?/gi, type: "Debug/Admin Flag", severity: "high" as const, ruleId: null },
    { pattern: /(?:password|auth)\s*(?:===?|==)\s*['"][^'"]{0,20}['"]\s*\)/gi, type: "Hardcoded Auth Bypass", severity: "critical" as const, ruleId: "BACKDOOR_HARDCODED_AUTH" },
  ].filter(({ ruleId }) => !ruleId || !coveredRuleIds.has(ruleId))

  for (const { pattern, type, severity } of backdoorPatterns) {
    const matches = content.match(pattern)
    if (matches) {
      findings.push({
        severity,
        type: "BACKDOOR",
        file: filePath,
        description: `Backdoor detected: ${type}`,
        codeSnippet: matches[0],
        codeExplanation: `🚪 ${type} - This code allows remote attackers to execute arbitrary commands or bypass authentication. This is a CRITICAL security vulnerability.`,
        evidence: collectEvidence(content, pattern),
      })
    }
  }

  return findings
}

function detectSupplyChainRisks(content: string, filePath: string): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  if (!filePath.endsWith("package.json")) return findings

  try {
    const pkg = JSON.parse(content)
    const scripts = pkg.scripts || {}
    const suspiciousScripts: string[] = []

    for (const [scriptName, scriptContent] of Object.entries(scripts)) {
      if (typeof scriptContent === "string") {
        if (/(?:curl|wget|fetch)[\s\S]*\.(?:exe|sh|py|bin|dmg|pkg|msi|dll)/i.test(scriptContent)) {
          suspiciousScripts.push(`${scriptName}: Downloads executable files`)
        }
        if (/(?:cd|pushd)[\s\S]*node_modules/i.test(scriptContent)) {
          suspiciousScripts.push(`${scriptName}: Modifies node_modules`)
        }
        if (/(?:>|>>|tee)[\s\S]*(?:package\.json|index\.js|\.\.\/)/i.test(scriptContent)) {
          suspiciousScripts.push(`${scriptName}: Self-modifying script`)
        }
        if (/(?:preinstall|postinstall|install)/.test(scriptName) && /(?:curl|wget|fetch|http|https)/i.test(scriptContent)) {
          suspiciousScripts.push(`${scriptName}: Network access during installation`)
        }
      }
    }

    if (suspiciousScripts.length > 0) {
      findings.push({
        severity: "critical",
        type: "SUPPLY_CHAIN_RISK",
        file: filePath,
        description: `Supply chain attack patterns in package scripts: ${suspiciousScripts.join("; ")}`,
        codeSnippet: JSON.stringify(scripts, null, 2).substring(0, 300) + "...",
        codeExplanation:
          "📦 Supply chain attacks inject malicious code through package installation scripts. These scripts run automatically when you install the package and can compromise your entire system.",
      })
    }
  } catch {
    // Not valid JSON
  }

  return findings
}

function detectSuspiciousFileAccess(
  content: string,
  filePath: string,
  coveredRuleIds: ReadonlySet<string> = new Set()
): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  if (isTestFile(filePath)) return findings

  const fileAccessPatterns = [
    { pattern: /(?:fs\.read|readFileSync|readFile)\s*\([^)]*(?:\.ssh|\.aws|\.gnupg|\.docker|id_rsa|credentials)/gi, type: "SSH/AWS Credentials Access", severity: "critical" as const, ruleId: "FILE_ACCESS_CREDENTIALS" },
    { pattern: /(?:fs\.read|readFileSync|readFile)\s*\([^)]*(?:etc\/passwd|etc\/shadow|\.bash_history|\.zsh_history)/gi, type: "System File Access", severity: "critical" as const, ruleId: "FILE_ACCESS_SYSTEM" },
    { pattern: /(?:fs\.read|readFileSync|readFile)\s*\([^)]*(?:Chrome|Firefox|Safari|Edge)[\w\s/\\]*(?:Cookies|Login|History)/gi, type: "Browser Data Access", severity: "critical" as const, ruleId: "FILE_ACCESS_BROWSER_DATA" },
    { pattern: /(?:fs\.write|writeFileSync|writeFile)\s*\([^)]*(?:\/etc|\/sys|\/bin|C:\\\\Windows)/gi, type: "System Directory Write", severity: "critical" as const, ruleId: null },
    { pattern: /(?:fs\.unlink|unlinkSync|rmSync|rm\s+-rf)/gi, type: "File Deletion", severity: "medium" as const, ruleId: null },
  ].filter(({ ruleId }) => !ruleId || !coveredRuleIds.has(ruleId))

  for (const { pattern, type, severity } of fileAccessPatterns) {
    const matches = content.match(pattern)
    if (matches) {
      findings.push({
        severity,
        type: "SUSPICIOUS_FILE_ACCESS",
        file: filePath,
        description: `Suspicious file access detected: ${type}`,
        codeSnippet: matches[0],
        codeExplanation: `📁 ${type} - This code attempts to access or modify sensitive system files. This could be credential theft, system compromise, or destructive malware.`,
        evidence: collectEvidence(content, pattern),
      })
    }
  }

  return findings
}

async function detectCodeIntegrityIssues(
  files: Array<{ path: string; content: string }>,
  allPaths: string[],
  _repo: GitHubRepoInfo
): Promise<GitHubFinding[]> {
  const findings: GitHubFinding[] = []

  for (const file of files) {
    if (file.path.endsWith(".min.js") || file.path.endsWith(".min.css")) continue

    const lines = file.content.split("\n")
    const longLines = lines.filter((l) => l.length > 500)
    const avgLineLength = lines.reduce((sum, l) => sum + l.length, 0) / lines.length

    if (longLines.length > 3 && avgLineLength > 200) {
      const shortVars = (file.content.match(/\b[a-z]\b/g) || []).length
      const totalVars = (file.content.match(/\b[a-z][a-zA-Z0-9_]*\b/g) || []).length

      if (shortVars / totalVars > 0.3) {
        findings.push({
          severity: "medium",
          type: "CODE_INTEGRITY_ISSUE",
          file: file.path,
          description: "Minified/obfuscated code detected in source repository",
          codeExplanation:
            "🔍 Source code appears to be minified or obfuscated. Legitimate projects typically commit readable source code, not minified versions. This makes code review difficult and may hide malicious intent.",
        })
      }
    }
  }

  // Presence checks run against the full tree — LICENSE/README aren't in the
  // scanned-source list (wrong extension) and would otherwise always "miss".
  const basename = (p: string) => p.split("/").pop() ?? p
  const hasLicense = allPaths.some((p) => /^(LICENSE|COPYING)/i.test(basename(p)))
  if (!hasLicense && allPaths.length > 5) {
    findings.push({
      severity: "low",
      type: "CODE_INTEGRITY_ISSUE",
      description: "No LICENSE file found in repository",
      codeExplanation:
        "📄 Missing license file. Legitimate open-source projects typically include a license. Absence may indicate a quickly assembled malicious repository.",
    })
  }

  const hasReadme = allPaths.some((p) => /^README/i.test(basename(p)))
  if (!hasReadme && allPaths.length > 5) {
    findings.push({
      severity: "low",
      type: "CODE_INTEGRITY_ISSUE",
      description: "No README file found in repository",
      codeExplanation:
        "📝 Missing README. Legitimate projects typically have documentation. Absence may indicate a hastily created malicious repository.",
    })
  }

  return findings
}

function detectSocialEngineering(content: string, filePath: string): GitHubFinding[] {
  const findings: GitHubFinding[] = []

  if (!/README/i.test(filePath)) return findings

  const socialEngineeringPatterns = [
    { pattern: /(?:urgent|immediately|quick|fast|act now|limited time)/gi, type: "Urgency Language", severity: "medium" as const },
    { pattern: /(?:disable|turn off|bypass)[\s\w]*(?:antivirus|firewall|security|protection)/gi, type: "Security Bypass Instructions", severity: "high" as const },
    { pattern: /(?:admin|root|sudo)[\s\w]*(?:rights|privileges|access|permission)/gi, type: "Privilege Escalation Language", severity: "medium" as const },
    { pattern: /(?:100%|totally|completely|absolutely)[\s\w]*(?:safe|secure|trusted|legit)/gi, type: "Over-assurance Language", severity: "low" as const },
    { pattern: /(?:millions?|thousands?)[\s\w]*(?:downloads?|users?|stars?)/gi, type: "Fake Popularity Claims", severity: "low" as const },
  ]

  const detectedPatterns: string[] = []
  let highestSeverity: "high" | "medium" | "low" = "low"

  for (const { pattern, type, severity } of socialEngineeringPatterns) {
    if (pattern.test(content)) {
      detectedPatterns.push(type)
      if (severity === "high" || (severity === "medium" && highestSeverity === "low")) {
        highestSeverity = severity
      }
    }
  }

  if (detectedPatterns.length >= 2) {
    findings.push({
      severity: highestSeverity,
      type: "SOCIAL_ENGINEERING",
      file: filePath,
      description: `Social engineering tactics detected in README: ${detectedPatterns.join(", ")}`,
      codeExplanation:
        "🎣 README contains persuasive language designed to manipulate users. Scammers use urgency, fake credentials, and security bypass instructions to trick users into running malicious code.",
    })
  }

  return findings
}

// ─── Utilities ────────────────────────────────────────────────────────────────

async function getNpmWeeklyDownloads(packageName: string): Promise<number | null> {
  const cached = NPM_DOWNLOAD_CACHE.get(packageName)
  if (cached && Date.now() - cached.fetchedAt < NPM_CACHE_TTL_MS) {
    return cached.weeklyDownloads
  }
  try {
    const url = `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`
    const response = await fetch(url, { signal: AbortSignal.timeout(5000) })
    const weeklyDownloads = response.ok
      ? ((await response.json()) as { downloads: number }).downloads ?? 0
      : 0
    NPM_DOWNLOAD_CACHE.set(packageName, { weeklyDownloads, fetchedAt: Date.now() })
    return weeklyDownloads
  } catch {
    NPM_DOWNLOAD_CACHE.set(packageName, { weeklyDownloads: null, fetchedAt: Date.now() })
    return null
  }
}

function levenshteinDistance(a: string, b: string): number {
  const m = a.length, n = b.length
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  )
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i]![j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1]![j - 1]!
          : 1 + Math.min(dp[i - 1]![j - 1]!, dp[i - 1]![j]!, dp[i]![j - 1]!)
    }
  }
  return dp[m]![n]!
}

function checkTyposquat(packageName: string): string | null {
  const popularPackages = [
    "lodash", "express", "react", "axios", "moment", "webpack", "babel",
    "typescript", "eslint", "prettier", "jest", "mocha", "bcrypt", "crypto", "request",
  ]

  for (const popular of popularPackages) {
    if (packageName === popular) continue
    if (Math.abs(packageName.length - popular.length) > 3) continue
    if (levenshteinDistance(packageName, popular) <= 2) return popular
  }

  return null
}

function countDependencies(content: string): number {
  try {
    const pkg = JSON.parse(content)
    return (
      Object.keys(pkg.dependencies || {}).length +
      Object.keys(pkg.devDependencies || {}).length
    )
  } catch {
    return 0
  }
}

// Export internal helpers for testing
export { checkTyposquat, detectObfuscation, isTestFile }
