import type { FindingEvidence } from "../types/index.js"

const MAX_EVIDENCE_LINES = 3
const MAX_LINE_LENGTH = 160

/**
 * Locate the source lines a pattern matched, with 1-based line numbers, so
 * findings can show *where* the evidence lives (and consumers can deep-link
 * `#L<n>`). Best-effort: patterns that only match across line boundaries
 * yield no evidence — callers keep their `codeSnippet` as the fallback.
 */
export function collectEvidence(
  content: string,
  patterns: RegExp | RegExp[],
  max = MAX_EVIDENCE_LINES
): FindingEvidence[] {
  const list = (Array.isArray(patterns) ? patterns : [patterns]).map(
    // Fresh non-global copies: per-line .test() with a shared /g regex would
    // carry lastIndex across calls and silently skip matches.
    (p) => new RegExp(p.source, p.flags.replace(/g/g, ""))
  )

  const evidence: FindingEvidence[] = []
  const lines = content.split("\n")
  for (let i = 0; i < lines.length && evidence.length < max; i++) {
    const raw = lines[i]!
    if (!list.some((re) => re.test(raw))) continue
    const code = raw.trim()
    evidence.push({
      line: i + 1,
      code: code.length > MAX_LINE_LENGTH ? code.slice(0, MAX_LINE_LENGTH) + "…" : code
    })
  }
  return evidence
}
