/**
 * Masks the contents of JavaScript/TypeScript regex literals with spaces so
 * pattern detectors don't fire on them. A regex literal *describing* a
 * keylogger is inert data, not a keylogger — without this, any security
 * tool, linter, or tutorial repo scans as malicious (including this one).
 *
 * Masking (not stripping) preserves line/column positions, so evidence line
 * numbers stay correct. String literals and comments are left untouched:
 * strings can hold real payloads (base64 blobs, URLs) that must stay
 * scannable, and hiding behavior in a regex literal isn't possible — a regex
 * never executes anything.
 */

const REGEX_ALLOWED_AFTER_CHAR = new Set([..."=(:,[!&|?{};+*%^<>~"])
const REGEX_ALLOWED_AFTER_WORD = new Set(["return", "case", "typeof", "in", "of", "do", "void", "delete"])

export function maskRegexLiterals(content: string): string {
  return content.split("\n").map(maskLine).join("\n")
}

function maskLine(line: string): string {
  let out = ""
  let i = 0

  while (i < line.length) {
    const ch = line[i]!

    // String literals pass through verbatim — real payloads live in strings.
    if (ch === '"' || ch === "'" || ch === "`") {
      const end = stringEnd(line, i)
      out += line.slice(i, end)
      i = end
      continue
    }

    if (ch === "/" && line[i + 1] === "/") {
      out += line.slice(i) // line comment — keep (comment heuristics elsewhere)
      break
    }

    if (ch === "/" && regexCanStartAfter(out)) {
      const end = regexEnd(line, i)
      if (end !== -1) {
        out += " ".repeat(end - i)
        i = end
        continue
      }
    }

    out += ch
    i++
  }

  return out
}

/** A `/` starts a regex literal only in expression position (not division). */
function regexCanStartAfter(before: string): boolean {
  const trimmed = before.trimEnd()
  if (trimmed === "") return true
  if (REGEX_ALLOWED_AFTER_CHAR.has(trimmed.slice(-1)!)) return true
  const word = trimmed.match(/[A-Za-z_$][A-Za-z0-9_$]*$/)?.[0]
  return word !== undefined && REGEX_ALLOWED_AFTER_WORD.has(word)
}

/** End index (exclusive, incl. flags) of a regex literal starting at `start`, or -1. */
function regexEnd(line: string, start: number): number {
  let i = start + 1
  let inClass = false
  let body = 0

  for (; i < line.length; i++) {
    const ch = line[i]!
    if (ch === "\\") {
      i++
      body++
      continue
    }
    if (inClass) {
      if (ch === "]") inClass = false
    } else if (ch === "[") {
      inClass = true
    } else if (ch === "/") {
      if (body === 0) return -1 // `//` handled as comment; empty regex isn't one
      let end = i + 1
      while (end < line.length && /[a-z]/i.test(line[end]!)) end++
      return end
    }
    body++
  }
  return -1 // unterminated — treat as division/other, don't mask
}

function stringEnd(line: string, start: number): number {
  const quote = line[start]!
  let i = start + 1
  for (; i < line.length; i++) {
    if (line[i] === "\\") {
      i++
      continue
    }
    if (line[i] === quote) return i + 1
  }
  return line.length
}
