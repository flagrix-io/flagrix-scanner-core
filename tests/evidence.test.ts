import { describe, expect, it } from "vitest"

import { collectEvidence } from "../src/utils/evidence"

describe("collectEvidence", () => {
  const content = [
    `const ok = 1`, // 1
    `const c = document.cookie`, // 2
    `document.addEventListener("keydown", grab)`, // 3
    `const d = document.cookie // again`, // 4
    `done()` // 5
  ].join("\n")

  it("returns 1-based line numbers and trimmed lines", () => {
    const ev = collectEvidence(content, /document\.cookie/g)
    expect(ev).toEqual([
      { line: 2, code: "const c = document.cookie" },
      { line: 4, code: "const d = document.cookie // again" }
    ])
  })

  it("accepts multiple patterns and reports each line once", () => {
    const ev = collectEvidence(content, [
      /document\.cookie/g,
      /addEventListener\s*\(\s*['"]keydown['"]/g
    ])
    expect(ev.map((e) => e.line)).toEqual([2, 3, 4])
  })

  it("caps the number of evidence lines", () => {
    const many = Array(10).fill("document.cookie").join("\n")
    expect(collectEvidence(many, /document\.cookie/g)).toHaveLength(3)
  })

  it("caps line length", () => {
    const long = "const x = document.cookie + " + `"a"`.repeat(100)
    const ev = collectEvidence(long, /document\.cookie/g)
    expect(ev[0]!.code.length).toBeLessThanOrEqual(161)
    expect(ev[0]!.code.endsWith("…")).toBe(true)
  })

  it("is not tripped up by global-regex lastIndex", () => {
    const g = /cookie/g
    g.test("cookie") // advance lastIndex on the original
    expect(collectEvidence("document.cookie", g)).toHaveLength(1)
  })

  it("returns empty for patterns that only match across lines", () => {
    expect(collectEvidence("a\nb", /a[\s\S]b/g)).toEqual([])
  })
})
