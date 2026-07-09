import { describe, expect, it } from "vitest"

import { maskRegexLiterals, maskStringLiterals } from "../src/utils/mask.js"

describe("maskRegexLiterals", () => {
  it("blanks a regex literal describing a keylogger", () => {
    const line = `  { pattern: /(?:addEventListener|on)\\s*\\(\\s*['"](?:keydown|keypress|keyup)['"]/gi, name: "x" },`
    const masked = maskRegexLiterals(line)
    expect(masked).not.toContain("keydown")
    expect(masked).toContain(`name: "x"`) // rest of the line intact
    expect(masked.length).toBe(line.length) // offsets preserved
  })

  it("leaves real code untouched", () => {
    const line = `document.addEventListener("keydown", (e) => send(e.key))`
    expect(maskRegexLiterals(line)).toBe(line)
  })

  it("does not treat division as a regex", () => {
    const line = `const rate = total / count / window`
    expect(maskRegexLiterals(line)).toBe(line)
  })

  it("keeps string contents scannable (payloads live in strings)", () => {
    const line = `const p = "coinhive.min.js" // eslint-disable-line`
    expect(maskRegexLiterals(line)).toContain("coinhive")
  })

  it("does not mask a slash inside a string", () => {
    const line = `const url = "https://example.com/a/b" + document.cookie`
    expect(maskRegexLiterals(line)).toContain("document.cookie")
  })

  it("handles character classes containing slashes", () => {
    const line = `const re = /[/x]+coinhive[/y]+/g; steal()`
    const masked = maskRegexLiterals(line)
    expect(masked).not.toContain("coinhive")
    expect(masked).toContain("steal()")
  })

  it("masks regexes after return/case keywords", () => {
    const masked = maskRegexLiterals(`return /stratum\\+tcp/i`)
    expect(masked).not.toContain("stratum")
  })

  it("preserves line count and numbering", () => {
    const content = `a\nconst r = /document\\.cookie/g\nb`
    const masked = maskRegexLiterals(content)
    expect(masked.split("\n")).toHaveLength(3)
    expect(masked.split("\n")[2]).toBe("b")
  })

  it("leaves unterminated slashes alone", () => {
    const line = `const half = 1 / 2`
    expect(maskRegexLiterals(line)).toBe(line)
  })
})

describe("maskStringLiterals (test-file fixtures)", () => {
  it("masks a quoted attack fixture but keeps real code", () => {
    const content = [
      `const fixture = "document.addEventListener(\\"keydown\\", grab)"`,
      `document.addEventListener("keydown", spy)` // the call itself stays; only the string arg blanks
    ].join("\n")
    const masked = maskStringLiterals(content)
    const lines = masked.split("\n")
    expect(lines[0]).not.toContain("addEventListener")
    expect(lines[1]).toContain("document.addEventListener(")
  })

  it("masks multi-line template literals and preserves line numbers", () => {
    const content = "const f = `line one\ndocument.cookie\nline three`\nsteal()"
    const masked = maskStringLiterals(content)
    expect(masked.split("\n")).toHaveLength(4)
    expect(masked).not.toContain("document.cookie")
    expect(masked.split("\n")[3]).toBe("steal()")
  })

  it("is not derailed by apostrophes in comments", () => {
    const content = `// don't break here\nconst c = document.cookie`
    expect(maskStringLiterals(content)).toContain("document.cookie")
  })

  it("composes with regex masking (regexes containing quotes)", () => {
    const content = `const re = /['"]key['"]/g\nconst s = "coinhive"`
    const masked = maskStringLiterals(maskRegexLiterals(content))
    expect(masked).not.toContain("coinhive")
    expect(masked.split("\n")).toHaveLength(2)
  })
})
