/**
 * Whether a failed response is GitHub refusing because the request budget is
 * spent — the primary hourly limit (`x-ratelimit-remaining: 0`) or a secondary
 * limit, which answers 403/429 with `retry-after` instead.
 *
 * Headers only: the caller may still want to read the body, and mid-scan this
 * is asked once per file, where parsing JSON for every miss would be waste.
 */
export function isRateLimitResponse(response: Response): boolean {
  if (response.status !== 403 && response.status !== 429) return false
  return (
    response.headers?.get("x-ratelimit-remaining") === "0" ||
    response.headers?.get("retry-after") !== null
  )
}

/**
 * Turns a failed GitHub API response into an actionable error.
 *
 * GitHub uses 403 for several unrelated conditions (SAML/SSO enforcement,
 * disabled classic PATs, rate limiting) and explains which one in the JSON
 * body — so surface that instead of a bare status code.
 */
/**
 * What a 404 means depends on whether we were carrying a token.
 *
 * GitHub answers 404 rather than 403 for a repository the caller may not see,
 * so "not found" is really "not visible to you". Without a token that is
 * almost always a private repo. With one it is the harder case to diagnose and
 * the one users hit later: the token expired, or it is a fine-grained token
 * whose repository access does not cover this repo. Reporting both as the same
 * "add a token" message sends someone who already has a token nowhere.
 */
export function githubNotFoundError(hasToken: boolean): Error {
  return hasToken
    ? new Error(
        "Your GitHub token can't see this repository — it may have expired, or it may not include this repo. Check it in Flagrix settings (404)."
      )
    : new Error(
        "This appears to be a private repository. To scan private repos, add a GitHub personal access token in Flagrix settings."
      )
}

export async function githubApiError(
  response: Response,
  fallback = "GitHub API error"
): Promise<Error> {
  let apiMessage = ""
  try {
    const body = (await response.json()) as { message?: unknown }
    if (typeof body?.message === "string") apiMessage = body.message
  } catch {
    // Non-JSON body — fall through to the status-only message.
  }

  if (response.status === 401) {
    return new Error(
      "GitHub token is invalid or expired — update it in Flagrix settings (401)."
    )
  }

  if (response.status === 403) {
    if (/saml|sso/i.test(apiMessage) || response.headers?.get("x-github-sso")) {
      return new Error(
        "This organization requires SSO authorization for your token. Open github.com/settings/tokens and use 'Configure SSO' on your token to authorize it for the organization (403)."
      )
    }
    if (/personal access token/i.test(apiMessage)) {
      return new Error(
        `This organization restricts personal access tokens — ${apiMessage} (403).`
      )
    }
    if (response.headers?.get("x-ratelimit-remaining") === "0") {
      return new Error(
        "GitHub API rate limit exceeded. Add a personal access token in Flagrix settings to raise the limit (403)."
      )
    }
  }

  return new Error(
    apiMessage
      ? `${fallback}: ${response.status} — ${apiMessage}`
      : `${fallback}: ${response.status}`
  )
}
