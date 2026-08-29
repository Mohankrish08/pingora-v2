/**
 * Read a cookie value from `document.cookie`.
 *
 * Only ever used for the two cookies the server deliberately leaves readable
 * (`XSRF-TOKEN` and `session_hint`). The HttpOnly refresh cookie is invisible
 * here by design, which is the whole reason `session_hint` exists.
 *
 * Callers must confirm they are in a browser first; `document` does not exist
 * during server rendering.
 */
export function readCookie(name: string): string | null {
  const prefix = `${name}=`;
  const match = document.cookie.split('; ').find((row) => row.startsWith(prefix));

  if (!match) {
    return null;
  }

  const value = match.substring(prefix.length);

  // Cookie values are percent-encoded by some servers; decode defensively.
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
