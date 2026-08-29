import { HttpErrorResponse } from '@angular/common/http';

interface ApiErrorBody {
  detail?: string;
  code?: string;
  errors?: { field: string; message: string }[];
}

/**
 * Turn any thrown value into one sentence worth showing a user.
 *
 * The server deliberately returns vague text for auth failures (a specific
 * "no such account" would let anyone enumerate users), so this passes `detail`
 * through rather than trying to improve on it. Only transport-level problems,
 * which carry no server message at all, get wording invented here.
 */
export function describeHttpError(error: unknown, fallback = 'Something went wrong. Please try again.'): string {
  if (error instanceof HttpErrorResponse) {
    // status 0 means the request never completed: offline, DNS, CORS, or the
    // API is not running. "Unauthorized" would be actively misleading here.
    if (error.status === 0) {
      return 'Cannot reach the server. Check your connection and try again.';
    }

    if (error.status === 429) {
      const retryAfter = error.headers.get('Retry-After');
      return retryAfter
        ? `Too many attempts. Try again in ${retryAfter} seconds.`
        : 'Too many attempts. Please try again shortly.';
    }

    const body = error.error as ApiErrorBody | string | null;

    if (typeof body === 'string' && body.trim().length > 0) {
      return body;
    }

    if (body && typeof body === 'object') {
      // 422 from the validation handler: field errors, no submitted values.
      if (Array.isArray(body.errors) && body.errors.length > 0) {
        return body.errors.map((e) => e.message).join(' ');
      }
      if (typeof body.detail === 'string' && body.detail.length > 0) {
        return body.detail;
      }
    }

    if (error.status >= 500) {
      return 'The server ran into a problem. Please try again in a moment.';
    }

    return fallback;
  }

  if (error instanceof Error && error.message) {
    return error.message;
  }

  return fallback;
}

/** Field-level errors from a 422, keyed by field name, for inline display. */
export function fieldErrors(error: unknown): Record<string, string> {
  if (!(error instanceof HttpErrorResponse)) {
    return {};
  }

  const body = error.error as ApiErrorBody | null;
  if (!body || !Array.isArray(body.errors)) {
    return {};
  }

  return body.errors.reduce<Record<string, string>>((acc, item) => {
    if (item.field) {
      acc[item.field] = item.message;
    }
    return acc;
  }, {});
}
