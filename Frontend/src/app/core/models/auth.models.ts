/**
 * Wire contracts for the authentication API.
 *
 * The refresh token is deliberately absent from every interface here: it lives
 * only in an HttpOnly cookie the browser attaches automatically, so JavaScript
 * never sees it and an XSS bug cannot steal it.
 */

export interface LoginResponse {
  requires_totp: boolean;
  message: string;

  user_id?: string | null;
  email?: string | null;
  display_name?: string | null;

  access_token?: string | null;
  csrf_token?: string | null;
  token_type?: string;
  expires_in?: number | null;

  /** Short-lived proof the password factor passed. Only when requires_totp. */
  mfa_token?: string | null;
}

export interface TotpVerifyResponse {
  user_id: string;
  email: string;
  display_name?: string | null;
  access_token: string;
  csrf_token: string;
  token_type: string;
  expires_in: number;
  message: string;
}

export interface RefreshResponse {
  access_token: string;
  csrf_token: string;
  token_type: string;
  expires_in: number;
}

export interface LogoutResponse {
  message: string;
  sessions_revoked: number;
}

export interface MeResponse {
  user_id: string;
  email: string;
  phone_number?: string | null;
  display_name?: string | null;
  email_verified: boolean;
  phone_verified: boolean;
  roles: string[];
}

export interface SessionInfo {
  session_id: string;
  created_at?: string | null;
  last_used_at?: string | null;
  expires_at?: string | null;
  user_agent?: string | null;
  ip_address?: string | null;
  current: boolean;
}

export interface ApiError {
  detail: string;
  code?: string;
  errors?: { field: string; message: string }[];
}

/** Signed-in user held in memory for the lifetime of the tab. */
export interface AuthUser {
  userId: string;
  email: string;
  displayName: string | null;
  roles: string[];
}
