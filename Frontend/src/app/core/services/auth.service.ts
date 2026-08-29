import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, PLATFORM_ID, computed, inject, signal } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import {
  Observable,
  catchError,
  map,
  of,
  retry,
  shareReplay,
  tap,
  throwError,
  timeout,
  timer,
} from 'rxjs';

import { environment } from '../../../environment/environment';
import { CsrfService } from './csrf.service';
import { readCookie } from '../utils/cookie.util';
import {
  AuthUser,
  LoginResponse,
  LogoutResponse,
  MeResponse,
  RefreshResponse,
  SessionInfo,
  TotpVerifyResponse,
} from '../models/auth.models';

const BOOTSTRAP_TIMEOUT_MS = 8_000;

/** Backoff before the single retry of a transport-level refresh failure. */
const REFRESH_RETRY_DELAY_MS = 600;

const LEGACY_TOKEN_STORAGE_KEYS = ['accessToken'] as const;

function isAuthRejection(error: unknown): boolean {
  return (
    error instanceof HttpErrorResponse && (error.status === 401 || error.status === 403)
  );
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly csrf = inject(CsrfService);
  private readonly isBrowser = isPlatformBrowser(inject(PLATFORM_ID));

  private readonly baseUrl = environment.authAPI;

  private readonly accessToken = signal<string | null>(null);
  private readonly currentUser = signal<AuthUser | null>(null);
  private readonly bootstrapped = signal(false);

  /** Set while a login is mid-MFA: password accepted, code still needed. */
  private readonly pendingMfaToken = signal<string | null>(null);

  readonly user = this.currentUser.asReadonly();
  readonly isReady = this.bootstrapped.asReadonly();
  readonly isAuthenticated = computed(() => this.accessToken() !== null);
  readonly awaitingTotp = computed(() => this.pendingMfaToken() !== null);

  private refreshInFlight: Observable<RefreshResponse> | null = null;

  constructor() {
    this.purgeLegacyTokenStorage();
  }

  private purgeLegacyTokenStorage(): void {
    if (!this.isBrowser) {
      return;
    }

    for (const key of LEGACY_TOKEN_STORAGE_KEYS) {
      try {
        localStorage.removeItem(key);
        sessionStorage.removeItem(key);
      } catch {
        // Nothing recoverable to do here.
      }
    }
  }

  // --- Token accessors ----------------------------------------------------
  getAccessToken(): string | null {
    return this.accessToken();
  }

  private setSession(token: string, csrfToken: string): void {
    this.accessToken.set(token);
    this.csrf.setToken(csrfToken);
    this.pendingMfaToken.set(null);
  }

  private clearSession(): void {
    this.accessToken.set(null);
    this.currentUser.set(null);
    this.pendingMfaToken.set(null);
    this.csrf.clearToken();
    this.refreshInFlight = null;
    this.purgeLegacyTokenStorage();
  }

  // --- Bootstrap ----------------------------------------------------------
  bootstrap(): Observable<boolean> {
    if (!this.isBrowser) {
      this.bootstrapped.set(true);
      return of(false);
    }

    return this.refresh().pipe(
      timeout(BOOTSTRAP_TIMEOUT_MS),
      map(() => true),
      catchError(() => of(false)),
      tap(() => this.bootstrapped.set(true)),
    );
  }

  // --- Login --------------------------------------------------------------
  login(email: string, password: string): Observable<boolean> {
    return this.http
      .post<LoginResponse>(
        `${this.baseUrl}/auth/login`,
        { email, password },
        { withCredentials: true },
      )
      .pipe(
        map((res) => {
          if (res.requires_totp) {
            // Park the challenge token; no access token exists yet.
            this.pendingMfaToken.set(res.mfa_token ?? null);
            return false;
          }

          if (!res.access_token || !res.csrf_token) {
            throw new Error('Login response was missing its tokens');
          }

          this.setSession(res.access_token, res.csrf_token);
          this.currentUser.set({
            userId: res.user_id ?? '',
            email: res.email ?? email,
            displayName: res.display_name ?? null,
            roles: ['user'],
          });
          return true;
        }),
      );
  }

  /** Second factor. Consumes the challenge token parked by `login()`. */
  verifyTotp(totpCode: string): Observable<TotpVerifyResponse> {
    const mfaToken = this.pendingMfaToken();
    if (!mfaToken) {
      return throwError(
        () => new Error('No verification in progress. Please sign in again.'),
      );
    }

    return this.http
      .post<TotpVerifyResponse>(
        `${this.baseUrl}/auth/verify-totp`,
        { mfa_token: mfaToken, totp_code: totpCode },
        { withCredentials: true },
      )
      .pipe(
        tap((res) => {
          this.setSession(res.access_token, res.csrf_token);
          this.currentUser.set({
            userId: res.user_id,
            email: res.email,
            displayName: res.display_name ?? null,
            roles: ['user'],
          });
        }),
      );
  }

  cancelTotp(): void {
    this.pendingMfaToken.set(null);
  }

  // --- Refresh ------------------------------------------------------------
  /** Exchange the refresh cookie for a new access token. Single-flight. */
  refresh(): Observable<RefreshResponse> {
    if (!this.isBrowser) {
      return throwError(() => new Error('Refresh is unavailable during server rendering'));
    }

    if (!this.hasSessionHint()) {
      return throwError(() => new Error('No session to restore'));
    }

    if (this.refreshInFlight) {
      return this.refreshInFlight;
    }

    this.refreshInFlight = this.http
      .post<RefreshResponse>(
        `${this.baseUrl}/auth/refresh`,
        {},
        { withCredentials: true },
      )
      .pipe(
        timeout(environment.apiTimeout),
        retry({
          count: 1,
          delay: (error) =>
            isAuthRejection(error)
              ? throwError(() => error)
              : timer(REFRESH_RETRY_DELAY_MS),
        }),
        tap({
          next: (res) => {
            this.setSession(res.access_token, res.csrf_token);
            this.refreshInFlight = null;
          },
          error: (error: unknown) => {
            if (isAuthRejection(error)) {
              this.clearSession();
            } else {
              this.refreshInFlight = null;
            }
          },
        }),
        // Replay to every subscriber that joined while the call was open.
        shareReplay({ bufferSize: 1, refCount: false }),
      );

    return this.refreshInFlight;
  }

  /** Whether the server says a refresh cookie should be sitting in the jar. */
  private hasSessionHint(): boolean {
    return readCookie(environment.sessionHintCookieName) !== null;
  }

  // --- Logout -------------------------------------------------------------
  logout(allDevices = false): Observable<LogoutResponse> {
    return this.http
      .post<LogoutResponse>(
        `${this.baseUrl}/auth/logout`,
        { all_devices: allDevices },
        { withCredentials: true },
      )
      .pipe(
        tap({
          next: () => this.clearSession(),
          error: () => this.clearSession(),
        }),
      );
  }

  // --- Profile and sessions ----------------------------------------------
  loadProfile(): Observable<MeResponse> {
    return this.http
      .get<MeResponse>(`${this.baseUrl}/auth/me`, { withCredentials: true })
      .pipe(
        tap((profile) =>
          this.currentUser.set({
            userId: profile.user_id,
            email: profile.email,
            displayName: profile.display_name ?? null,
            roles: profile.roles ?? ['user'],
          }),
        ),
      );
  }

  listSessions(): Observable<SessionInfo[]> {
    return this.http.get<SessionInfo[]>(`${this.baseUrl}/auth/sessions`, {
      withCredentials: true,
    });
  }

  revokeSession(sessionId: string): Observable<LogoutResponse> {
    return this.http.delete<LogoutResponse>(
      `${this.baseUrl}/auth/sessions/${encodeURIComponent(sessionId)}`,
      { withCredentials: true },
    );
  }
}
