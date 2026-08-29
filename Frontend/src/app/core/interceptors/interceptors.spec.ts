import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { authInterceptor } from './auth.interceptor';
import { csrfInterceptor } from './csrf.interceptor';
import { AuthService } from '../services/auth.service';
import { CsrfService } from '../services/csrf.service';
import { environment } from '../../../environment/environment';

const API = environment.authAPI;
const CSRF_HEADER = environment.csrfHeaderName;

describe('HTTP interceptors', () => {
  let http: HttpTestingController;
  let client: HttpClient;
  let auth: AuthService;
  let csrf: CsrfService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        // Same order as app.config.ts: auth wraps csrf.
        provideHttpClient(withInterceptors([authInterceptor, csrfInterceptor])),
        provideHttpClientTesting(),
        provideRouter([{ path: 'login', children: [] }, { path: 'landing', children: [] }]),
      ],
    });

    http = TestBed.inject(HttpTestingController);
    client = TestBed.inject(HttpClient);
    auth = TestBed.inject(AuthService);
    csrf = TestBed.inject(CsrfService);
  });

  afterEach(() => {
    http.verify();
    document.cookie = `${environment.csrfCookieName}=; Max-Age=0; path=/`;
  });

  /** Signs in through the real login path so the services hold real state. */
  function signIn(accessToken = 'token-1', csrfToken = 'csrf-1') {
    auth.login('ada@example.com', 'pw').subscribe();
    http.expectOne(`${API}/auth/login`).flush({
      requires_totp: false,
      message: 'ok',
      user_id: 'u-1',
      email: 'ada@example.com',
      access_token: accessToken,
      csrf_token: csrfToken,
      expires_in: 900,
    });
  }

  describe('csrfInterceptor', () => {
    it('omits the header on safe methods', () => {
      csrf.setToken('csrf-1');
      client.get(`${API}/auth/me`).subscribe();

      const request = http.expectOne(`${API}/auth/me`);
      expect(request.request.headers.has(CSRF_HEADER)).toBe(false);
      request.flush({});
    });

    it('attaches the header on unsafe methods', () => {
      document.cookie = `${environment.csrfCookieName}=csrf-1; path=/`;
      client.post(`${API}/auth/logout`, {}).subscribe();

      const request = http.expectOne(`${API}/auth/logout`);
      expect(request.request.headers.get(CSRF_HEADER)).toBe('csrf-1');
      request.flush({});
    });

    it('does not leak the token to third-party hosts', () => {
      document.cookie = `${environment.csrfCookieName}=csrf-1; path=/`;
      client.post('https://not-our-api.example.com/collect', {}).subscribe();

      const request = http.expectOne('https://not-our-api.example.com/collect');
      expect(request.request.headers.has(CSRF_HEADER)).toBe(false);
      request.flush({});
    });
  });

  describe('authInterceptor', () => {
    it('attaches the bearer token', () => {
      signIn();
      client.get(`${API}/auth/me`).subscribe();

      const request = http.expectOne(`${API}/auth/me`);
      expect(request.request.headers.get('Authorization')).toBe('Bearer token-1');
      request.flush({});
    });

    it('refreshes and retries once on a 401', () => {
      signIn();
      client.get(`${API}/auth/me`).subscribe();

      http
        .expectOne(`${API}/auth/me`)
        .flush({ detail: 'expired' }, { status: 401, statusText: 'Unauthorized' });

      http.expectOne(`${API}/auth/refresh`).flush({
        access_token: 'token-2',
        csrf_token: 'csrf-2',
        token_type: 'Bearer',
        expires_in: 900,
      });

      const retry = http.expectOne(`${API}/auth/me`);
      expect(retry.request.headers.get('Authorization')).toBe('Bearer token-2');
      retry.flush({});
    });

    it('re-applies the rotated CSRF token on the retry', () => {
      // This is why auth is registered before csrf. If the order were flipped,
      // the retry would replay the original stale header and the server would
      // answer 403 instead of succeeding.
      signIn();
      document.cookie = `${environment.csrfCookieName}=csrf-1; path=/`;

      client.post(`${API}/auth/sessions/abc`, {}).subscribe();

      http
        .expectOne(`${API}/auth/sessions/abc`)
        .flush({ detail: 'expired' }, { status: 401, statusText: 'Unauthorized' });

      // The server rotates the CSRF cookie as part of refreshing.
      document.cookie = `${environment.csrfCookieName}=csrf-rotated; path=/`;
      http.expectOne(`${API}/auth/refresh`).flush({
        access_token: 'token-2',
        csrf_token: 'csrf-rotated',
        token_type: 'Bearer',
        expires_in: 900,
      });

      const retry = http.expectOne(`${API}/auth/sessions/abc`);
      expect(retry.request.headers.get(CSRF_HEADER)).toBe('csrf-rotated');
      retry.flush({});
    });

    it('does not try to refresh a failed login', () => {
      client.post(`${API}/auth/login`, {}).subscribe({ error: () => undefined });

      http
        .expectOne(`${API}/auth/login`)
        .flush({ detail: 'bad creds' }, { status: 401, statusText: 'Unauthorized' });

      // A wrong password must surface as a wrong password, not kick off a
      // refresh loop.
      http.expectNone(`${API}/auth/refresh`);
    });

    it('does not retry when the refresh itself fails', () => {
      signIn();
      client.get(`${API}/auth/me`).subscribe({ error: () => undefined });

      http
        .expectOne(`${API}/auth/me`)
        .flush({ detail: 'expired' }, { status: 401, statusText: 'Unauthorized' });
      http
        .expectOne(`${API}/auth/refresh`)
        .flush({ detail: 'gone' }, { status: 401, statusText: 'Unauthorized' });

      http.expectNone(`${API}/auth/me`);
      expect(auth.isAuthenticated()).toBe(false);
    });

    it('passes non-401 errors straight through', () => {
      signIn();
      let status: number | undefined;
      client.get(`${API}/auth/me`).subscribe({ error: (e) => (status = e.status) });

      http
        .expectOne(`${API}/auth/me`)
        .flush({ detail: 'nope' }, { status: 403, statusText: 'Forbidden' });

      http.expectNone(`${API}/auth/refresh`);
      expect(status).toBe(403);
    });
  });
});
