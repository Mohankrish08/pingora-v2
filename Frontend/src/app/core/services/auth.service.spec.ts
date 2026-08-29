import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { AuthService } from './auth.service';
import { CsrfService } from './csrf.service';
import { authInterceptor } from '../interceptors/auth.interceptor';
import { csrfInterceptor } from '../interceptors/csrf.interceptor';
import { environment } from '../../../environment/environment';

const API = environment.authAPI;

describe('AuthService', () => {
  let auth: AuthService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor, csrfInterceptor])),
        provideHttpClientTesting(),
        provideRouter([{ path: 'login', children: [] }, { path: 'landing', children: [] }]),
      ],
    });

    auth = TestBed.inject(AuthService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  describe('token storage', () => {
    it('keeps the access token out of web storage', () => {
      auth.login('ada@example.com', 'Str0ng!Passphrase42').subscribe();

      http.expectOne(`${API}/auth/login`).flush({
        requires_totp: false,
        message: 'ok',
        user_id: 'u-1',
        email: 'ada@example.com',
        access_token: 'secret-access-token',
        csrf_token: 'csrf-1',
        expires_in: 900,
      });

      expect(auth.getAccessToken()).toBe('secret-access-token');
      // An XSS payload can read localStorage/sessionStorage; it cannot read a
      // closure-scoped signal.
      expect(JSON.stringify(localStorage)).not.toContain('secret-access-token');
      expect(JSON.stringify(sessionStorage)).not.toContain('secret-access-token');
    });

    it('sends credentials so the HttpOnly refresh cookie travels', () => {
      auth.login('ada@example.com', 'pw').subscribe();

      const request = http.expectOne(`${API}/auth/login`);
      expect(request.request.withCredentials).toBe(true);
      request.flush({ requires_totp: true, message: 'mfa', mfa_token: 'm-1' });
    });
  });

  describe('two-factor', () => {
    it('does not authenticate on the password step alone', () => {
      let signedIn: boolean | undefined;
      auth.login('ada@example.com', 'pw').subscribe((v) => (signedIn = v));

      http.expectOne(`${API}/auth/login`).flush({
        requires_totp: true,
        message: 'Enter your code',
        mfa_token: 'challenge-1',
      });

      expect(signedIn).toBe(false);
      expect(auth.isAuthenticated()).toBe(false);
      expect(auth.awaitingTotp()).toBe(true);
    });

    it('refuses to verify without a challenge in progress', () => {
      let failed = false;
      auth.verifyTotp('123456').subscribe({ error: () => (failed = true) });

      expect(failed).toBe(true);
      http.expectNone(`${API}/auth/verify-totp`);
    });

    it('completes sign-in with a valid code', () => {
      auth.login('ada@example.com', 'pw').subscribe();
      http.expectOne(`${API}/auth/login`).flush({
        requires_totp: true,
        message: 'mfa',
        mfa_token: 'challenge-1',
      });

      auth.verifyTotp('123456').subscribe();
      const request = http.expectOne(`${API}/auth/verify-totp`);
      expect(request.request.body).toEqual({
        mfa_token: 'challenge-1',
        totp_code: '123456',
      });

      request.flush({
        user_id: 'u-1',
        email: 'ada@example.com',
        display_name: 'Ada',
        access_token: 'token-after-2fa',
        csrf_token: 'csrf-2',
        token_type: 'Bearer',
        expires_in: 900,
        message: 'ok',
      });

      expect(auth.isAuthenticated()).toBe(true);
      expect(auth.awaitingTotp()).toBe(false);
    });
  });

  describe('refresh', () => {
    it('is single-flight', () => {
      // The server rotates the refresh token on use. Two concurrent refreshes
      // would make the second present an already-rotated token, which the
      // server correctly treats as theft and answers by killing the session.
      auth.refresh().subscribe();
      auth.refresh().subscribe();
      auth.refresh().subscribe();

      const requests = http.match(`${API}/auth/refresh`);
      expect(requests.length).toBe(1);

      requests[0].flush({
        access_token: 'refreshed',
        csrf_token: 'csrf-new',
        token_type: 'Bearer',
        expires_in: 900,
      });
    });

    it('clears the session when the refresh cookie is rejected', () => {
      auth.refresh().subscribe({ error: () => undefined });

      http
        .expectOne(`${API}/auth/refresh`)
        .flush({ detail: 'expired' }, { status: 401, statusText: 'Unauthorized' });

      expect(auth.isAuthenticated()).toBe(false);
    });
  });

  describe('logout', () => {
    function signIn() {
      auth.login('ada@example.com', 'pw').subscribe();
      http.expectOne(`${API}/auth/login`).flush({
        requires_totp: false,
        message: 'ok',
        user_id: 'u-1',
        email: 'ada@example.com',
        access_token: 'token-1',
        csrf_token: 'csrf-1',
        expires_in: 900,
      });
    }

    it('clears local state on success', () => {
      signIn();
      auth.logout().subscribe();
      http.expectOne(`${API}/auth/logout`).flush({ message: 'ok', sessions_revoked: 1 });

      expect(auth.isAuthenticated()).toBe(false);
      expect(auth.user()).toBeNull();
    });

    it('clears local state even when the request fails', () => {
      // Clicking "sign out" must end the session in this browser regardless of
      // what the network did.
      signIn();
      auth.logout().subscribe({ error: () => undefined });
      http
        .expectOne(`${API}/auth/logout`)
        .flush({ detail: 'boom' }, { status: 500, statusText: 'Server Error' });

      expect(auth.isAuthenticated()).toBe(false);
    });

    it('can revoke every device', () => {
      signIn();
      auth.logout(true).subscribe();

      const request = http.expectOne(`${API}/auth/logout`);
      expect(request.request.body).toEqual({ all_devices: true });
      request.flush({ message: 'ok', sessions_revoked: 3 });
    });
  });
});

describe('CsrfService', () => {
  let csrf: CsrfService;

  beforeEach(() => {
    document.cookie = `${environment.csrfCookieName}=; Max-Age=0; path=/`;
    TestBed.configureTestingModule({ providers: [provideHttpClient()] });
    csrf = TestBed.inject(CsrfService);
  });

  afterEach(() => {
    document.cookie = `${environment.csrfCookieName}=; Max-Age=0; path=/`;
  });

  it('reads the token from the cookie', () => {
    // Reading the cookie rather than only an in-memory signal is what lets a
    // page reload keep working: an empty header means 403 on every POST.
    document.cookie = `${environment.csrfCookieName}=token-from-cookie; path=/`;

    expect(csrf.getToken()).toBe('token-from-cookie');
  });

  it('prefers the cookie over a stale in-memory value', () => {
    csrf.setToken('stale-token');
    document.cookie = `${environment.csrfCookieName}=rotated-token; path=/`;

    expect(csrf.getToken()).toBe('rotated-token');
  });

  it('returns null when there is no token', () => {
    expect(csrf.getToken()).toBeNull();
  });
});
