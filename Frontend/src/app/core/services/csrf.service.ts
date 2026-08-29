import { Injectable, PLATFORM_ID, inject, signal } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { environment } from '../../../environment/environment';
import { readCookie } from '../utils/cookie.util';

@Injectable({ providedIn: 'root' })
export class CsrfService {
  private readonly platformId = inject(PLATFORM_ID);
  private readonly isBrowser = isPlatformBrowser(this.platformId);

  /** Mirrors the cookie so reads stay cheap and SSR-safe. */
  private readonly token = signal<string | null>(null);

  constructor() {
    if (this.isBrowser) {
      this.token.set(readCookie(environment.csrfCookieName));
    }
  }

  setToken(token: string | null): void {
    this.token.set(token && token.length > 0 ? token : null);
  }

  /** Prefer the live cookie: the server rotates the token on every refresh. */
  getToken(): string | null {
    if (!this.isBrowser) {
      return null;
    }
    return readCookie(environment.csrfCookieName) ?? this.token();
  }

  clearToken(): void {
    this.token.set(null);
    if (this.isBrowser) {
      document.cookie = `${environment.csrfCookieName}=; Max-Age=0; path=/`;
    }
  }
}
