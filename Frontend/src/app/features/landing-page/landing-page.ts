import { Component, inject, signal } from '@angular/core';
import { Router } from '@angular/router';

import { AuthService } from '../../core/services/auth.service';
import { describeHttpError } from '../../core/utils/http-error.util';

@Component({
  selector: 'app-landing-page',
  standalone: true,
  imports: [],
  templateUrl: './landing-page.html',
  styleUrl: './landing-page.scss',
})
export class LandingPage {
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);

  readonly user = this.authService.user;
  readonly signingOut = signal(false);
  readonly errorMessage = signal<string | null>(null);

  constructor() {
    // The login response carries only the basics. /auth/me is the authoritative
    // source for roles and verification flags, and it re-confirms the session
    // against the server rather than trusting anything decoded client-side.
    if (!this.user()) {
      this.authService.loadProfile().subscribe({
        error: (error: unknown) => this.errorMessage.set(describeHttpError(error)),
      });
    }
  }

  onLogout(allDevices = false): void {
    if (this.signingOut()) {
      return;
    }
    this.signingOut.set(true);

    // Navigate on both outcomes: clicking "sign out" must end the session in
    // this browser regardless of what the network did. AuthService already
    // clears local state in its error path.
    this.authService.logout(allDevices).subscribe({
      next: () => void this.router.navigate(['/login']),
      error: () => void this.router.navigate(['/login']),
    });
  }
}
