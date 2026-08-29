import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import {
  FormBuilder,
  FormGroup,
  ReactiveFormsModule,
  Validators,
} from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { HttpErrorResponse } from '@angular/common/http';

import { AuthService } from '../../../core/services/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterLink],
  templateUrl: './loginComponent.html',
  styleUrl: './login.scss',
})
export class LoginComponent {
  private readonly fb = inject(FormBuilder);
  private readonly authService = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  readonly showPassword = signal(false);
  readonly submitting = signal(false);
  readonly errorMessage = signal<string | null>(null);

  /** Switches the template from the password form to the TOTP form. */
  readonly requiresTotp = signal(false);

  readonly loginForm: FormGroup = this.fb.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', Validators.required],
    rememberMe: [false],
  });

  readonly totpForm: FormGroup = this.fb.group({
    totpCode: [
      '',
      [Validators.required, Validators.pattern(/^\d{6}$/)],
    ],
  });

  togglePassword(): void {
    this.showPassword.update((v) => !v);
  }

  onSubmit(): void {
    if (this.loginForm.invalid || this.submitting()) {
      this.loginForm.markAllAsTouched();
      return;
    }

    this.submitting.set(true);
    this.errorMessage.set(null);

    const { email, password } = this.loginForm.getRawValue();

    this.authService.login(email, password).subscribe({
      next: (signedIn) => {
        this.submitting.set(false);

        if (signedIn) {
          this.redirect();
          return;
        }

        // Password accepted, second factor still required.
        this.requiresTotp.set(true);
      },
      error: (error: unknown) => {
        this.submitting.set(false);
        this.errorMessage.set(this.describe(error));
        this.loginForm.patchValue({ password: '' });
      },
    });
  }

  onVerifyTotp(): void {
    if (this.totpForm.invalid || this.submitting()) {
      this.totpForm.markAllAsTouched();
      return;
    }

    this.submitting.set(true);
    this.errorMessage.set(null);

    this.authService.verifyTotp(this.totpForm.getRawValue().totpCode).subscribe({
      next: () => {
        this.submitting.set(false);
        this.redirect();
      },
      error: (error: unknown) => {
        this.submitting.set(false);
        this.errorMessage.set(this.describe(error));
        this.totpForm.reset();
      },
    });
  }

  /** Abandon the 2FA step and go back to the password form. */
  onCancelTotp(): void {
    this.authService.cancelTotp();
    this.requiresTotp.set(false);
    this.totpForm.reset();
    this.errorMessage.set(null);
    this.loginForm.patchValue({ password: '' });
  }

  private redirect(): void {
    // Only relative paths are honoured. Redirecting to an arbitrary value from
    // the query string is an open-redirect: an attacker could send a victim to
    // /login?returnUrl=https://evil.example and have our own app forward them.
    const requested = this.route.snapshot.queryParamMap.get('returnUrl');
    const safe =
      requested && requested.startsWith('/') && !requested.startsWith('//')
        ? requested
        : '/landing';

    void this.router.navigateByUrl(safe);
  }

  private describe(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      if (error.status === 0) {
        return 'Cannot reach the server. Check your connection and try again.';
      }
      if (error.status === 429) {
        const retry = error.headers.get('Retry-After');
        return retry
          ? `Too many attempts. Try again in ${retry} seconds.`
          : 'Too many attempts. Please try again shortly.';
      }
      const detail = (error.error as { detail?: string } | null)?.detail;
      if (typeof detail === 'string' && detail.length > 0) {
        return detail;
      }
      return 'Sign-in failed. Please try again.';
    }

    if (error instanceof Error && error.message) {
      return error.message;
    }

    return 'Something went wrong. Please try again.';
  }
}
