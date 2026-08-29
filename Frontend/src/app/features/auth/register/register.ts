import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import {
  FormBuilder,
  FormGroup,
  ReactiveFormsModule,
  Validators,
} from '@angular/forms';
import { Router, RouterLink } from '@angular/router';

import { describeHttpError, fieldErrors } from '../../../core/utils/http-error.util';
import {
  e164PhoneValidator,
  passwordRequirements,
  passwordStrength,
  strongPasswordValidator,
} from '../../../core/validators/auth.validators';
import { RegisterResponse, RegisterService } from './register.service';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterLink],
  templateUrl: './register.html',
  styleUrl: './register.scss',
})
export class RegisterComponent {
  private readonly fb = inject(FormBuilder);
  private readonly registerService = inject(RegisterService);
  private readonly router = inject(Router);

  readonly showPassword = signal(false);
  readonly submitting = signal(false);
  readonly errorMessage = signal<string | null>(null);
  readonly serverFieldErrors = signal<Record<string, string>>({});

  /** Set once the account exists; switches the view to authenticator setup. */
  readonly created = signal<RegisterResponse | null>(null);

  readonly registerForm: FormGroup = this.fb.group({
    display_name: [
      '',
      [Validators.required, Validators.minLength(2), Validators.maxLength(50)],
    ],
    email: ['', [Validators.required, Validators.email]],
    // The server requires E.164. Enforcing "10 digits" here would let the user
    // submit something the server then rejects with a 422.
    phone_number: ['', [Validators.required, e164PhoneValidator()]],
    password: ['', [Validators.required, strongPasswordValidator()]],
  });

  private readonly passwordValue = signal('');

  readonly requirements = computed(() => passwordRequirements(this.passwordValue()));
  readonly strength = computed(() => passwordStrength(this.passwordValue()));

  readonly strengthColors = ['#ffb4ab', '#ffb86b', '#71a1ff', '#4edea3'];

  readonly strengthText = computed(() => {
    if (!this.passwordValue()) {
      return 'At least 12 characters, with a mix of cases, a number and a symbol';
    }
    const unmet = this.requirements().filter((r) => !r.met);
    if (unmet.length === 0) {
      return 'Strong password';
    }
    return `Still needed: ${unmet.map((r) => r.label.toLowerCase()).join(', ')}`;
  });

  onPasswordInput(value: string): void {
    this.passwordValue.set(value);
  }

  barColor(index: number): string {
    const level = this.strength();
    return index < level
      ? this.strengthColors[Math.max(0, level - 1)]
      : 'rgba(60, 74, 66, 0.4)';
  }

  togglePassword(): void {
    this.showPassword.update((v) => !v);
  }

  /** Server-side message for a field, if the last submit produced one. */
  serverError(field: string): string | null {
    return this.serverFieldErrors()[field] ?? null;
  }

  /**
   * The base32 secret pulled out of the otpauth:// URI.
   *
   * Rendering a real QR code would need a QR library we do not depend on, so
   * the user gets the secret to type in manually. It is shown exactly once --
   * the server cannot re-issue it, because it only ever stored the ciphertext.
   */
  readonly totpSecret = computed(() => {
    const uri = this.created()?.totp_provisioning_uri;
    if (!uri) {
      return null;
    }
    // Parsed with URLSearchParams rather than a regex so an encoded value with
    // "&" or "=" inside it survives.
    const query = uri.slice(uri.indexOf('?') + 1);
    return new URLSearchParams(query).get('secret');
  });

  readonly copied = signal(false);

  async copySecret(): Promise<void> {
    const secret = this.totpSecret();
    if (!secret || !navigator.clipboard) {
      return;
    }
    try {
      await navigator.clipboard.writeText(secret);
      this.copied.set(true);
      setTimeout(() => this.copied.set(false), 2000);
    } catch {
      // Clipboard access can be denied; the secret is selectable on screen.
    }
  }

  onSubmit(): void {
    if (this.registerForm.invalid || this.submitting()) {
      this.registerForm.markAllAsTouched();
      return;
    }

    this.submitting.set(true);
    this.errorMessage.set(null);
    this.serverFieldErrors.set({});

    this.registerService.register(this.registerForm.getRawValue()).subscribe({
      next: (response) => {
        this.submitting.set(false);

        // Show the authenticator setup step rather than navigating away: the
        // provisioning URI is returned exactly once and cannot be re-fetched.
        this.created.set(response);
        this.registerForm.reset();
        this.passwordValue.set('');
      },
      error: (error: unknown) => {
        this.submitting.set(false);
        this.errorMessage.set(describeHttpError(error, 'Could not create your account.'));
        this.serverFieldErrors.set(fieldErrors(error));
        this.registerForm.patchValue({ password: '' });
        this.passwordValue.set('');
      },
    });
  }

  goToLogin(): void {
    void this.router.navigate(['/login']);
  }
}
