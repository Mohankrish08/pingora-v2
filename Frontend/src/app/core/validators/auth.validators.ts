import { AbstractControl, ValidationErrors, ValidatorFn } from '@angular/forms';

/**
 * Client-side mirrors of the server's validation rules.
 *
 * These exist purely so the user sees a helpful message while typing instead of
 * a 422 on submit. The server re-validates everything in
 * `schema/auth_schemas.py` and remains the only authority -- anything enforced
 * only here is trivially bypassed with curl.
 *
 * Keep the two in step. If the backend policy changes, change it here too.
 */

/** Must match PHONE_PATTERN (E.164) in auth_schemas.py. */
export const E164_PATTERN = /^\+[1-9]\d{7,14}$/;

/** Must match COMMON_PASSWORDS in auth_schemas.py. */
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', '12345678', '123456789',
  'qwerty123', 'letmein1', 'welcome1', 'admin123', 'iloveyou1',
  'passw0rd', 'abc12345', 'football1', 'monkey123', 'sunshine1',
]);

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

export interface PasswordRequirement {
  key: string;
  label: string;
  met: boolean;
}

/** Per-rule breakdown, so the UI can show a live checklist. */
export function passwordRequirements(value: string): PasswordRequirement[] {
  return [
    {
      key: 'length',
      label: `At least ${PASSWORD_MIN_LENGTH} characters`,
      met: value.length >= PASSWORD_MIN_LENGTH,
    },
    { key: 'uppercase', label: 'An uppercase letter', met: /[A-Z]/.test(value) },
    { key: 'lowercase', label: 'A lowercase letter', met: /[a-z]/.test(value) },
    { key: 'digit', label: 'A number', met: /\d/.test(value) },
    { key: 'symbol', label: 'A symbol', met: /[^A-Za-z0-9]/.test(value) },
  ];
}

export function strongPasswordValidator(): ValidatorFn {
  return (control: AbstractControl): ValidationErrors | null => {
    const value: string = control.value ?? '';

    // Leave "required" to Validators.required so errors do not stack up on an
    // untouched empty field.
    if (!value) {
      return null;
    }

    if (value.length > PASSWORD_MAX_LENGTH) {
      return { passwordTooLong: { max: PASSWORD_MAX_LENGTH } };
    }

    if (COMMON_PASSWORDS.has(value.toLowerCase())) {
      return { passwordTooCommon: true };
    }

    const unmet = passwordRequirements(value).filter((r) => !r.met);
    return unmet.length > 0 ? { passwordWeak: { unmet: unmet.map((r) => r.key) } } : null;
  };
}

export function e164PhoneValidator(): ValidatorFn {
  return (control: AbstractControl): ValidationErrors | null => {
    const value: string = (control.value ?? '').trim();
    if (!value) {
      return null;
    }
    return E164_PATTERN.test(value) ? null : { e164: true };
  };
}

/**
 * Strength score 0-4, driven by the same rules the validator enforces, so the
 * meter can never read "Strong" on a password the server will reject.
 */
export function passwordStrength(value: string): number {
  if (!value) {
    return 0;
  }
  const met = passwordRequirements(value).filter((r) => r.met).length;
  // Five requirements collapsed onto a four-segment meter.
  return Math.min(4, Math.max(0, met - 1));
}
