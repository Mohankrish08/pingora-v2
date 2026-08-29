import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

// The component is LoginComponent in loginComponent.ts. The generated spec
// imported a `Login` class from './login', which never existed -- so this file
// failed to compile rather than failing a test.
import { LoginComponent } from './loginComponent';
import { AuthService } from '../../../core/services/auth.service';
import { environment } from '../../../../environment/environment';

describe('LoginComponent', () => {
  let fixture: ComponentFixture<LoginComponent>;
  let component: LoginComponent;
  let http: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [LoginComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([{ path: 'login', children: [] }, { path: 'landing', children: [] }]),
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(LoginComponent);
    component = fixture.componentInstance;
    http = TestBed.inject(HttpTestingController);
    await fixture.whenStable();
  });

  afterEach(() => http.verify());

  it('creates', () => {
    expect(component).toBeTruthy();
  });

  it('starts on the password step', () => {
    expect(component.requiresTotp()).toBe(false);
  });

  it('does not submit an invalid form', () => {
    component.onSubmit();

    // No request should have been made at all.
    http.expectNone(`${environment.authAPI}/auth/login`);
    expect(component.submitting()).toBe(false);
  });

  it('switches to the TOTP step when the server asks for a second factor', () => {
    component.loginForm.setValue({
      email: 'ada@example.com',
      password: 'Str0ng!Passphrase42',
      rememberMe: false,
    });

    component.onSubmit();

    http.expectOne(`${environment.authAPI}/auth/login`).flush({
      requires_totp: true,
      message: 'Enter your authenticator code.',
      mfa_token: 'challenge-token',
    });

    expect(component.requiresTotp()).toBe(true);
    expect(component.submitting()).toBe(false);
  });

  it('surfaces the server message on a failed sign-in', () => {
    component.loginForm.setValue({
      email: 'ada@example.com',
      password: 'Wr0ng!Passphrase42',
      rememberMe: false,
    });

    component.onSubmit();

    http.expectOne(`${environment.authAPI}/auth/login`).flush(
      { detail: 'Invalid email or password' },
      { status: 401, statusText: 'Unauthorized' },
    );

    expect(component.errorMessage()).toBe('Invalid email or password');
    // The password field is cleared so it is not left sitting in the DOM.
    expect(component.loginForm.value.password).toBe('');
  });

  it('does not store the access token in localStorage', () => {
    component.loginForm.setValue({
      email: 'ada@example.com',
      password: 'Str0ng!Passphrase42',
      rememberMe: false,
    });

    component.onSubmit();

    http.expectOne(`${environment.authAPI}/auth/login`).flush({
      requires_totp: false,
      message: 'Login successful.',
      user_id: 'u-1',
      email: 'ada@example.com',
      display_name: 'Ada',
      access_token: 'the-access-token',
      csrf_token: 'the-csrf-token',
      expires_in: 900,
    });

    const auth = TestBed.inject(AuthService);
    expect(auth.getAccessToken()).toBe('the-access-token');

    // Anything in web storage is readable by injected script; the token must
    // live in memory only.
    expect(localStorage.getItem('accessToken')).toBeNull();
    expect(JSON.stringify(localStorage)).not.toContain('the-access-token');
  });
});
