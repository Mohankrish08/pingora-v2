import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { LandingPage } from './landing-page';
import { environment } from '../../../environment/environment';

describe('LandingPage', () => {
  let fixture: ComponentFixture<LandingPage>;
  let component: LandingPage;
  let http: HttpTestingController;

  beforeEach(async () => {
    // The component injects AuthService, which needs HttpClient and Router.
    // Without these providers the generated spec threw NullInjectorError.
    await TestBed.configureTestingModule({
      imports: [LandingPage],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([{ path: 'login', children: [] }, { path: 'landing', children: [] }]),
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(LandingPage);
    component = fixture.componentInstance;
    http = TestBed.inject(HttpTestingController);
    await fixture.whenStable();
  });

  afterEach(() => http.verify());

  it('creates', () => {
    expect(component).toBeTruthy();
    // The constructor fires /auth/me; answer it so afterEach's verify() passes.
    http.expectOne(`${environment.authAPI}/auth/me`).flush({
      user_id: 'u-1',
      email: 'ada@example.com',
      display_name: 'Ada',
      email_verified: true,
      phone_verified: true,
      roles: ['user'],
    });
  });

  it('loads the profile from the server when none is cached', () => {
    const request = http.expectOne(`${environment.authAPI}/auth/me`);
    expect(request.request.method).toBe('GET');

    request.flush({
      user_id: 'u-1',
      email: 'ada@example.com',
      display_name: 'Ada',
      email_verified: true,
      phone_verified: true,
      roles: ['user'],
    });

    expect(component.user()?.email).toBe('ada@example.com');
  });

  it('reports a failure to load the profile', () => {
    http
      .expectOne(`${environment.authAPI}/auth/me`)
      .flush({ detail: 'Not authenticated' }, { status: 401, statusText: 'Unauthorized' });

    expect(component.errorMessage()).toBe('Not authenticated');
  });
});
