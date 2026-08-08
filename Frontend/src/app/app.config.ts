import { ApplicationConfig, inject, PLATFORM_ID, provideAppInitializer } from '@angular/core';
import { provideRouter } from '@angular/router';

import { routes } from './app.routes';
import { csrfInterceptor } from './core/interceptors/csrf.interceptor';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { AuthService } from './core/services/auth.service';
import { isPlatformBrowser } from '@angular/common';
import { catchError, firstValueFrom, of } from 'rxjs';
import { authInterceptor } from './core/interceptors/auth.interceptor';

export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes),
    provideHttpClient(withInterceptors([csrfInterceptor, authInterceptor])),
    provideAppInitializer(() => {
      const authService = inject(AuthService);
      const platformId = inject(PLATFORM_ID);

      if (!isPlatformBrowser(platformId)) return Promise.resolve();
      return firstValueFrom(authService.tryRefresh().pipe(catchError(() => of(null))));
    }),
  ],
};