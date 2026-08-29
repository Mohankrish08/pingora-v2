import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, switchMap, throwError } from 'rxjs';

import { AuthService } from '../services/auth.service';

const NO_RETRY = ['/auth/login', '/auth/refresh', '/auth/register', '/auth/verify-totp'];

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  const withAuth = (token: string | null) =>
    token
      ? req.clone({
          setHeaders: { Authorization: `Bearer ${token}` },
          withCredentials: true,
        })
      : req.clone({ withCredentials: true });

  return next(withAuth(authService.getAccessToken())).pipe(
    catchError((error: HttpErrorResponse) => {
      const isAuthEndpoint = NO_RETRY.some((path) => req.url.includes(path));

      if (error.status !== 401 || isAuthEndpoint) {
        return throwError(() => error);
      }

      return authService.refresh().pipe(
        switchMap(() => next(withAuth(authService.getAccessToken()))),
        catchError((refreshError) => {
          router.navigate(['/login'], {
            queryParams: { returnUrl: router.url },
          });
          return throwError(() => refreshError);
        }),
      );
    }),
  );
};
