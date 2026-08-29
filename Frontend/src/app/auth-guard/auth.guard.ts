import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { catchError, map, of } from 'rxjs';

import { AuthService } from '../core/services/auth.service';

export const authGuard: CanActivateFn = (_route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authService.isAuthenticated()) {
    return true;
  }

  const denied = () =>
    router.createUrlTree(['/login'], {
      queryParams: { returnUrl: state.url },
    });

  return authService.refresh().pipe(
    map(() => true as const),
    catchError(() => of(denied())),
  );
};
