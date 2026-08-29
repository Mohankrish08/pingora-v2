import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { catchError, map, of } from 'rxjs';

import { AuthService } from '../core/services/auth.service';

export const guestGuard: CanActivateFn = () => {
  const authService = inject(AuthService);
  const router = inject(Router);

  const alreadyIn = () => router.createUrlTree(['/landing']);

  if (authService.isAuthenticated()) {
    return alreadyIn();
  }

  if (authService.isReady()) {
    return true;
  }

  return authService.refresh().pipe(
    map(() => alreadyIn()),
    catchError(() => of(true as const)),
  );
};
