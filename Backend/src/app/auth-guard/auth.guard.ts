import { inject, PLATFORM_ID } from "@angular/core";
import { CanActivateFn, Router } from "@angular/router";
import { AuthService } from "../core/services/auth.service";
import { isPlatformBrowser } from "@angular/common";
import { catchError, map, of } from "rxjs";

export const authGuard: CanActivateFn = () => {
    const authService = inject(AuthService);
    const router = inject(Router);
    const platformId = inject(PLATFORM_ID);

    if (authService.isAuthenticated()) {
        return true;
    }

    if (!isPlatformBrowser(platformId)) {
        return true;
    }

    return authService.tryRefresh().pipe(
        map(() => true),
        catchError(() => {
            router.navigate(['/login'], { queryParams: { returnUrl: router.url }})
            return of(false);
        })
    )
};