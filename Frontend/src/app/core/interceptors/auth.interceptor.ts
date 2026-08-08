import { HttpInterceptorFn, HttpErrorResponse } from "@angular/common/http";
import { inject } from "@angular/core";
import { catchError, switchMap, throwError } from "rxjs";
import { AuthService } from "../services/auth.service";
import { Router } from "@angular/router";

export const authInterceptor: HttpInterceptorFn = (req, next) => {
    const authService = inject(AuthService);
    const router = inject(Router);

    const token = authService.getAccessToken();
    const authReq = token
        ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
        : req;

    return next(authReq).pipe(
        catchError((err: HttpErrorResponse) => {
            // don't try to refresh the refresh call itself, or auth endpoints
            if (err.status === 401 && !req.url.includes('/auth/refresh') && !req.url.includes('/auth/login')) {
                return authService.tryRefresh().pipe(
                    switchMap(() => {
                        const retryToken = authService.getAccessToken();
                        const retryReq = req.clone({ setHeaders: { Authorization: `Bearer ${retryToken}` } });
                        return next(retryReq);
                    }),
                    catchError(refreshErr => {
                        authService.clearAccessToken();
                        router.navigate(['/login']);
                        return throwError(() => refreshErr);
                    })
                );
            }
            return throwError(() => err);
        })
    );
};