import { HttpInterceptorFn } from "@angular/common/http"
import { inject } from "@angular/core"
import { CsrfService } from "../services/csrf.service"

const CSRF_SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE'])

export const csrfInterceptor: HttpInterceptorFn = (req, next) => {
    const csrfService = inject(CsrfService)

    if (CSRF_SAFE_METHODS.has(req.method)) {
        return next(req)
    }

    const token = csrfService.getToken()
    if (!token) {
        return next(req)
    }

    const cloned = req.clone({
        setHeaders: { 'X-CSRF-Token': token },
    });

    return next(cloned);
}