import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';

import { environment } from '../../../environment/environment';
import { CsrfService } from '../services/csrf.service';

/** Methods that cannot change state, so they need no CSRF proof. */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);

export const csrfInterceptor: HttpInterceptorFn = (req, next) => {
  const csrfService = inject(CsrfService);

  if (SAFE_METHODS.has(req.method.toUpperCase())) {
    return next(req);
  }

  const isOwnApi =
    req.url.startsWith(environment.authAPI) ||
    req.url.startsWith(environment.adminAPI) ||
    req.url.startsWith('/');

  const token = csrfService.getToken();
  if (!token || !isOwnApi) {
    return next(req);
  }

  return next(
    req.clone({
      setHeaders: { [environment.csrfHeaderName]: token },
      withCredentials: true,
    }),
  );
};
