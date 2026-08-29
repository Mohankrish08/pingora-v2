import { RenderMode, ServerRoute } from '@angular/ssr';

/**
 * Render modes per route.
 *
 * Anything behind a guard is session-dependent, and a session lives in a cookie
 * the render process does not have. Prerendering those routes bakes a
 * signed-out shell into a static file and, worse, runs the guards at build time
 * where they would fire real HTTP calls at an API that is not running.
 *
 * So: public marketing-style routes are prerendered, everything session-shaped
 * renders on the client.
 */
export const serverRoutes: ServerRoute[] = [
  // Guarded: the answer depends entirely on who is asking.
  {
    path: 'landing',
    renderMode: RenderMode.Client,
  },
  // guestGuard redirects an already-signed-in visitor away from these, which is
  // also a session-dependent decision.
  {
    path: 'login',
    renderMode: RenderMode.Client,
  },
  {
    path: 'register',
    renderMode: RenderMode.Client,
  },
  {
    path: '**',
    renderMode: RenderMode.Prerender,
  },
];
