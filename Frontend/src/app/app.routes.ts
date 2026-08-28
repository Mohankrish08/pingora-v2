import { Routes } from '@angular/router';
import { authGuard } from './auth-guard/auth.guard';
import { guestGuard } from './auth-guard/guest.guard';

export const routes: Routes = [


    // ==========================
    // Public Routes
    // ==========================
    {
        path: '',
        redirectTo: 'login',
        pathMatch: 'full'
    },
    {
        path: 'login',
        canActivate: [guestGuard],
        loadComponent: () =>
            import('./features/auth/login/loginComponent')
                .then(m => m.LoginComponent)
    },
    {
        path: 'register',
        canActivate: [guestGuard],
        loadComponent: () =>
            import('./features/auth/register/register')
                .then(m => m.RegisterComponent)
    },

    // ==========================
    // Protected Routes
    // ==========================
    {
        path: 'landing',
        canActivate: [authGuard],
        loadComponent: () =>
            import('./features/landing-page/landing-page')
                .then(m => m.LandingPage)
    }
];

