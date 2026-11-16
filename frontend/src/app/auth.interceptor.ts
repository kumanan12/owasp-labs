import { HttpInterceptorFn } from '@angular/common/http';

/**
 * VULNERABLE PATTERN (A02 / A07):
 * Reading JWT from `localStorage.getItem('token')` and attaching it manually.
 * If an XSS vulnerability exists anywhere in the app or a 3rd-party script,
 * `localStorage.getItem('token')` can be exfiltrated immediately.
 */
export const vulnerableAuthInterceptor: HttpInterceptorFn = (req, next) => {
  const token = localStorage.getItem('jwt_token');
  if (token) {
    req = req.clone({
      setHeaders: { Authorization: `Bearer ${token}` },
    });
  }
  return next(req);
};

/**
 * SECURE PATTERN (A02 / A07 / A08):
 * 1. Use `withCredentials: true` so the browser automatically sends `HttpOnly; Secure; SameSite=Strict` cookies.
 * 2. Restrict credentialed requests strictly to trusted API origins so cookies/headers are never leaked to 3rd-party URLs.
 */
const TRUSTED_API_ORIGINS = ['http://localhost:3000', 'https://api.example.com'];

export const secureAuthInterceptor: HttpInterceptorFn = (req, next) => {
  const isTrustedOrigin =
    req.url.startsWith('/api') ||
    TRUSTED_API_ORIGINS.some((origin) => req.url.startsWith(origin));

  if (isTrustedOrigin) {
    req = req.clone({
      withCredentials: true,
    });
  }
  return next(req);
};
