import { ApplicationConfig } from '@angular/core';
import { provideHttpClient, withInterceptors, withXsrfConfiguration } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { secureAuthInterceptor } from './auth.interceptor';
import { OwaspLabComponent } from './owasp-lab.component';

/**
 * SECURE ANGULAR APPLICATION CONFIGURATION:
 * - Enables automatic CSRF/XSRF token handling (`withXsrfConfiguration`)
 * - Uses `secureAuthInterceptor` for `HttpOnly` cookie credentials on trusted origins
 */
export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter([{ path: '**', component: OwaspLabComponent }]),
    provideHttpClient(
      withInterceptors([secureAuthInterceptor]),
      withXsrfConfiguration({
        cookieName: 'XSRF-TOKEN',
        headerName: 'X-XSRF-TOKEN',
      })
    ),
  ],
};
