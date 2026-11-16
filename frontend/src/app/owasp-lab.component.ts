import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { Router } from '@angular/router';

@Component({
  selector: 'app-owasp-lab',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <main class="lab-container">
      <h1>OWASP Top 10 Security Lab (Angular + Express)</h1>

      <!-- A03: Cross-Site Scripting (XSS) via DomSanitizer -->
      <section class="card">
        <h2>A03:2021 - Injection (Cross-Site Scripting in Angular)</h2>
        <label>
          Comment Input (Try: <code>&lt;img src=x onerror="alert('XSS')"&gt;</code>):
          <input [(ngModel)]="userInput" />
        </label>

        <div class="comparison">
          <div class="vulnerable">
            <h3>Vulnerable (bypassSecurityTrustHtml)</h3>
            <div [innerHTML]="getVulnerableHtml()"></div>
          </div>
          <div class="secure">
            <h3>Secure (Default Angular Interpolation / Sanitization)</h3>
            <div>{{ userInput }}</div>
          </div>
        </div>
      </section>

      <!-- A01: Open Redirect vs Safe Internal Navigation -->
      <section class="card">
        <h2>A01:2021 - Broken Access Control (Open Redirect)</h2>
        <button (click)="vulnerableRedirect('https://evil-phishing.example.com')">
          Trigger Vulnerable Redirect
        </button>
        <button (click)="secureRedirect('https://evil-phishing.example.com')">
          Trigger Secure Redirect (Blocked)
        </button>
      </section>
    </main>
  `,
})
export class OwaspLabComponent {
  private sanitizer = inject(DomSanitizer);
  private router = inject(Router);

  userInput = '<img src="x" onerror="console.warn(\'XSS Executed!\')">';

  /**
   * VULNERABLE (A03 - XSS):
   * Disabling Angular's built-in DOM sanitization on untrusted user input
   * allows arbitrary JavaScript execution in the victim's browser.
   */
  getVulnerableHtml(): SafeHtml {
    return this.sanitizer.bypassSecurityTrustHtml(this.userInput);
  }

  /**
   * VULNERABLE (A01 - Open Redirect):
   * Redirecting directly to an unvalidated query parameter (`?returnUrl=https://evil.com`)
   * allows attackers to craft convincing phishing links.
   */
  vulnerableRedirect(returnUrl: string): void {
    window.location.href = returnUrl;
  }

  /**
   * SECURE (A01 - Safe Internal Redirect):
   * Enforce relative internal paths starting with a single `/` (not `//evil.com`)
   * and navigate via Angular Router.
   */
  secureRedirect(returnUrl: string): void {
    const isInternalPath = returnUrl.startsWith('/') && !returnUrl.startsWith('//');
    if (isInternalPath) {
      this.router.navigateByUrl(returnUrl);
    } else {
      this.router.navigate(['/dashboard']);
    }
  }
}
