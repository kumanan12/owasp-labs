# OWASP Top 10 Security Lab (Angular + Express.js in TypeScript)

This monorepo contains an **Express.js (TypeScript)** backend and an **Angular (TypeScript)** frontend demonstrating **all 10 OWASP Top 10 (2021) security risks**, complete with:
1. **Vulnerable Code & Exploit Payloads**
2. **Secure Code & Remediation Best Practices**

## Repository Structure

- `backend/` — Express.js + TypeScript API containing vulnerable and remediated routes (`src/owasp-examples.ts` and `src/server.ts`).
- `frontend/` — Angular + TypeScript SPA demonstrating client-side vulnerabilities and defenses (`src/app/owasp-lab.component.ts`, `src/app/auth.interceptor.ts`, `src/app/app.config.ts`).

## Quick Start

```bash
# Install dependencies in backend
cd backend && npm install

# Start the Express security lab server
npm run dev
```
