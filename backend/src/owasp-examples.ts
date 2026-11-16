import express, { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { execFile } from 'child_process';
import dns from 'dns/promises';
import pino from 'pino';

export const owaspRouter = express.Router();
const logger = pino({
  redact: ['req.headers.authorization', 'password', 'creditCard'],
});

// Extend Express Request to hold authenticated user info
export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    role: 'user' | 'admin';
  };
}

// Mock database interfaces
interface AccountRecord {
  id: string;
  ownerId: string;
  balance: number;
  email: string;
}

const mockAccounts: AccountRecord[] = [
  { id: '101', ownerId: 'user-1', balance: 5000, email: 'alice@example.com' },
  { id: '102', ownerId: 'user-2', balance: 12500, email: 'bob@example.com' },
];

// ============================================================================
// A01:2021 - Broken Access Control (IDOR & Privilege Escalation)
// ============================================================================

/**
 * VULNERABLE: Insecure Direct Object Reference (IDOR) & Mass Assignment
 * Exploit: User 'user-1' requests GET /api/a01/vulnerable/accounts/102
 * and reads 'user-2's private account details, or passes {"role": "admin"} in body.
 */
owaspRouter.get('/a01/vulnerable/accounts/:accountId', (req: AuthenticatedRequest, res: Response) => {
  const account = mockAccounts.find((a) => a.id === req.params.accountId);
  // Missing ownership check! Any authenticated (or unauthenticated) user can view any account.
  res.json(account);
});

/**
 * SECURE: Enforce Object-Level Authorization & Explicit DTOs
 * Fix: Verify that the authenticated user owns the requested resource or has an admin role.
 */
owaspRouter.get('/a01/secure/accounts/:accountId', (req: AuthenticatedRequest, res: Response) => {
  const currentUser = req.user;
  if (!currentUser) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const account = mockAccounts.find(
    (a) => a.id === req.params.accountId && (a.ownerId === currentUser.id || currentUser.role === 'admin')
  );

  if (!account) {
    // Return 404 or 403 consistently to avoid leaking existence
    return res.status(404).json({ error: 'Account not found' });
  }

  res.json(account);
});

// ============================================================================
// A02:2021 - Cryptographic Failures
// ============================================================================

/**
 * VULNERABLE: Weak Hashing (MD5) without Salt & Hardcoded Secrets
 * Exploit: Rainbow table lookup instantly cracks MD5 hashes.
 */
owaspRouter.post('/a02/vulnerable/register', (req: Request, res: Response) => {
  const { password } = req.body;
  // NEVER use MD5 or SHA1 for passwords
  const weakHash = crypto.createHash('md5').update(password).digest('hex');
  res.json({ storedHash: weakHash });
});

/**
 * SECURE: Adaptive Password Hashing (bcrypt / Argon2id) with Strong Cost Factor
 */
owaspRouter.post('/a02/secure/register', async (req: Request, res: Response) => {
  const { password } = req.body;
  const SALT_ROUNDS = 12;
  const strongHash = await bcrypt.hash(password, SALT_ROUNDS);
  res.json({ storedHash: strongHash });
});

// ============================================================================
// A03:2021 - Injection (SQL Injection & Command Injection)
// ============================================================================

// Simulated SQL Runner
const dbQuery = async (sql: string, params?: unknown[]) => ({ sql, params });

/**
 * VULNERABLE: SQL Injection via String Concatenation
 * Exploit: GET /api/a03/vulnerable/users?email=' OR '1'='1
 */
owaspRouter.get('/a03/vulnerable/users', async (req: Request, res: Response) => {
  const email = req.query.email as string;
  const unsafeSql = `SELECT id, email FROM users WHERE email = '${email}'`;
  const result = await dbQuery(unsafeSql);
  res.json(result);
});

/**
 * SECURE: Parameterized Queries + Strict Input Validation (Zod)
 */
const EmailSearchSchema = z.object({
  email: z.string().email().max(254),
});

owaspRouter.get('/a03/secure/users', async (req: Request, res: Response) => {
  const parsed = EmailSearchSchema.safeParse(req.query);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  const safeSql = 'SELECT id, email FROM users WHERE email = $1';
  const result = await dbQuery(safeSql, [parsed.data.email]);
  res.json(result);
});

/**
 * SECURE vs VULNERABLE OS Command Execution:
 * Instead of `exec('ping -c 1 ' + host)` (vulnerable to `8.8.8.8; cat /etc/passwd`),
 * use `execFile` with an argument array and strict allowlist validation.
 */
owaspRouter.post('/a03/secure/ping', (req: Request, res: Response) => {
  const host = String(req.body.host || '');
  if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
    return res.status(400).json({ error: 'Invalid hostname' });
  }
  execFile('ping', ['-n', '1', host], { timeout: 3000 }, (err, stdout) => {
    if (err) return res.status(500).json({ error: 'Ping failed' });
    res.json({ output: stdout });
  });
});

// ============================================================================
// A04:2021 - Insecure Design (Business Logic Flaws & Race Conditions)
// ============================================================================

/**
 * VULNERABLE: Trusting Client-Supplied Prices & Negative Quantities
 * Exploit: POST {"itemId": "pro-plan", "quantity": -5, "unitPrice": 0.01}
 */
owaspRouter.post('/a04/vulnerable/checkout', (req: Request, res: Response) => {
  const { quantity, unitPrice } = req.body;
  const totalCharged = quantity * unitPrice;
  res.json({ status: 'charged', totalCharged });
});

/**
 * SECURE: Server-Side Price Lookup & Strict Domain Invariants
 */
const CATALOG: Record<string, number> = { 'pro-plan': 9900 }; // in cents

const CheckoutSchema = z.object({
  itemId: z.string(),
  quantity: z.number().int().min(1).max(10),
});

owaspRouter.post('/a04/secure/checkout', (req: Request, res: Response) => {
  const parsed = CheckoutSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const unitPriceCents = CATALOG[parsed.data.itemId];
  if (unitPriceCents === undefined) {
    return res.status(404).json({ error: 'Item not found' });
  }

  const totalCents = unitPriceCents * parsed.data.quantity;
  res.json({ status: 'charged', totalCents });
});

// ============================================================================
// A05:2021 - Security Misconfiguration
// ============================================================================

/**
 * VULNERABLE: Stack Trace Leakage & Wildcard CORS with Credentials
 */
export function vulnerableErrorHandler(err: Error, _req: Request, res: Response, _next: NextFunction) {
  // Leaks internal file paths, library versions, and SQL query details to attackers
  res.status(500).json({
    message: err.message,
    stack: err.stack,
    env: process.env,
  });
}

/**
 * SECURE: Hardened Helmet Headers, Strict CORS Origin Allowlist, Generic Error Responses
 */
export function applySecureServerConfig(app: express.Application) {
  app.disable('x-powered-by');
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          objectSrc: ["'none'"],
          upgradeInsecureRequests: [],
        },
      },
    })
  );
  app.use(
    cors({
      origin: ['http://localhost:4200'],
      methods: ['GET', 'POST', 'PUT', 'DELETE'],
      credentials: true,
    })
  );
}

// ============================================================================
// A07:2021 - Identification and Authentication Failures
// ============================================================================

/**
 * VULNERABLE: No Rate Limiting, JWT 'none' Algorithm Acceptance, Token in URL/localStorage
 */
owaspRouter.post('/a07/vulnerable/login', (req: Request, res: Response) => {
  const { username } = req.body;
  // Weak secret and excessively long expiration
  const token = jwt.sign({ sub: username, role: 'user' }, 'secret123');
  res.json({ token });
});

/**
 * SECURE: Strict Rate Limiting, Explicit JWT Algorithm Verification, HttpOnly Cookie
 */
export const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 failed login requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts, please try again later.' },
});

owaspRouter.post('/a07/secure/login', loginRateLimiter, (req: Request, res: Response) => {
  const { username } = req.body;
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret || jwtSecret.length < 32) {
    throw new Error('Server misconfigured: JWT_SECRET must be at least 32 chars');
  }

  const token = jwt.sign({ sub: username, role: 'user' }, jwtSecret, {
    algorithm: 'HS256',
    expiresIn: '15m',
    issuer: 'owasp-security-lab',
    audience: 'owasp-security-lab-client',
  });

  // Deliver token in an HttpOnly, Secure, SameSite=Strict cookie so XSS cannot steal it
  res.cookie('session_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000,
  });

  res.json({ authenticated: true });
});

// ============================================================================
// A08:2021 - Software and Data Integrity Failures (Prototype Pollution)
// ============================================================================

/**
 * VULNERABLE: Unvalidated Recursive Object Merge (Prototype Pollution)
 * Exploit: POST {"__proto__": {"isAdmin": true}} pollutes Object.prototype across the process!
 */
function unsafeMerge(target: any, source: any) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      unsafeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

owaspRouter.post('/a08/vulnerable/settings', (req: Request, res: Response) => {
  const userSettings = unsafeMerge({}, req.body);
  res.json({ updated: userSettings });
});

/**
 * SECURE: Schema Validation + Blocking Dangerous Prototype Keys
 */
const SettingsSchema = z
  .object({
    theme: z.enum(['light', 'dark']),
    notificationsEnabled: z.boolean(),
  })
  .strict();

owaspRouter.post('/a08/secure/settings', (req: Request, res: Response) => {
  const parsed = SettingsSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid settings payload' });
  }
  res.json({ updated: parsed.data });
});

// ============================================================================
// A09:2021 - Security Logging and Monitoring Failures
// ============================================================================

/**
 * VULNERABLE: Log Injection (CRLF) & Logging Plaintext Secrets
 * Exploit: username = "admin\n[INFO] User admin logged in successfully"
 */
owaspRouter.post('/a09/vulnerable/audit', (req: Request, res: Response) => {
  const { username, password } = req.body;
  // Logs plaintext password and allows newline injection to forge log entries!
  console.log(`[AUTH] Login failed for user ${username} with password ${password}`);
  res.status(401).json({ error: 'Invalid credentials' });
});

/**
 * SECURE: Structured JSON Logging with Automatic Secret Redaction
 */
owaspRouter.post('/a09/secure/audit', (req: Request, res: Response) => {
  const { username } = req.body;
  logger.warn(
    {
      event: 'AUTH_LOGIN_FAILED',
      username: String(username).replace(/[\r\n]/g, ''),
      ip: req.ip,
    },
    'Authentication attempt failed'
  );
  res.status(401).json({ error: 'Invalid credentials' });
});

// ============================================================================
// A10:2021 - Server-Side Request Forgery (SSRF)
// ============================================================================

/**
 * VULNERABLE: Unvalidated Server-Side Fetch
 * Exploit: POST {"avatarUrl": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
 * Steals cloud IAM credentials or scans internal VPC services!
 */
owaspRouter.post('/a10/vulnerable/fetch-avatar', async (req: Request, res: Response) => {
  const { avatarUrl } = req.body;
  const response = await fetch(avatarUrl);
  const data = await response.text();
  res.send(data);
});

/**
 * SECURE: Strict Domain Allowlist, HTTPS Enforcement, and Private IP Rejection
 */
const ALLOWED_AVATAR_HOSTS = new Set(['images.example.com', 'cdn.example.com']);

function isPrivateIPv4(ip: string): boolean {
  return (
    ip.startsWith('10.') ||
    ip.startsWith('127.') ||
    ip.startsWith('169.254.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
    ip === '0.0.0.0'
  );
}

owaspRouter.post('/a10/secure/fetch-avatar', async (req: Request, res: Response) => {
  try {
    const parsedUrl = new URL(String(req.body.avatarUrl));

    if (parsedUrl.protocol !== 'https:') {
      return res.status(400).json({ error: 'Only HTTPS URLs are permitted' });
    }

    if (!ALLOWED_AVATAR_HOSTS.has(parsedUrl.hostname)) {
      return res.status(400).json({ error: 'Hostname not in allowlist' });
    }

    const resolvedAddresses = await dns.resolve4(parsedUrl.hostname);
    if (resolvedAddresses.some(isPrivateIPv4)) {
      return res.status(400).json({ error: 'Internal/private IP addresses are forbidden' });
    }

    const response = await fetch(parsedUrl.toString(), { redirect: 'error' });
    const buffer = await response.arrayBuffer();
    res.type(response.headers.get('content-type') || 'image/png').send(Buffer.from(buffer));
  } catch {
    res.status(400).json({ error: 'Invalid or unreachable URL' });
  }
});
