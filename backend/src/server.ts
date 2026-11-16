import express, { Request, Response, NextFunction } from 'express';
import cookieParser from 'cookie-parser';
import { applySecureServerConfig, owaspRouter } from './owasp-examples';

const app = express();
const PORT = process.env.PORT || 3000;

// Set default demo JWT secret if not set in environment
process.env.JWT_SECRET = process.env.JWT_SECRET || 'super-long-32-byte-secret-for-owasp-lab-only!';

// 1. Apply OWASP A05 Security Headers & Strict CORS
applySecureServerConfig(app);

// 2. Limit request body size to prevent Denial of Service (DoS)
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// 3. Mount OWASP Top 10 Lab Routes
app.use('/api', owaspRouter);

// 4. Secure Global Error Handler (A05: Never leak stack traces in responses)
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[Internal Error]', err.message);
  res.status(500).json({ error: 'An unexpected error occurred' });
});

app.listen(PORT, () => {
  console.log(`OWASP Security Lab Backend listening on http://localhost:${PORT}`);
});
