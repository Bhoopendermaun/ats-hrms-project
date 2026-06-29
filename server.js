import express from 'express';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import 'dotenv/config';
import swaggerUi from 'swagger-ui-express';
import yaml from 'yamljs'; 

// 1. SECURITY & PROJECT IMPORTS
import { logSecurityEvent } from './logger.js';
import { authenticate } from './src/middleware/auth.js'; 
import adminRoutes from './src/routes/adminRoutes.js'; 

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// --- 2. MIDDLEWARE STACK ---
app.use(express.json()); 
app.use(cookieParser());
const swaggerDocument = yaml.load(join(__dirname, 'docs/openapi/oauth.yaml'));
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
app.use(express.static('public'));

// --- 3. API ROUTES (Protected) ---
// AC Check: Admin APIs secured via 'authenticate' and role-checks
app.use('/api/admin', authenticate, adminRoutes);

// Test Canary: Used to verify the 'DEACTIVATED' kill-switch in tests
app.get('/api/ping', authenticate, (req, res) => res.json({ message: "pong" }));

// --- 4. OAUTH INITIATION (Hardened Logging) ---
app.get('/auth/google', (req, res) => {
    const state = "xyz" + Math.random().toString(36).substring(7);
    logSecurityEvent('AUTH_INIT', { provider: 'Google', state }); 
    res.redirect(`/auth/callback?status=success&role=ADMIN&state=${state}`);
});

app.get('/auth/microsoft', (req, res) => {
    const state = "abc" + Math.random().toString(36).substring(7);
    logSecurityEvent('AUTH_INIT', { provider: 'Microsoft', state });
    res.redirect(`/auth/callback?status=success&role=USER&state=${state}`);
});

// --- 5. OAUTH CALLBACK (Security Monitor) ---
app.get('/auth/callback', (req, res) => {
    const { status, role, error } = req.query;
    const userIP = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const identity = status === 'success' ? 'OAuth_User' : 'Unknown_Attacker';

    if (status === 'success' && role) {
        logSecurityEvent('LOGIN_SUCCESS', identity, role, 'AUTHORIZED', userIP);
        res.cookie('session_token', 'secure-jwt-token-123', { httpOnly: true });

        if (role === 'ADMIN') {
            return res.redirect('/admin-dashboard.html');
        } else {
            return res.redirect('/user-dashboard.html');
        }
    }

    logSecurityEvent('LOGIN_FAILURE', identity, 'NONE', error || 'DENIED', userIP);
    res.redirect(`/?error=${error || 'Authentication Failed'}`);
});

// --- 6. SESSION TERMINATION ---
app.get('/logout', (req, res) => {
    const userIP = req.ip || req.socket.remoteAddress;
    logSecurityEvent('LOGOUT', 'OAuth_User', 'NONE', 'SESSION_TERMINATED', userIP);
    res.clearCookie('session_token');
    res.redirect('/');
});

// --- 7. SERVER INITIALIZATION ---
const PORT = process.env.PORT || 5000;

// NODE_ENV check prevents "Port in Use" errors during testing
if (process.env.NODE_ENV !== 'test') {
    app.listen(PORT, () => {
        console.log(`🚀 Server running at http://localhost:${PORT}`);
        console.log(`🛡️  Audit System: Active`);
    });
}

// CRITICAL: Required for supertest in tests/admin_management.test.js
export default app;
