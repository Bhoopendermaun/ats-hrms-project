import express from 'express';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';
// 1. IMPORT THE LOGGER
import { logSecurityEvent } from './logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

app.use(cookieParser());
app.use(express.static('public'));

// --- 1. OAuth Initiation (SIMULATED) ---
app.get('/auth/google', (req, res) => {
    res.redirect('/auth/callback?status=success&role=ADMIN');
});

app.get('/auth/microsoft', (req, res) => {
    res.redirect('/auth/callback?status=success&role=USER');
});

// --- 2. The Callback Handler (Security Monitor) ---
app.get('/auth/callback', (req, res) => {
    const { status, role, error } = req.query;

    // --- CAPTURE THE FORENSICS ---
    const userIP = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const identity = status === 'success' ? 'OAuth_User' : 'Unknown_Attacker';

    if (status === 'success' && role) {
        // Pass identity and IP to the logger
        logSecurityEvent('LOGIN_SUCCESS', identity, role, 'AUTHORIZED', userIP);

        res.cookie('session_token', 'secure-jwt-token-123', { httpOnly: true });

        if (role === 'ADMIN') {
            return res.redirect('/admin-dashboard.html');
        } else {
            return res.redirect('/user-dashboard.html');
        }
    }

    // Capture the failure with IP
    logSecurityEvent('LOGIN_FAILURE', identity, 'NONE', error || 'DENIED', userIP);
    res.redirect(`/?error=${error || 'Authentication Failed'}`);
});

// --- 3. Logout ---
app.get('/logout', (req, res) => {
    const userIP = req.ip || req.socket.remoteAddress;
    logSecurityEvent('LOGOUT', 'OAuth_User', 'NONE', 'SESSION_TERMINATED', userIP);
    res.clearCookie('session_token');
    res.redirect('/');
});

const PORT = 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
    console.log(`🛡️  Audit System: Active`);
});
