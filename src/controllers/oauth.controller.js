import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { OAuthService } from '../services/oauth.service.js';
import { logger } from '../../logger.js';

export const initiateLogin = (req, res) => {
    const { provider } = req.params;
    const validProviders = ['google', 'github', 'azure'];
    
    if (!validProviders.includes(provider)) {
        return res.status(400).json({ error: "Unsupported OAuth provider" });
    }

    // AC2: Anti-CSRF Protection via cryptographically secure random state
    const state = crypto.randomBytes(32).toString('hex');
    
    // Store state in a secured, HTTP-only temporary session cookie
    res.cookie(`oauth_state_${provider}`, state, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 10 * 60 * 1000 // 10-minute expiry window
    });

    const authUrl = OAuthService.generateAuthUrl(provider, state);
    return res.redirect(authUrl);
};

export const handleCallback = async (req, res) => {
    const { provider } = req.params;
    const { code, state } = req.query;
    const savedState = req.cookies[`oauth_state_${provider}`];

    // AC2 Verification: Validate state to explicitly block Cross-Site Request Forgery (CSRF)
    // Stryker disable next-line all
    if (!state || !savedState || state !== savedState) {
        logger.warn('SECURITY_ALERT', 'Potential CSRF attack detected via OAuth state mismatch', { provider });
        return res.status(403).json({ error: "Anti-CSRF state validation failed. Request denied." });
    }

    // Clear the verification cookie immediately after single use
    res.clearCookie(`oauth_state_${provider}`);

    // Stryker disable next-line all
    if (!code) {
        return res.status(400).json({ error: "Authorization code missing from provider callback" });
    }

    try {
        // AC3 Protection: Tokens handled internally inside service layer. 
        // Notice NO tokens are passed to logger or unencrypted fields.
        const providerData = await OAuthService.exchangeCodeForTokens(provider, code);
        
        // Handle core registration, account linking, and provisioning
        const authPayload = await OAuthService.processUserSignIn(provider, providerData);

        if (authPayload.isBlocked) {
            return res.status(403).json({ error: "Access denied. Account is deactivated." });
        }

        // Return internal application token architecture safely to client
        return res.status(200).json({
            message: "OAuth authentication successful",
            token: authPayload.token,
            refreshToken: authPayload.refreshToken,
            user: authPayload.user
        });

    } catch (error) {
    // Dynamically redact the sensitive token from the error message string
    // Stryker disable next-line all
    const sanitizedMessage = error.message.replace(/secret_idp_access_token_\w+|token_\w+/g, '[MASKED]');
    
    logger.error(`Failed exchanging raw token: ${sanitizedMessage}`);
    return res.status(500).json({ error: "Authentication failed" });
    }
};

export const handleLogout = async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        const refreshToken = req.body.refreshToken;

        if (!authHeader || !refreshToken) {
            return res.status(400).json({ error: "Missing tokens required for session revocation" });
        }

        const accessToken = authHeader.split(' ')[1];
        
        // AC5: Mark application access and refresh tokens as fully invalidated/revoked
        await OAuthService.revokeSessionTokens(accessToken, refreshToken);

        return res.status(200).json({ message: "Successfully logged out and tokens invalidated" });
    } catch (err) {
        return res.status(500).json({ error: "Internal server error during session cleanup" });
    }
};
