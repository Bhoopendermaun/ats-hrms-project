import { jest } from '@jest/globals';

// 1. Setup absolute mock definitions before importing the controller
jest.unstable_mockModule('../src/services/oauth.service.js', () => ({
    OAuthService: {
        generateAuthUrl: jest.fn(),
        exchangeCodeForTokens: jest.fn(),
        processUserSignIn: jest.fn(),
        revokeSessionTokens: jest.fn()
    }
}));

jest.unstable_mockModule('../logger.js', () => ({
    logger: {
        warn: jest.fn(),
        error: jest.fn(),
        info: jest.fn()
    }
}));

// Import modules after applying structural mocks
const { OAuthService } = await import('../src/services/oauth.service.js');
const { logger } = await import('../logger.js');
const { initiateLogin, handleCallback, handleLogout } = await import('../src/controllers/oauth.controller.js');

describe('OAuth Controller - Security & Mutation Protection Suite', () => {
    let req;
    let res;
    let next;

    beforeEach(() => {
        jest.clearAllMocks();
        process.env.NODE_ENV = 'development';

        // Express Request Mock
        req = {
            params: {},
            query: {},
            cookies: {},
            headers: {},
            body: {}
        };

        // Express Response Mock with strict chain fluent methods
        res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis(),
            cookie: jest.fn().mockReturnThis(),
            clearCookie: jest.fn().mockReturnThis(),
            redirect: jest.fn().mockReturnThis()
        };

        next = jest.fn();
    });

    describe('initiateLogin', () => {
        test('should reject unsupported third-party OAuth providers with 400', () => {
            req.params.provider = 'invalid_provider';

            initiateLogin(req, res);

            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ error: "Unsupported OAuth provider" });
            expect(res.redirect).not.toHaveBeenCalled();
        });

        test('should establish cryptographically secure random state and store cookie', () => {
            req.params.provider = 'google';
            OAuthService.generateAuthUrl.mockReturnValue('https://mock-auth-url.com');

            initiateLogin(req, res);

            // Verify a state cookie was dropped with explicit security configs
            expect(res.cookie).toHaveBeenCalledWith(
                'oauth_state_google',
                expect.any(String),
                expect.objectContaining({
                    httpOnly: true,
                    sameSite: 'lax'
                })
            );

            // Grab the exact generated state to ensure it was passed to the redirect URL generator
            const generatedState = res.cookie.mock.calls[0][1];
            expect(generatedState).toHaveLength(64); // 32 bytes hex = 64 characters
            expect(OAuthService.generateAuthUrl).toHaveBeenCalledWith('google', generatedState);
            expect(res.redirect).toHaveBeenCalledWith('https://mock-auth-url.com');
        });

        test('should enforce secure configuration setting flags when running in production environments', () => {
            process.env.NODE_ENV = 'production';
            req.params.provider = 'github';

            initiateLogin(req, res);

            // Kills BooleanLiteral mutation on secure property logic
            expect(res.cookie).toHaveBeenCalledWith(
                'oauth_state_github',
                expect.any(String),
                expect.objectContaining({ secure: true })
            );
        });
    });

    describe('handleCallback', () => {
        test('should aggressively block requests when state configuration parameters are missing or unmatched (CSRF Defense)', async () => {
            req.params.provider = 'google';
            req.query.state = 'attacker_state_value';
            req.cookies['oauth_state_google'] = 'legitimate_state_value'; // Mismatch

            await handleCallback(req, res);

            // Strict structural verification kills true/false statement deviations
            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith({ error: "Anti-CSRF state validation failed. Request denied." });
            expect(logger.warn).toHaveBeenCalledWith('SECURITY_ALERT', 'Potential CSRF attack detected via OAuth state mismatch', { provider: 'google' });
            expect(OAuthService.exchangeCodeForTokens).not.toHaveBeenCalled();
        });

        test('should clear anti-CSRF token verification cookies instantly upon execution evaluation', async () => {
            req.params.provider = 'google';
            req.query.state = 'secure_state_token';
            req.cookies['oauth_state_google'] = 'secure_state_token'; // Exact match
            req.query.code = ''; // Force breakdown on code check next

            await handleCallback(req, res);

            // Verification cookie MUST be flushed immediately to prevent replay vectors
            expect(res.clearCookie).toHaveBeenCalledWith('oauth_state_google');
            expect(res.status).toHaveBeenCalledWith(400);
        });

        test('should decline processing if identity provider token authorization code parameter is missing', async () => {
            req.params.provider = 'google';
            req.query.state = 'valid_state';
            req.cookies['oauth_state_google'] = 'valid_state';
            req.query.code = undefined; // Missing code

            await handleCallback(req, res);

            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ error: "Authorization code missing from provider callback" });
        });

        test('should issue token payload response upon successful end-to-end OAuth flow coordination', async () => {
            req.params.provider = 'google';
            req.query.state = 'match';
            req.cookies['oauth_state_google'] = 'match';
            req.query.code = 'valid_auth_code';

            const mockTokens = { access_token: 'secret_idp_token', email: 'test@semo.edu' };
            const mockAuthPayload = {
                isBlocked: false,
                token: 'app_access_jwt',
                refreshToken: 'app_refresh_jwt',
                user: { id: 'usr_123', role: 'USER' }
            };

            OAuthService.exchangeCodeForTokens.mockResolvedValue(mockTokens);
            OAuthService.processUserSignIn.mockResolvedValue(mockAuthPayload);

            await handleCallback(req, res);

            expect(OAuthService.exchangeCodeForTokens).toHaveBeenCalledWith('google', 'valid_auth_code');
            expect(OAuthService.processUserSignIn).toHaveBeenCalledWith('google', mockTokens);
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({
                message: "OAuth authentication successful",
                token: 'app_access_jwt',
                refreshToken: 'app_refresh_jwt',
                user: { id: 'usr_123', role: 'USER' }
            });
        });

        test('should block authentication pipelines and reject with 403 status if account flag is deactivated', async () => {
            req.params.provider = 'google';
            req.query.state = 'match';
            req.cookies['oauth_state_google'] = 'match';
            req.query.code = 'auth_code';

            OAuthService.exchangeCodeForTokens.mockResolvedValue({});
            OAuthService.processUserSignIn.mockResolvedValue({ isBlocked: true }); // Disabled user block target

            await handleCallback(req, res);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith({ error: "Access denied. Account is deactivated." });
        });

        test('should systematically mask third-party raw tokens from transport logging structures during transaction exceptions', async () => {
            req.params.provider = 'google';
            req.query.state = 'match';
            req.cookies['oauth_state_google'] = 'match';
            req.query.code = 'malicious_or_expired_code';

            // Throw error from exchange sequence containing raw key components
            const secretLeakError = new Error('Failed exchanging raw token secret_idp_access_token_123');
            OAuthService.exchangeCodeForTokens.mockRejectedValue(secretLeakError);

            await handleCallback(req, res);

            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith({ error: "Authentication failed" });

            // AC3 Check: Guard against mutation variants that accidentally log unredacted error parameters
            const logCallArgs = logger.error.mock.calls[0];
            const logOutputString = JSON.stringify(logCallArgs);
            expect(logOutputString).toContain('[MASKED]');
            expect(logOutputString).not.toContain('secret_idp_access_token_123');
        });
    });

    describe('handleLogout', () => {
        test('should require both access authentication authorization header and reference refresh tokens to proceed', async () => {
            req.headers.authorization = undefined;
            req.body.refreshToken = 'refresh_token_string';

            await handleLogout(req, res);

            expect(res.status).toHaveBeenCalledWith(400);
            expect(res.json).toHaveBeenCalledWith({ error: "Missing tokens required for session revocation" });
            expect(OAuthService.revokeSessionTokens).not.toHaveBeenCalled();
        });

        test('should capture individual keys and pass them into the underlying revocation engine mechanisms', async () => {
            req.headers.authorization = 'Bearer primary_access_jwt_abc';
            req.body.refreshToken = 'associated_refresh_jwt_xyz';

            OAuthService.revokeSessionTokens.mockResolvedValue(true);

            await handleLogout(req, res);

            // Kills split index mutations or wrong field indexing bugs
            expect(OAuthService.revokeSessionTokens).toHaveBeenCalledWith(
                'primary_access_jwt_abc',
                'associated_refresh_jwt_xyz'
            );
            expect(res.status).toHaveBeenCalledWith(200);
            expect(res.json).toHaveBeenCalledWith({ message: "Successfully logged out and tokens invalidated" });
        });

        test('should securely return 500 status codes when underlying service blocklist engines experience runtime errors', async () => {
            req.headers.authorization = 'Bearer access';
            req.body.refreshToken = 'refresh';
            OAuthService.revokeSessionTokens.mockRejectedValue(new Error('Database tracking down'));

            await handleLogout(req, res);

            expect(res.status).toHaveBeenCalledWith(500);
            expect(res.json).toHaveBeenCalledWith({ error: "Internal server error during session cleanup" });
        });
    });

describe('OAuth Controller - Final Mutant Killers', () => {

    beforeEach(() => {
        jest.clearAllMocks();
        process.env.NODE_ENV = 'development';
        req = {
            params: {}, query: {}, cookies: {},
            headers: {}, body: {}
        };
        res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis(),
            cookie: jest.fn().mockReturnThis(),
            clearCookie: jest.fn().mockReturnThis(),
            redirect: jest.fn().mockReturnThis()
        };
    });

    // Kills: validProviders exact array contents mutations
    test('should accept all three valid providers exactly', () => {
        ['google', 'github', 'azure'].forEach(provider => {
            jest.clearAllMocks();
            req.params.provider = provider;
            OAuthService.generateAuthUrl.mockReturnValue('https://mock.com');
            initiateLogin(req, res);
            expect(res.redirect).toHaveBeenCalled();
            expect(res.status).not.toHaveBeenCalledWith(400);
        });
    });

    // Kills: maxAge 10 * 60 * 1000 number literal mutations
    test('cookie maxAge should be exactly 600000ms (10 minutes)', () => {
        req.params.provider = 'google';
        OAuthService.generateAuthUrl.mockReturnValue('https://mock.com');
        initiateLogin(req, res);
        expect(res.cookie).toHaveBeenCalledWith(
            'oauth_state_google',
            expect.any(String),
            expect.objectContaining({ maxAge: 600000 })
        );
    });

    // Kills: secure: false in development mutations
    test('cookie secure should be false in development', () => {
        process.env.NODE_ENV = 'development';
        req.params.provider = 'google';
        OAuthService.generateAuthUrl.mockReturnValue('https://mock.com');
        initiateLogin(req, res);
        expect(res.cookie).toHaveBeenCalledWith(
            'oauth_state_google',
            expect.any(String),
            expect.objectContaining({ secure: false })
        );
    });

    // Kills: sameSite 'lax' string literal mutations
    test('cookie sameSite should be exactly lax', () => {
        req.params.provider = 'azure';
        OAuthService.generateAuthUrl.mockReturnValue('https://mock.com');
        initiateLogin(req, res);
        expect(res.cookie).toHaveBeenCalledWith(
            'oauth_state_azure',
            expect.any(String),
            expect.objectContaining({ sameSite: 'lax', httpOnly: true })
        );
    });

    // Kills: !state || !savedState → AND mutations
    test('should block when state is missing but savedState exists', async () => {
        req.params.provider = 'google';
        req.query.state = undefined;
        req.cookies['oauth_state_google'] = 'valid_state';
        await handleCallback(req, res);
        expect(res.status).toHaveBeenCalledWith(403);
    });

    test('should block when savedState is missing but state exists', async () => {
        req.params.provider = 'google';
        req.query.state = 'some_state';
        req.cookies['oauth_state_google'] = undefined;
        await handleCallback(req, res);
        expect(res.status).toHaveBeenCalledWith(403);
    });

    // Kills: state !== savedState → === mutations
    test('should allow when state and savedState match exactly', async () => {
        req.params.provider = 'google';
        req.query.state = 'exact_match';
        req.cookies['oauth_state_google'] = 'exact_match';
        req.query.code = 'code123';
        OAuthService.exchangeCodeForTokens.mockResolvedValue({});
        OAuthService.processUserSignIn.mockResolvedValue({
            isBlocked: false,
            token: 'tok',
            refreshToken: 'ref',
            user: { id: '1' }
        });
        await handleCallback(req, res);
        expect(res.status).toHaveBeenCalledWith(200);
    });

    // Kills: authHeader.split(' ')[1] index mutations
    test('handleLogout should extract token at index 1 of split', async () => {
        req.headers.authorization = 'Bearer exact_access_token_value';
        req.body.refreshToken = 'exact_refresh_token_value';
        OAuthService.revokeSessionTokens.mockResolvedValue(true);
        await handleLogout(req, res);
        expect(OAuthService.revokeSessionTokens).toHaveBeenCalledWith(
            'exact_access_token_value',
            'exact_refresh_token_value'
        );
    });

    // Kills: !authHeader AND !refreshToken OR mutations
    test('handleLogout should block when only refreshToken is missing', async () => {
        req.headers.authorization = 'Bearer token';
        req.body.refreshToken = undefined;
        await handleLogout(req, res);
        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.json).toHaveBeenCalledWith({ error: "Missing tokens required for session revocation" });
    });

    // Kills: regex pattern mutations in sanitizedMessage
    test('should mask token_ pattern in error messages', async () => {
        req.params.provider = 'google';
        req.query.state = 'match';
        req.cookies['oauth_state_google'] = 'match';
        req.query.code = 'code';
        OAuthService.exchangeCodeForTokens.mockRejectedValue(
            new Error('Error with token_abc123 exposed')
        );
        await handleCallback(req, res);
        const logOutput = JSON.stringify(logger.error.mock.calls[0]);
        expect(logOutput).toContain('[MASKED]');
        expect(logOutput).not.toContain('token_abc123');
    });

    // Kills: 200/400/403/500 status code number mutations
    test('handleLogout exact 200 response shape on success', async () => {
        req.headers.authorization = 'Bearer tok';
        req.body.refreshToken = 'ref';
        OAuthService.revokeSessionTokens.mockResolvedValue(true);
        await handleLogout(req, res);
        expect(res.status).toHaveBeenCalledWith(200);
        expect(res.json).toHaveBeenCalledWith({ message: "Successfully logged out and tokens invalidated" });
    });

// Kills: !state || !savedState || state !== savedState LogicalOperator/ConditionalExpression
    test('should block when all three state conditions fail independently', async () => {
        // state missing
        req.params.provider = 'google';
        req.query.state = undefined;
        req.cookies['oauth_state_google'] = undefined;
        await handleCallback(req, res);
        expect(res.status).toHaveBeenCalledWith(403);
    });

    // Kills: !code ConditionalExpression/StringLiteral line 41
    test('should return exact 400 error when code is empty string', async () => {
        req.params.provider = 'google';
        req.query.state = 'st';
        req.cookies['oauth_state_google'] = 'st';
        req.query.code = '';
        await handleCallback(req, res);
        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.json).toHaveBeenCalledWith({
            error: 'Authorization code missing from provider callback'
        });
    });

    // Kills: Regex mutations line 69 — three regex patterns
    test('should mask secret_idp_access_token_ pattern exactly', async () => {
        req.params.provider = 'google';
        req.query.state = 'st';
        req.cookies['oauth_state_google'] = 'st';
        req.query.code = 'code';
        OAuthService.exchangeCodeForTokens.mockRejectedValue(
            new Error('secret_idp_access_token_ABC leaked here')
        );
        await handleCallback(req, res);
        const logArg = logger.error.mock.calls[0][0];
        expect(logArg).toContain('[MASKED]');
        expect(logArg).not.toContain('secret_idp_access_token_ABC');
    });

    test('should mask token_ pattern with word characters exactly', async () => {
        req.params.provider = 'google';
        req.query.state = 'st';
        req.cookies['oauth_state_google'] = 'st';
        req.query.code = 'code';
        OAuthService.exchangeCodeForTokens.mockRejectedValue(
            new Error('token_xyz789 was exposed in error')
        );
        await handleCallback(req, res);
        const logArg = logger.error.mock.calls[0][0];
        expect(logArg).toContain('[MASKED]');
        expect(logArg).not.toContain('token_xyz789');
    });

    test('should NOT mask unrelated words — only token patterns', async () => {
        req.params.provider = 'google';
        req.query.state = 'st';
        req.cookies['oauth_state_google'] = 'st';
        req.query.code = 'code';
        OAuthService.exchangeCodeForTokens.mockRejectedValue(
            new Error('generic error occurred')
        );
        await handleCallback(req, res);
        const logArg = logger.error.mock.calls[0][0];
        expect(logArg).toContain('generic error occurred');
        expect(logArg).not.toContain('[MASKED]');
    });
});

describe('OAuth Controller - Deep Surgical Mutant Killers', () => {

    beforeEach(() => {
        jest.clearAllMocks();
        process.env.NODE_ENV = 'development';
        req = { params: {}, query: {}, cookies: {}, headers: {}, body: {} };
        res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis(),
            cookie: jest.fn().mockReturnThis(),
            clearCookie: jest.fn().mockReturnThis(),
            redirect: jest.fn().mockReturnThis()
        };
    });

    // Kills: validProviders array content mutations
    test('should reject provider not in exact list — FACEBOOK not valid', () => {
        req.params.provider = 'facebook';
        initiateLogin(req, res);
        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.json).toHaveBeenCalledWith({ error: 'Unsupported OAuth provider' });
    });

    // Kills: cookie name template literal mutations
    test('cookie name must include provider name exactly', () => {
        req.params.provider = 'github';
        OAuthService.generateAuthUrl.mockReturnValue('https://mock.com');
        initiateLogin(req, res);
        expect(res.cookie.mock.calls[0][0]).toBe('oauth_state_github');
    });

    // Kills: clearCookie name mutations
    test('clearCookie must use exact provider-specific cookie name', async () => {
        req.params.provider = 'azure';
        req.query.state = 'st';
        req.cookies['oauth_state_azure'] = 'st';
        req.query.code = '';
        await handleCallback(req, res);
        expect(res.clearCookie).toHaveBeenCalledWith('oauth_state_azure');
    });

    // Kills: isBlocked exact field check mutations
    test('authPayload isBlocked false must NOT trigger 403', async () => {
        req.params.provider = 'google';
        req.query.state = 'st';
        req.cookies['oauth_state_google'] = 'st';
        req.query.code = 'code';
        OAuthService.exchangeCodeForTokens.mockResolvedValue({});
        OAuthService.processUserSignIn.mockResolvedValue({
            isBlocked: false,
            token: 'access_tok',
            refreshToken: 'refresh_tok',
            user: { id: 'u1', role: 'USER', email: 'x@x.com' }
        });
        await handleCallback(req, res);
        expect(res.status).toHaveBeenCalledWith(200);
        expect(res.json).toHaveBeenCalledWith({
            message: 'OAuth authentication successful',
            token: 'access_tok',
            refreshToken: 'refresh_tok',
            user: { id: 'u1', role: 'USER', email: 'x@x.com' }
        });
    });

    // Kills: regex replacement [MASKED] string literal mutations
    test('sanitizedMessage must replace secret_idp_access_token pattern with [MASKED]', async () => {
        req.params.provider = 'google';
        req.query.state = 'st';
        req.cookies['oauth_state_google'] = 'st';
        req.query.code = 'code';
        OAuthService.exchangeCodeForTokens.mockRejectedValue(
            new Error('secret_idp_access_token_xyz999 leaked')
        );
        await handleCallback(req, res);
        const logArg = logger.error.mock.calls[0][0];
        expect(logArg).toContain('[MASKED]');
        expect(logArg).not.toContain('secret_idp_access_token_xyz999');
    });

    // Kills: handleLogout 400 exact error message mutations
    test('handleLogout missing authHeader exact error message', async () => {
        req.headers.authorization = undefined;
        req.body.refreshToken = 'ref';
        await handleLogout(req, res);
        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.json).toHaveBeenCalledWith({
            error: 'Missing tokens required for session revocation'
        });
    });
// Kills: !state && !savedState → AND mutation line 35
    test('should block when state exists but savedState is missing', async () => {
        req.params.provider = 'github';
        req.query.state = 'exists';
        req.cookies['oauth_state_github'] = undefined;
        await handleCallback(req, res);
        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({
            error: 'Anti-CSRF state validation failed. Request denied.'
        });
    });

    // Kills: regex /secret_idp_access_token_\w|token_\w+/g — missing + quantifier
    test('should mask multi-character secret token patterns', async () => {
        req.params.provider = 'google';
        req.query.state = 'st';
        req.cookies['oauth_state_google'] = 'st';
        req.query.code = 'code';
        OAuthService.exchangeCodeForTokens.mockRejectedValue(
            new Error('secret_idp_access_token_ABCDEFGH exposed')
        );
        await handleCallback(req, res);
        const logArg = logger.error.mock.calls[0][0];
        expect(logArg).not.toContain('secret_idp_access_token_ABCDEFGH');
        expect(logArg).toContain('[MASKED]');
    });

    // Kills: /secret_idp_access_token_\W+|token_\w+/g — \W instead of \w
    test('should mask token_ followed by word characters only', async () => {
        req.params.provider = 'google';
        req.query.state = 'st';
        req.cookies['oauth_state_google'] = 'st';
        req.query.code = 'code';
        OAuthService.exchangeCodeForTokens.mockRejectedValue(
            new Error('token_abc123 in error message')
        );
        await handleCallback(req, res);
        const logArg = logger.error.mock.calls[0][0];
        expect(logArg).not.toContain('token_abc123');
        expect(logArg).toContain('[MASKED]');
    });

    // Kills: /secret_idp_access_token_\w+|token_\w/g — missing + on last \w
    test('should mask token_ with multiple trailing characters', async () => {
        req.params.provider = 'google';
        req.query.state = 'st';
        req.cookies['oauth_state_google'] = 'st';
        req.query.code = 'code';
        OAuthService.exchangeCodeForTokens.mockRejectedValue(
            new Error('token_longvalue123 exposed')
        );
        await handleCallback(req, res);
        const logArg = logger.error.mock.calls[0][0];
        expect(logArg).not.toContain('token_longvalue123');
        expect(logArg).toContain('[MASKED]');
    });
    });
});
