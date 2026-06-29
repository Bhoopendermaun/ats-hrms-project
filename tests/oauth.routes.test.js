import { jest } from '@jest/globals';
import request from 'supertest';
import express from 'express';

// 1. Setup mock functions
const mockInitiateLogin = jest.fn((req, res) => res.sendStatus(302));
const mockHandleCallback = jest.fn((req, res) => res.sendStatus(200));
const mockHandleLogout = jest.fn((req, res) => res.sendStatus(200));

// 2. Declare unstable mocks before importing router
jest.unstable_mockModule('../src/controllers/oauth.controller.js', () => ({
    initiateLogin: mockInitiateLogin,
    handleCallback: mockHandleCallback,
    handleLogout: mockHandleLogout
}));

jest.unstable_mockModule('../src/models/OAuthAccount.js', () => ({
    default: class OAuthAccount {}
}), { virtual: true });

// 3. Dynamic ESM Imports
const oauthRoutesModule = await import('../src/routes/oauthRoutes.js');
const oauthRouter = oauthRoutesModule.default || oauthRoutesModule.oauthRouter || oauthRoutesModule;

describe('OAuth Routing & Model Binding Execution Suite', () => {
    let app;

    beforeAll(() => {
        app = express();
        app.use(express.json());

        // Mount directly to root to let the router's internal paths evaluate cleanly
        app.use('/api/oauth', oauthRouter);
    });

    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe('GET /api/oauth/:provider/login', () => {
        test('should properly route requests down to the initiateLogin controller function', async () => {
            await request(app)
                .get('/api/oauth/google/login')
                .expect(302);

            expect(mockInitiateLogin).toHaveBeenCalledTimes(1);
        });
    });

    describe('GET /api/oauth/:provider/callback', () => {
        test('should route identity provider incoming callbacks directly to handleCallback', async () => {
            await request(app)
                .get('/api/oauth/github/callback?code=test_code&state=secure_hex')
                .expect(200);

            expect(mockHandleCallback).toHaveBeenCalledTimes(1);
        });
    });

    describe('POST /api/oauth/logout', () => {
        test('should forward request structures safely through to the handleLogout controller target', async () => {
            await request(app)
                .post('/api/oauth/logout')
                .set('Authorization', 'Bearer active_access_token_payload')
                .send({ refreshToken: 'active_refresh_token_payload' })
                .expect(200);

            expect(mockHandleLogout).toHaveBeenCalledTimes(1);
        });
    });
});
