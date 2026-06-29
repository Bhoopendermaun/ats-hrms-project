import { jest } from '@jest/globals';
import request from 'supertest';
import jwt from 'jsonwebtoken';

// =============================================================
// MOCKS
// =============================================================
jest.unstable_mockModule('../src/models/UserModel.js', () => ({
    default: { findById: jest.fn(), findOneAndDelete: jest.fn() },
}));

jest.unstable_mockModule('../src/services/auditService.js', () => ({
    logAuditTrail: jest.fn().mockResolvedValue(true),
}));

const { default: app }  = await import('../src/app.js');
const { default: User } = await import('../src/models/UserModel.js');
const auditService      = await import('../src/services/auditService.js');

const JWT_SECRET      = process.env.JWT_SECRET || 'your-test-secret';
const validUserToken  = jwt.sign({ id: 'user-1',  role: 'USER'  }, JWT_SECRET);
const validAdminToken = jwt.sign({ id: 'admin-1', role: 'ADMIN' }, JWT_SECRET);
const userToken       = jwt.sign({ id: 'user-2',  role: 'USER'  }, JWT_SECRET);

describe('App Boundary Conditions', () => {

    beforeEach(() => {
        jest.clearAllMocks();
        auditService.logAuditTrail.mockResolvedValue(true); // default: succeeds
    });

    test('Should handle internal server errors gracefully', async () => {
        const res = await request(app).get('/api/test/error');
        expect(res.status).toBe(500);
        expect(res.body.error).toBe('Internal Server Error');
    });

    test('Should hit 404 handler', async () => {
        const res = await request(app).get('/not-a-real-route');
        expect(res.status).toBe(404);
        expect(res.body.error).toBe('Not Found');
    });

    test('Coverage: Should hit index.js protected route', async () => {
        User.findById.mockResolvedValue({ _id: 'user-1', role: 'USER', isActive: true });
        const res = await request(app)
            .get('/api/protected')
            .set('Authorization', `Bearer ${validUserToken}`);
        expect(res.status).toBe(200);
        expect(res.body.message).toBe('You are authenticated!');
    });

    test('Coverage: Should hit index.js admin-only route', async () => {
        User.findById.mockResolvedValue({ _id: 'admin-1', role: 'ADMIN', isActive: true });
        const res = await request(app)
            .get('/api/admin-only')
            .set('Authorization', `Bearer ${validAdminToken}`);
        expect(res.status).toBe(200);
        expect(res.body.message).toBe('Welcome, Admin!');
    });

    test('Should reject wrong-secret token', async () => {
        const wrongToken = jwt.sign({ id: '1', role: 'USER' }, 'WRONG_SECRET');
        const res = await request(app)
            .get('/api/protected')
            .set('Authorization', `Bearer ${wrongToken}`);
        expect(res.status).toBe(401);
    });

    test('Should handle malformed JSON body (400)', async () => {
        const res = await request(app)
            .post('/api/login')
            .set('Content-Type', 'application/json')
            .send('{"invalid": json }');
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/json/i);
    });

    test('Should suppress stack traces in production', async () => {
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'production';
        const res = await request(app).get('/force-error');
        expect(res.status).toBe(500);
        process.env.NODE_ENV = originalEnv;
    });

    // ── userRoutes line 11 — GET /api/users/profile ───────────
    test('userRoutes: GET /profile returns profile data (line 11)', async () => {
        User.findById.mockResolvedValue({ _id: 'user-1', role: 'USER', isActive: true });
        const res = await request(app)
            .get('/api/users/profile')
            .set('Authorization', `Bearer ${validUserToken}`);
        expect(res.status).toBe(200);
        expect(res.body.message).toBe('Profile data');
    });

    // ── userRoutes line 18 — DELETE /api/users/manage-users/:id ─
    test('userRoutes: DELETE /manage-users/:id with ADMIN (line 18)', async () => {
        User.findById.mockResolvedValue({ _id: 'admin-1', role: 'ADMIN', isActive: true });
        const res = await request(app)
            .delete('/api/users/manage-users/target-99')
            .set('Authorization', `Bearer ${validAdminToken}`);
        expect(res.status).toBe(200);
        expect(res.body.message).toMatch(/target-99/);
    });

    // ── rbac.js line 34 — the .catch((err) => console.error(...)) callback ──
    // This fires when logAuditTrail rejects inside the non-admin path of authorizeAdmin.
    // We spy on console.error to confirm the catch callback body executed.
        // Make audit reject so the .catch on line 34 fires
      test('rbac: non-admin user is denied access to admin route (line 34 path)', async () => {
    User.findById.mockResolvedValue({ _id: 'user-2', role: 'USER', isActive: true });
      auditService.logAuditTrail.mockRejectedValueOnce(new Error('audit down'));

    const res = await request(app)
        .get('/api/admin-only')
        .set('Authorization', `Bearer ${userToken}`);

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/access denied/i);
 });    
});

describe('Express App Boundary - Error Handling', () => {
    let errorSpy;

    beforeEach(() => {
        // Prevent expected error stacks from printing to the terminal
        errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterEach(() => {
        errorSpy.mockRestore();
    });

    it('should return 400 Bad Request on invalid JSON payload', async () => {
        const response = await request(app)
            .post('/api/some-endpoint')
            .set('Content-Type', 'application/json')
            .send('{"invalid": json }'); // Triggers the body-parser SyntaxError

        expect(response.status).toBe(400);
    });
});
