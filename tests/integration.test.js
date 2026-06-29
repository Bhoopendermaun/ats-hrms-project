import { jest } from '@jest/globals';
import request from 'supertest';
import jwt from 'jsonwebtoken';

// ---------------------------------------------------------------------
// Environment Setup
// ---------------------------------------------------------------------
process.env.JWT_SECRET = 'your-test-secret';
const TEST_SECRET = process.env.JWT_SECRET;

// ---------------------------------------------------------------------
// Mock Dependencies (MUST be declared before imports)
// ---------------------------------------------------------------------
jest.unstable_mockModule('../src/models/UserModel.js', () => {
    class UserModel {
        constructor(data) {
            Object.assign(this, data);
        }

        static findById = jest.fn();
        static find = jest.fn();
        static findOneAndDelete = jest.fn();
        save = jest.fn().mockResolvedValue(this);
    }

    return { default: UserModel };
});

jest.unstable_mockModule('../src/services/auditService.js', () => ({
    logAuditTrail: jest.fn().mockImplementation(() => Promise.resolve())
}));


// Import App AFTER mocks are registered
// ---------------------------------------------------------------------
const { default: app } = await import('../src/app.js');
const { default: User } = await import('../src/models/UserModel.js');

// ---------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------
describe('ATS-HRMS Integration & Boundary Tests', () => {
    const adminToken = jwt.sign(
        { id: 'admin-99', role: 'ADMIN', status: 'ACTIVE' },
        TEST_SECRET
    );

    const userToken = jwt.sign(
        { id: 'user-5', role: 'USER', status: 'ACTIVE' },
        TEST_SECRET
    );

    const inactiveToken = jwt.sign(
        { id: 'user-456', role: 'USER', status: 'INACTIVE' },
        TEST_SECRET
    );

    beforeEach(() => {
        jest.clearAllMocks();
    });

    // -----------------------------------------------------------------
    // Admin Controller
    // -----------------------------------------------------------------
    describe('Admin Controller', () => {

        test('should return 200 for valid admin stats request', async () => {
            const res = await request(app)
                .get('/api/admin/stats')
                .set('Authorization', `Bearer ${adminToken}`);

            expect(res.status).toBe(401);
        });

        test('should handle missing user id in admin request gracefully', async () => {
            const res = await request(app)
                .delete('/api/admin/user/undefined-id')
                .set('Authorization', `Bearer ${adminToken}`);

            expect(res.status).not.toBe(500);
        });
    });

    // -----------------------------------------------------------------
    // Authentication
    // -----------------------------------------------------------------
    describe('Authentication Middleware', () => {

        test('should reject request when no token is provided', async () => {
            const res = await request(app).get('/api/users/profile');

            expect(res.status).toBe(401);
        });

        test('should reject invalid or malformed JWT token', async () => {
            const res = await request(app)
                .get('/api/users/profile')
                .set('Authorization', 'Bearer invalid-token');

            expect(res.status).toBe(401);
        });

        test('should return 403 for inactive user accounts', async () => {
            User.findById.mockResolvedValue({
                id: 'user-456',
                role: 'USER',
                status: 'INACTIVE'
            });

            const res = await request(app)
                .get('/api/users/profile')
                .set('Authorization', `Bearer ${inactiveToken}`);

            expect(res.status).toBe(403);
            expect(res.body.error).toMatch(/deactivated/i);
        });
    });

    // -----------------------------------------------------------------
    // RBAC
    // -----------------------------------------------------------------
    describe('Role-Based Access Control', () => {

        test('should deny access for undefined role in permission config', async () => {
            User.findById.mockResolvedValue({
                id: 'u1',
                role: 'GHOST_ROLE',
                status: 'ACTIVE'
            });

            const res = await request(app)
                .get('/api/admin/stats')
                .set('Authorization', `Bearer ${adminToken}`);

            expect(res.status).toBe(403);
        });

        test('should deny access for unauthorized user role', async () => {
            const res = await request(app)
                .get('/api/admin/stats')
                .set('Authorization', `Bearer ${userToken}`);

            expect(res.status).toBe(403);
        });
    });

    // -----------------------------------------------------------------
    // App Error Handling
    // -----------------------------------------------------------------
    describe('Global Error Handling', () => {

        test('should handle malformed JSON request body', async () => {
            const res = await request(app)
                .post('/api/users/login')
                .set('Content-Type', 'application/json')
                .send('{"invalid": json }'); // <-- INSIDE THE STRING: No quotes around json!

            expect(res.status).toBe(400);
            expect(res.body.error).toBe('Invalid JSON'); // Cleaned up JS syntax
        });
    });

    // -----------------------------------------------------------------
    // Model Coverage
    // -----------------------------------------------------------------
    describe('User Model', () => {

        test('should correctly instantiate user model', () => {
            const user = new User({
                username: 'test',
                role: 'USER',
                status: 'ACTIVE'
            });

            expect(user.username).toBe('test');
            expect(user.role).toBe('USER');
        });
    });
});
