import { jest } from '@jest/globals';

// =========================
// 1. ENV SETUP
// =========================
process.env.JWT_SECRET = 'stryker-test-key-2026';

// =========================
// 2. MOCKS (BEFORE ALL IMPORTS)
// =========================
const roleServiceMock = {
    checkPermission: jest.fn(),
    getPermissionsByRole: jest.fn(),
};

const userModelMock = {
    findById: jest.fn(),
};

// Mock roleService
jest.unstable_mockModule('../src/services/roleService.js', () => ({
    default: roleServiceMock,
}));

// Mock UserModel
jest.unstable_mockModule('../src/models/UserModel.js', () => ({
    default: userModelMock,
}));

// FIX: Mock permissions.js so authorize() can resolve ADMIN → ['admin:write', 'all:all']
// Without this mock, rbac.js imports the REAL PERMISSION_MATRIX which may not
// include 'admin:write', so the "allow access" test gets 403 instead of calling next().
jest.unstable_mockModule('../src/config/permissions.js', () => ({
    PERMISSION_MATRIX: {
        ADMIN:   ['admin:write', 'all:all'],
        MANAGER: ['admin:write'],
        USER:    ['view:self'],
    },
}));

// Mock auditService to prevent real calls
jest.unstable_mockModule('../src/services/auditService.js', () => ({
    logAuditTrail: jest.fn().mockResolvedValue(true),
}));

// =========================
// 3. DYNAMIC IMPORTS (AFTER MOCKS)
// =========================
const { default: jwt } = await import('jsonwebtoken');

const { authenticate }  = await import('../src/middleware/auth.js');
const { authorize }     = await import('../src/middleware/rbac.js');

const roleService = (await import('../src/services/roleService.js')).default;
const User        = (await import('../src/models/UserModel.js')).default;

// =========================
// TEST SUITE
// =========================
describe('Admin Controller - Fixed Suite (ESM Safe)', () => {
    let req, res, next;

    beforeEach(() => {
        jest.clearAllMocks();

        next = jest.fn();

        res = {
            status: jest.fn().mockReturnThis(),
            json:   jest.fn().mockReturnThis(),
        };

        req = {
            headers: {},
            user:    null,
        };
    });

    // ─────────────────────────────────────────────────────────
    // AUTH MIDDLEWARE
    // ─────────────────────────────────────────────────────────
    describe('Authentication Middleware', () => {

        test('should return 401 when no token provided', async () => {
            await authenticate(req, res, next);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(next).not.toHaveBeenCalled();
        });

        test('should return 403 for deactivated user', async () => {
            const token = jwt.sign({ id: '123' }, process.env.JWT_SECRET);
            req.headers.authorization = `Bearer ${token}`;

            // FIX: auth.js checks user.isActive === false OR user.status === 'DEACTIVATED'
            // Use isActive: false to match the boolean path in auth.js
            User.findById.mockResolvedValue({
                _id:      '123',
                role:     'USER',
                isActive: false,          // ← triggers the deactivated guard
            });

            await authenticate(req, res, next);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({ error: expect.stringMatching(/deactivated/i) })
            );
            expect(next).not.toHaveBeenCalled();
        });

        test('should pass valid active user', async () => {
            const token = jwt.sign({ id: '123' }, process.env.JWT_SECRET);
            req.headers.authorization = `Bearer ${token}`;

            User.findById.mockResolvedValue({
                _id:      '123',
                role:     'ADMIN',
                isActive: true,
            });

            await authenticate(req, res, next);

            expect(next).toHaveBeenCalled();
        });
    });

    // ─────────────────────────────────────────────────────────
    // RBAC MIDDLEWARE
    // ─────────────────────────────────────────────────────────
    describe('RBAC Middleware', () => {

        test('should deny access when permission missing', async () => {
            // USER role only has 'view:self', not 'admin:write'
            req.user = { id: '1', role: 'USER', isActive: true };

            const middleware = authorize('admin:write');
            await middleware(req, res, next);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(next).not.toHaveBeenCalled();
        });

        test('should allow access when permission exists', async () => {
            // ADMIN role has ['admin:write', 'all:all'] from the mocked PERMISSION_MATRIX
            req.user = { id: '1', role: 'ADMIN', isActive: true };

            const middleware = authorize('admin:write');
            await middleware(req, res, next);

            expect(next).toHaveBeenCalled();
        });

        test('should return 401 when user missing', async () => {
            const middleware = authorize('admin:write');

            // No req.user at all → 401
            await middleware({}, res, next);

            expect(res.status).toHaveBeenCalledWith(401);
        });
    });
});
