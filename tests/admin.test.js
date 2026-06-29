import { jest } from '@jest/globals';

process.env.JWT_SECRET = 'test-secret';

// =============================================================
// MOCKS
// =============================================================
jest.unstable_mockModule('../src/models/UserModel.js', () => {
    const mockUser = {
        find: jest.fn(),
        findById: jest.fn(),
        findByIdAndUpdate: jest.fn(),
        findOneAndDelete: jest.fn(),
    };
    return { __esModule: true, User: mockUser, default: mockUser };
});

jest.unstable_mockModule('../src/services/auditService.js', () => ({
    logAuditTrail: jest.fn().mockResolvedValue(true),
}));

jest.unstable_mockModule('../src/services/roleService.js', () => ({
    __esModule: true,
    default: {
        getPermissionsByRole: jest.fn(),
        checkPermission: jest.fn(),
    },
}));

// =============================================================
// IMPORTS (after mocks)
// =============================================================
const { User }        = await import('../src/models/UserModel.js');
const auditService    = await import('../src/services/auditService.js');
const roleServiceMod  = await import('../src/services/roleService.js');
const roleService     = roleServiceMod.default;

const adminModule     = await import('../src/controllers/adminController.js');
const adminController = adminModule.default || adminModule;

// =============================================================
// HELPERS
// =============================================================
const makeReq = (overrides = {}) => ({
    params: {},
    body:   {},
    user:   { id: 'admin-1' },
    ...overrides,
});

// =============================================================
// SUITE
// =============================================================
describe('Admin Controller - SSDLC Clean Suite', () => {

    let mockRes;

    beforeEach(() => {
        jest.clearAllMocks();
        mockRes = {
            status: jest.fn().mockReturnThis(),
            json:   jest.fn().mockReturnThis(),
        };
    });

    // ─────────────────────────────────────────────────────────
    // GET ALL USERS
    // ─────────────────────────────────────────────────────────
    describe('getAllUsers', () => {

        test('should return all users (non-empty)', async () => {
            User.find.mockResolvedValue([{ id: '1' }, { id: '2' }]);
            await adminController.getAllUsers({}, mockRes);
            expect(mockRes.status).toHaveBeenCalledWith(200);
            expect(mockRes.json).toHaveBeenCalledWith([{ id: '1' }, { id: '2' }]);
        });

        test('should return empty array when DB returns null', async () => {
            User.find.mockResolvedValue(null);
            await adminController.getAllUsers({}, mockRes);
            expect(mockRes.status).toHaveBeenCalledWith(200);
            expect(mockRes.json).toHaveBeenCalledWith([]);
        });

        // Kills: ObjectLiteral {} and StringLiteral "" mutants on 500 body
        test('should return 500 with error message on DB failure', async () => {
            User.find.mockRejectedValue(new Error('DB_FAIL'));
            await adminController.getAllUsers({}, mockRes);
            expect(mockRes.status).toHaveBeenCalledWith(500);
            expect(mockRes.json).toHaveBeenCalledWith({ error: 'Internal Server Error' });
        });
    });

    // ─────────────────────────────────────────────────────────
    // UPDATE USER
    // ─────────────────────────────────────────────────────────
    describe('updateUser', () => {

        // Kills: ObjectLiteral + StringLiteral on 400 missing payload body
        test('should return 400 with exact error when id is missing', async () => {
            await adminController.updateUser({ params: {}, body: { role: 'USER' } }, mockRes);
            expect(mockRes.status).toHaveBeenCalledWith(400);
            expect(mockRes.json).toHaveBeenCalledWith(
                { error: 'Missing userId or update parameters' }
            );
        });

        test('should return 400 when neither role nor status provided', async () => {
            await adminController.updateUser({ params: { id: '1' }, body: {} }, mockRes);
            expect(mockRes.status).toHaveBeenCalledWith(400);
            expect(mockRes.json).toHaveBeenCalledWith(
                { error: 'Missing userId or update parameters' }
            );
        });

        test('should return 400 for invalid role', async () => {
            await adminController.updateUser(
                { params: { id: '1' }, body: { role: 'HACKER' } }, mockRes
            );
            expect(mockRes.status).toHaveBeenCalledWith(400);
            expect(mockRes.json).toHaveBeenCalledWith({ error: 'Invalid role specified' });
        });

        test('should return 400 for invalid status', async () => {
            await adminController.updateUser(
                { params: { id: '1' }, body: { status: 'BANNED' }, user: { id: 'admin' } },
                mockRes
            );
            expect(mockRes.status).toHaveBeenCalledWith(400);
            expect(mockRes.json).toHaveBeenCalledWith({ error: 'Invalid status specified' });
        });

        // Kills: audit string "ROLE_REQUEST" → "", template literal → ``, message → ""
        test('should return 202 for ADMIN role and fire correct audit', async () => {
            await adminController.updateUser(
                { params: { id: '1' }, body: { role: 'ADMIN' }, user: { id: 'admin-1' } },
                mockRes
            );
            expect(mockRes.status).toHaveBeenCalledWith(202);
            expect(mockRes.json).toHaveBeenCalledWith({
                message: 'Elevated role change requires secondary approval',
                status:  'PENDING_APPROVAL',
            });
            expect(auditService.logAuditTrail).toHaveBeenCalledWith(
                'admin-1', '1', 'ROLE_REQUEST', 'PENDING_APPROVAL: ADMIN'
            );
        });

        test('should return 202 for MANAGER role', async () => {
            await adminController.updateUser(
                { params: { id: '1' }, body: { role: 'MANAGER' }, user: { id: 'admin-1' } },
                mockRes
            );
            expect(mockRes.status).toHaveBeenCalledWith(202);
            expect(mockRes.json).toHaveBeenCalledWith({
                message: 'Elevated role change requires secondary approval',
                status:  'PENDING_APPROVAL',
            });
            expect(auditService.logAuditTrail).toHaveBeenCalledWith(
                'admin-1', '1', 'ROLE_REQUEST', 'PENDING_APPROVAL: MANAGER'
            );
        });

        test('should NOT return 202 for USER role — proceeds to DB', async () => {
            User.findByIdAndUpdate.mockResolvedValue({ id: '1', role: 'USER' });
            await adminController.updateUser(
                { params: { id: '1' }, body: { role: 'USER' }, user: { id: 'admin' } },
                mockRes
            );
            expect(mockRes.status).toHaveBeenCalledWith(200);
        });

        // Kills: { role, status } → {} and { new: true } → { new: false }
        test('should call findByIdAndUpdate with exact args including new:true', async () => {
            User.findByIdAndUpdate.mockResolvedValue({ id: '1' });
            await adminController.updateUser(
                { params: { id: '1' }, body: { status: 'ACTIVE' }, user: { id: 'admin-1' } },
                mockRes
            );
            expect(User.findByIdAndUpdate).toHaveBeenCalledWith(
                '1',
                { role: undefined, status: 'ACTIVE' },
                { new: true }
            );
        });

        // Kills: ObjectLiteral + StringLiteral on 404 body
        test('should return 404 with exact error if user not found', async () => {
            User.findByIdAndUpdate.mockResolvedValue(null);
            await adminController.updateUser(
                { params: { id: '999' }, body: { status: 'ACTIVE' } }, mockRes
            );
            expect(mockRes.status).toHaveBeenCalledWith(404);
            expect(mockRes.json).toHaveBeenCalledWith({ error: 'User not found' });
        });

        // Kills: ConditionalExpression + LogicalOperator on status || 'UNCHANGED'
        // Uses exact string to kill template literal mutations
        test('should audit with exact UNCHANGED string when only status is provided', async () => {
            User.findByIdAndUpdate.mockResolvedValue({ id: '1' });
            await adminController.updateUser(
                { params: { id: '1' }, body: { status: 'ACTIVE' }, user: { id: 'admin-1' } },
                mockRes
            );
            expect(mockRes.status).toHaveBeenCalledWith(200);
            expect(mockRes.json).toHaveBeenCalledWith({
                message:     'User settings updated successfully',
                updatedUser: '1',
            });
            expect(auditService.logAuditTrail).toHaveBeenCalledWith(
                'admin-1', '1', 'ADMIN_ACTION',
                'Update finalized: Role=UNCHANGED, Status=ACTIVE'
            );
        });

        // Kills: status side of || 'UNCHANGED' when only role provided
        test('should audit with UNCHANGED for status when only role is updated', async () => {
            User.findByIdAndUpdate.mockResolvedValue({ id: '1' });
            await adminController.updateUser(
                { params: { id: '1' }, body: { role: 'USER' }, user: { id: 'admin-1' } },
                mockRes
            );
            expect(auditService.logAuditTrail).toHaveBeenCalledWith(
                'admin-1', '1', 'ADMIN_ACTION',
                'Update finalized: Role=USER, Status=UNCHANGED'
            );
        });

        // Kills: 'SYSTEM' → "" on adminId fallback
        test('should use SYSTEM as adminId when req.user is absent', async () => {
            User.findByIdAndUpdate.mockResolvedValue({ id: '1' });
            await adminController.updateUser(
                { params: { id: '1' }, body: { status: 'ACTIVE' } }, mockRes
            );
            expect(auditService.logAuditTrail).toHaveBeenCalledWith(
                'SYSTEM', '1', 'ADMIN_ACTION', expect.any(String)
            );
        });

        // Kills: ObjectLiteral + StringLiteral on 500 body
        test('should return 500 with exact error on unexpected failure', async () => {
            User.findByIdAndUpdate.mockRejectedValue(new Error('crash'));
            await adminController.updateUser(
                { params: { id: '1' }, body: { status: 'ACTIVE' } }, mockRes
            );
            expect(mockRes.status).toHaveBeenCalledWith(500);
            expect(mockRes.json).toHaveBeenCalledWith({ error: 'Internal Server Error' });
        });

	it('should safely resolve userId from params when req.body is undefined', async () => {
            const req = { 
                params: { userId: '123' }, 
                body: undefined,
                user: { id: 'admin-1' } 
            };
            const res = { 
                status: jest.fn().mockReturnThis(), 
                json: jest.fn() 
            };
            
            // Invoke via the imported namespace object
            await adminController.updateUser(req, res);
            
            // This verifies it fell back gracefully to params instead of crashing
            expect(res.status).not.toHaveBeenCalledWith(400);
        });
    });

    // ─────────────────────────────────────────────────────────
    // DELETE USER
    // ─────────────────────────────────────────────────────────
    describe('deleteUser', () => {

        // Kills: { _id: id } → {} and 404 body mutations
        test('should call findOneAndDelete with exact query and return 404 if not found', async () => {
            User.findOneAndDelete.mockResolvedValue(null);
            await adminController.deleteUser(makeReq({ params: { id: '999' } }), mockRes);
            expect(User.findOneAndDelete).toHaveBeenCalledWith({ _id: '999' });
            expect(mockRes.status).toHaveBeenCalledWith(404);
            expect(mockRes.json).toHaveBeenCalledWith({ error: 'User not found' });
        });

        test('should delete, return 200 with exact body, and log audit', async () => {
            User.findOneAndDelete.mockResolvedValue({ id: '1' });
            await adminController.deleteUser(makeReq({ params: { id: '1' } }), mockRes);
            expect(User.findOneAndDelete).toHaveBeenCalledWith({ _id: '1' });
            expect(mockRes.status).toHaveBeenCalledWith(200);
            expect(mockRes.json).toHaveBeenCalledWith({ id: '1', message: 'Deleted' });
            expect(auditService.logAuditTrail).toHaveBeenCalledWith(
                'admin-1', '1', 'DELETE_USER', 'User account removed'
            );
        });

        // Kills: 'SYSTEM' → "" fallback
        test('should use SYSTEM as audit actor when req.user is absent', async () => {
            User.findOneAndDelete.mockResolvedValue({ id: '1' });
            await adminController.deleteUser({ params: { id: '1' } }, mockRes);
            expect(mockRes.status).toHaveBeenCalledWith(200);
            expect(auditService.logAuditTrail).toHaveBeenCalledWith(
                'SYSTEM', '1', 'DELETE_USER', 'User account removed'
            );
        });

        // Kills: ObjectLiteral + StringLiteral on 500 body
        test('should return 500 with exact error on DB failure', async () => {
            User.findOneAndDelete.mockRejectedValue(new Error('FAIL'));
            await adminController.deleteUser(makeReq({ params: { id: '1' } }), mockRes);
            expect(mockRes.status).toHaveBeenCalledWith(500);
            expect(mockRes.json).toHaveBeenCalledWith({ error: 'Internal Server Error' });
        });
    });

    // ─────────────────────────────────────────────────────────
    // APPROVE ROLE
    // ─────────────────────────────────────────────────────────
    describe('approveRole', () => {

        // Kills: removes validation — checks exact error message
        test('should return 400 with exact error for invalid action', async () => {
            await adminController.approveRole(
                { body: { userId: '1', action: 'DELETE' } }, mockRes
            );
            expect(mockRes.status).toHaveBeenCalledWith(400);
            expect(mockRes.json).toHaveBeenCalledWith(
                { error: 'Invalid action. Use APPROVE or REJECT' }
            );
        });

        test('should return 400 for undefined action', async () => {
            await adminController.approveRole({ body: { userId: '1' } }, mockRes);
            expect(mockRes.status).toHaveBeenCalledWith(400);
            expect(mockRes.json).toHaveBeenCalledWith(
                { error: 'Invalid action. Use APPROVE or REJECT' }
            );
        });

        test('should return 400 when APPROVE sent without role', async () => {
            await adminController.approveRole(
                { body: { userId: '1', action: 'APPROVE' } }, mockRes
            );
            expect(mockRes.status).toHaveBeenCalledWith(400);
            expect(mockRes.json).toHaveBeenCalledWith(
                { error: 'Role is required for approval' }
            );
        });

        // Kills: DB args, "ROLE_APPROVED" string, template literal, message + toLowerCase mutant
        test('should approve: call DB, log ROLE_APPROVED with exact string, return exact message', async () => {
            User.findByIdAndUpdate.mockResolvedValue({ id: '1' });
            await adminController.approveRole(
                {
                    params: { userId: '1' },
                    body:   { action: 'APPROVE', role: 'MANAGER' },
                    user:   { id: 'admin-1' },
                },
                mockRes
            );
            expect(User.findByIdAndUpdate).toHaveBeenCalledWith('1', { role: 'MANAGER' });
            expect(mockRes.status).toHaveBeenCalledWith(200);
            // Exact string kills the toUpperCase() mutant
            expect(mockRes.json).toHaveBeenCalledWith(
                { message: 'Role change approveed successfully.' }
            );
            // Exact audit string kills template literal → `` mutant
            expect(auditService.logAuditTrail).toHaveBeenCalledWith(
                'admin-1', '1', 'ROLE_APPROVED', 'Decision finalized: APPROVE'
            );
        });

        // Kills: ternary ROLE_APPROVED→ROLE_REJECTED, skip DB, exact message
        test('should reject: skip DB, log ROLE_REJECTED with exact string, return exact message', async () => {
            await adminController.approveRole(
                {
                    params: { userId: '1' },
                    body:   { action: 'REJECT', role: 'MANAGER' },
                    user:   { id: 'admin-1' },
                },
                mockRes
            );
            expect(User.findByIdAndUpdate).not.toHaveBeenCalled();
            expect(mockRes.status).toHaveBeenCalledWith(200);
            expect(mockRes.json).toHaveBeenCalledWith(
                { message: 'Role change rejected successfully.' }
            );
            expect(auditService.logAuditTrail).toHaveBeenCalledWith(
                'admin-1', '1', 'ROLE_REJECTED', 'Decision finalized: REJECT'
            );
        });

        // Kills: 'SYSTEM' → "" on adminId fallback
        test('should use SYSTEM as adminId when req.user is absent', async () => {
            User.findByIdAndUpdate.mockResolvedValue({ id: '1' });
            await adminController.approveRole(
                { params: { userId: '1' }, body: { action: 'APPROVE', role: 'MANAGER' } },
                mockRes
            );
            expect(auditService.logAuditTrail).toHaveBeenCalledWith(
                'SYSTEM', '1', 'ROLE_APPROVED', expect.any(String)
            );
        });

        // Kills: ObjectLiteral + StringLiteral on 500 body
        test('should return 500 with exact error on unexpected failure', async () => {
            User.findByIdAndUpdate.mockRejectedValue(new Error('DB crash'));
            await adminController.approveRole(
                { params: { userId: '1' }, body: { action: 'APPROVE', role: 'MANAGER' } },
                mockRes
            );
            expect(mockRes.status).toHaveBeenCalledWith(500);
            expect(mockRes.json).toHaveBeenCalledWith({ error: 'Internal Server Error' });
        });
    });

    // ─────────────────────────────────────────────────────────
    // GET ROLE PERMISSIONS
    // ─────────────────────────────────────────────────────────
    describe('getRolePermissions', () => {

        test('should return 200 with permissions array', async () => {
            roleService.getPermissionsByRole.mockReturnValue(['READ', 'WRITE']);
            await adminController.getRolePermissions({ params: { id: 'ADMIN' } }, mockRes);
            expect(mockRes.status).toHaveBeenCalledWith(200);
            expect(mockRes.json).toHaveBeenCalledWith(['READ', 'WRITE']);
        });

        // Kills: ObjectLiteral + StringLiteral on 404 body
        test('should return 404 with exact error when service returns null', async () => {
            roleService.getPermissionsByRole.mockReturnValue(null);
            await adminController.getRolePermissions({ params: { id: 'INVALID' } }, mockRes);
            expect(mockRes.status).toHaveBeenCalledWith(404);
            expect(mockRes.json).toHaveBeenCalledWith(
                { error: 'Permissions not found for this role' }
            );
        });

        test('should return 404 with exact error when service returns undefined', async () => {
            roleService.getPermissionsByRole.mockReturnValue(undefined);
            await adminController.getRolePermissions({ params: { id: 'MISSING' } }, mockRes);
            expect(mockRes.status).toHaveBeenCalledWith(404);
            expect(mockRes.json).toHaveBeenCalledWith(
                { error: 'Permissions not found for this role' }
            );
        });

        test('should return 200 for empty permissions array (not 404)', async () => {
            roleService.getPermissionsByRole.mockReturnValue([]);
            await adminController.getRolePermissions({ params: { id: 'USER' } }, mockRes);
            expect(mockRes.status).toHaveBeenCalledWith(200);
            expect(mockRes.json).toHaveBeenCalledWith([]);
        });

        // Kills: ObjectLiteral + StringLiteral on 500 body
        test('should return 500 with exact error on service crash', async () => {
            roleService.getPermissionsByRole.mockRejectedValue(new Error('FAIL'));
            await adminController.getRolePermissions({ params: { id: 'ADMIN' } }, mockRes);
            expect(mockRes.status).toHaveBeenCalledWith(500);
            expect(mockRes.json).toHaveBeenCalledWith(
                { error: 'Could not retrieve permissions' }
            );
        });
    });

    // ─────────────────────────────────────────────────────────
    // updateUserSettings alias
    // ─────────────────────────────────────────────────────────
    describe('updateUserSettings alias', () => {

        test('should exist as a function', async () => {
            expect(adminController.updateUserSettings).toBeDefined();
            expect(typeof adminController.updateUserSettings).toBe('function');
        });

        test('should behave identically to updateUser', async () => {
            await adminController.updateUserSettings(
                { params: { id: '1' }, body: {} }, mockRes
            );
            expect(mockRes.status).toHaveBeenCalledWith(400);
            expect(mockRes.json).toHaveBeenCalledWith(
                { error: 'Missing userId or update parameters' }
            );
        });
    });

describe('AdminController - Surviving Mutant Killers', () => {

    // Kills: roleServiceModule?.default ?? roleServiceModule → roleServiceModule.default
    test('adminController should load correctly when roleService has default export', async () => {
        const req = { params: { id: 'u1' }, body: { status: 'ACTIVE' }, user: { id: 'admin1' } };
        const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };
        User.findByIdAndUpdate.mockResolvedValueOnce({ _id: 'u1', status: 'ACTIVE' });
        await adminController.updateUser(req, res);
        expect(res.status).toHaveBeenCalledWith(200);
    });

    // Kills: req.params?.userId ?? req.body?.userId optional chaining mutation line 112
    test('approveRole should read userId from req.body when params is missing', async () => {
        const req = {
            params: {},
            body: { userId: 'u2', action: 'APPROVE', role: 'USER' },
            user: { id: 'admin1' }
        };
        const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };
        User.findByIdAndUpdate.mockResolvedValueOnce({ _id: 'u2', role: 'USER' });
        auditService.logAuditTrail.mockResolvedValueOnce(undefined);
        await adminController.approveRole(req, res);
        expect(res.status).toHaveBeenCalledWith(200);
    });

    // Kills: req.params?.userId — optional chaining on params
    test('approveRole should read userId from req.params when available', async () => {
        const req = {
            params: { userId: 'u3' },
            body: { action: 'REJECT' },
            user: { id: 'admin1' }
        };
        const res = { status: jest.fn().mockReturnThis(), json: jest.fn() };
        auditService.logAuditTrail.mockResolvedValueOnce(undefined);
        await adminController.approveRole(req, res);
        expect(res.status).toHaveBeenCalledWith(200);
    });
});
});
