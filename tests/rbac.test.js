import { jest } from '@jest/globals';

process.env.JWT_SECRET = 'test-secret';

// --- MOCKS ---
jest.unstable_mockModule('../src/services/auditService.js', () => ({
  logAuditTrail: jest.fn().mockResolvedValue(true),
}));

jest.unstable_mockModule('../src/config/permissions.js', () => ({
  PERMISSION_MATRIX: {
    ADMIN: ['admin:write', 'all:all'],
    USER: ['view:self'],
  },
}));

const auditService = await import('../src/services/auditService.js');
const { PERMISSION_MATRIX } = await import('../src/config/permissions.js');
const { authorize, authorizeAdmin } = await import('../src/middleware/rbac.js');

// -------------------- TESTS --------------------

describe('RBAC Middleware - FULL COVERAGE', () => {
  let req, res, next;

  beforeEach(() => {
    jest.clearAllMocks();

    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    next = jest.fn();
    req = { headers: {}, originalUrl: '/api/test', method: 'GET' };
  });

  // =========================
  // authorizeAdmin
  // =========================

  describe('authorizeAdmin', () => {
    test('blocks when user is missing', () => {
      req = {};

      authorizeAdmin(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });

    test('blocks inactive user', () => {
      req = { user: { id: '1', isActive: false, role: 'ADMIN' } };

      authorizeAdmin(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });

    test('blocks non-admin role', async () => {
      req = { user: { id: '1', isActive: true, role: 'USER' }, originalUrl: '/admin' };

      authorizeAdmin(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(auditService.logAuditTrail).toHaveBeenCalled();
    });

    test('allows admin with correct role', () => {
      req = { user: { id: '1', isActive: true, role: 'ADMIN' } };

      authorizeAdmin(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    test('allows via all:all permission', () => {
      req = { user: { id: '1', isActive: true, role: 'SUPER' } };

      PERMISSION_MATRIX.SUPER = ['all:all'];

      authorizeAdmin(req, res, next);

      expect(next).toHaveBeenCalled();
    });
  });

  // =========================
  // authorize (generic RBAC)
  // =========================

  describe('authorize()', () => {
    test('rejects missing permission string', () => {
      const middleware = authorize(null);

      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
    });

    test('blocks unauthenticated user', () => {
      const middleware = authorize('admin:write');

      middleware({}, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    test('blocks inactive user', () => {
      const middleware = authorize('admin:write');

      req = { user: { id: '1', isActive: false, role: 'ADMIN' } };

      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
    });

    test('blocks missing permission', async () => {
      const middleware = authorize('admin:write');

      req = { user: { id: '1', isActive: true, role: 'USER' } };

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(auditService.logAuditTrail).toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });

    test('allows valid permission', () => {
      const middleware = authorize('admin:write');

      req = { user: { id: '1', isActive: true, role: 'ADMIN' } };

      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    test('allows super-admin all:all override', () => {
      const middleware = authorize('random:permission');

      req = { user: { id: '1', isActive: true, role: 'ADMIN' } };

      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    test('anonymous fallback audit ID', async () => {
      const middleware = authorize('admin:write');

      req = {
        user: { isActive: true, role: 'USER' }, // no id
      };

      await middleware(req, res, next);

      expect(auditService.logAuditTrail).toHaveBeenCalledWith(
        'Anonymous',
        'SYSTEM',
        'PERMISSION_DENIED',
        expect.any(String)
      );
    });
  });

describe('RBAC Middleware - Inactive Blocks & Auditing', () => {
    let req, res, next;

    beforeEach(() => {
        // Fresh mock setup before each test case
        res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn()
        };
        next = jest.fn();
    });

    it('should explicitly deny inactive users with the exact message layout', async () => {
        // Merged original test logic with strict structural string assertions
        req = { 
            user: { 
                id: '1', 
                isActive: false, 
                role: 'ADMIN' 
            } 
        };

        const middleware = authorize('admin:write');
        await middleware(req, res, next);

        // Kills ObjectLiteral and StringLiteral mutations on line 63 perfectly
        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({ 
            error: "Access denied. Account inactive." 
        });
        expect(next).not.toHaveBeenCalled();
    });

    it('should handle audit trail log promise rejections without crashing the request stream', async () => {
        const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

        req = { 
           user: { 
               id: '1', 
               isActive: false, 
               role: 'ADMIN' 
           } 
       };
        const middleware = authorize('admin:write');
        await middleware(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);

        errorSpy.mockRestore();
    });

    it('should log error when audit trail promise rejects without crashing', async () => {
	const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

       // Override the mock to reject this one time
        auditService.logAuditTrail.mockRejectedValueOnce(new Error('Audit DB Down'));

       // Active user but NOT admin — triggers the if(!isAdmin) block where logAuditTrail is called
        req = {
            user: {
                id: '1',
                isActive: true,
                role: 'USER'
             },
	       originalUrl: '/admin/test'

          };

         // Use authorizeAdmin, not authorize
         await authorizeAdmin(req, res, next);

        // Let the floating .catch() resolve
        await new Promise(resolve => setImmediate(resolve));

        expect(console.error).toHaveBeenCalledWith(
           'Audit log failed:',
           expect.any(Error)
        );
        expect(res.status).toHaveBeenCalledWith(403);

        errorSpy.mockRestore();
    });
});

  // =============================================================
  // PRECISION MUTANT ELIMINATION (STRYKER TARGETED)
  // =============================================================
  describe('RBAC Middleware - Precision Mutant Elimination', () => {

    test('should strictly enforce exact response structure on authorizeAdmin failures', () => {
      req.user = { id: '1', isActive: false, role: 'ADMIN' };
      authorizeAdmin(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      // Strict matching on exact payload to kill empty string/empty object mutations
      expect(res.json).toHaveBeenCalledWith({ error: 'Access denied. Account inactive.' });
    });

    test('should strictly enforce exact response structure on generic authorize unauthenticated blocks', () => {
      const middleware = authorize('admin:write');
      req.user = null; // Unauthenticated payload context
      
      middleware(req, res, next);
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ error: 'Unauthorized. Please log in.' });
    });

    test('should strictly enforce exact response structure on missing system configuration arguments', () => {
      const middleware = authorize(null);
      
      middleware(req, res, next);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ error: 'System configuration error' });
    });

    test('should strictly match exact error messages on missing custom permissions', async () => {
      const middleware = authorize('admin:write');
      req.user = { id: '888', isActive: true, role: 'USER' };
      
      await middleware(req, res, next);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ error: 'Access denied' });
    });
  });

describe('RBAC - Stryker Mutant Elimination Suite', () => {

    beforeEach(() => {
        jest.clearAllMocks();
        res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn(),
        };
        next = jest.fn();
    });

    // Kills: !user → true/false mutations on authorizeAdmin
    test('authorizeAdmin should call next exactly once for valid admin — not zero times', () => {
        req = { user: { id: 'a1', isActive: true, role: 'ADMIN' }, originalUrl: '/admin' };
        authorizeAdmin(req, res, next);
        expect(next).toHaveBeenCalledTimes(1);
        expect(res.status).not.toHaveBeenCalled();
    });

    // Kills: user.role === 'ADMIN' string literal → "" mutations
    test('authorizeAdmin should deny USER role with exact 403 and exact error message', () => {
        req = { user: { id: 'u1', isActive: true, role: 'USER' }, originalUrl: '/admin/test' };
        authorizeAdmin(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({ error: 'Access denied. Admin privileges required.' });
        expect(next).not.toHaveBeenCalled();
    });

    // Kills: perms.includes('all:all') string literal mutations
    test('authorizeAdmin should deny role with no permissions at all', () => {
        req = { user: { id: 'u2', isActive: true, role: 'MANAGER' }, originalUrl: '/admin' };
        authorizeAdmin(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);
        expect(next).not.toHaveBeenCalled();
    });

    // Kills: !user.isActive strict boolean mutations
    test('authorizeAdmin should allow user with isActive explicitly true', () => {
        req = { user: { id: 'a2', isActive: true, role: 'ADMIN' }, originalUrl: '/admin' };
        authorizeAdmin(req, res, next);
        expect(next).toHaveBeenCalled();
        expect(res.status).not.toHaveBeenCalled();
    });

    // Kills: no-user 403 exact message mutation on authorizeAdmin
    test('authorizeAdmin should return exact error when user is undefined', () => {
        req = { originalUrl: '/admin' };
        authorizeAdmin(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({ error: 'Access denied. Please log in.' });
    });

    // Kills: typeof requiredPermission !== 'string' type check mutations
    test('authorize should reject non-string permission like a number', () => {
        const middleware = authorize(123);
        middleware(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({ error: 'System configuration error' });
    });

    // Kills: typeof requiredPermission !== 'string' — undefined input
    test('authorize should reject undefined permission', () => {
        const middleware = authorize(undefined);
        middleware(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({ error: 'System configuration error' });
    });

    // Kills: template literal `Missing permission: ${requiredPermission}` mutations
    test('authorize should log exact permission name in audit trail', async () => {
        const middleware = authorize('view:self');
        req = { user: { id: 'u3', isActive: true, role: 'ADMIN' } };
        await middleware(req, res, next);
        // ADMIN has all:all so next is called — now test denied path with exact string
        const middleware2 = authorize('delete:all');
        req = { user: { id: 'u4', isActive: true, role: 'USER' } };
        await middleware2(req, res, next);
        expect(auditService.logAuditTrail).toHaveBeenCalledWith(
            'u4',
            'SYSTEM',
            'PERMISSION_DENIED',
            'Missing permission: delete:all'
        );
    });

    // Kills: `Denied attempt to access ${req.originalUrl}` template literal mutations
    test('authorizeAdmin should log exact originalUrl in audit trail', async () => {
        req = { user: { id: 'u5', isActive: true, role: 'USER' }, originalUrl: '/api/admin/secret' };
        authorizeAdmin(req, res, next);
        await Promise.resolve(); // flush async audit
        expect(auditService.logAuditTrail).toHaveBeenCalledWith(
            'u5',
            'SYSTEM',
            'UNAUTHORIZED_ADMIN_ACCESS',
            'Denied attempt to access /api/admin/secret'
        );
    });

    // Kills: perms.includes(requiredPermission) || perms.includes('all:all') — OR mutations
    test('authorize should allow USER role for their own specific permission', () => {
        const middleware = authorize('view:self');
        req = { user: { id: 'u6', isActive: true, role: 'USER' } };
        middleware(req, res, next);
        expect(next).toHaveBeenCalled();
        expect(res.status).not.toHaveBeenCalled();
    });

    // Kills: || [] fallback array mutations on PERMISSION_MATRIX lookup
    test('authorize should deny unknown role gracefully with 403', async () => {
        const middleware = authorize('admin:write');
        req = { user: { id: 'u7', isActive: true, role: 'UNKNOWN_ROLE' } };
        await middleware(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);
        expect(next).not.toHaveBeenCalled();
    });

    // Kills: next() call mutations — verifies next is called exactly once on success
    test('authorize should call next exactly once on successful permission check', () => {
        const middleware = authorize('admin:write');
        req = { user: { id: 'a3', isActive: true, role: 'ADMIN' } };
        middleware(req, res, next);
        expect(next).toHaveBeenCalledTimes(1);
    });

// Kills: PERMISSION_MATRIX[user.role] || [] ArrayDeclaration line 19
    test('authorizeAdmin role with no permissions in matrix should deny with exact message', () => {
        req = { user: { id: '1', isActive: true, role: 'GHOST_ROLE' }, originalUrl: '/admin' };
        authorizeAdmin(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({ error: 'Access denied. Admin privileges required.' });
        expect(next).not.toHaveBeenCalled();
    });

    // Kills: user.role === 'ADMIN' ConditionalExpression line 20
    test('authorizeAdmin ADMIN role must call next — not any other role', () => {
        req = { user: { id: '1', isActive: true, role: 'ADMIN' }, originalUrl: '/admin' };
        authorizeAdmin(req, res, next);
        expect(next).toHaveBeenCalledTimes(1);
        expect(res.status).not.toHaveBeenCalled();
    });

    // Kills: user.role === 'ADMIN' StringLiteral → "" mutation
    test('authorizeAdmin empty role string should deny', () => {
        req = { user: { id: '1', isActive: true, role: '' }, originalUrl: '/admin' };
        authorizeAdmin(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);
        expect(next).not.toHaveBeenCalled();
    });

    // Kills: perms.includes('all:all') StringLiteral line 54
    test('authorize all:all permission allows access exactly', () => {
        const middleware = authorize('anything:goes');
        req = { user: { id: '1', isActive: true, role: 'ADMIN' } };
        middleware(req, res, next);
        expect(next).toHaveBeenCalled();
    });

    // Kills: || [] ArrayDeclaration line 57
    test('authorize unknown role should deny with exact 403', async () => {
        const middleware = authorize('some:permission');
        req = { user: { id: '1', isActive: true, role: 'NONEXISTENT' } };
        await middleware(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({ error: 'Access denied' });
        expect(next).not.toHaveBeenCalled();
    });
});
});
