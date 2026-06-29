import { jest } from '@jest/globals';

process.env.JWT_SECRET = 'test-auth-controller-secret';

// =============================================================
// MOCKS — must be declared before imports
// =============================================================

// Mock the loginApi dependency
jest.unstable_mockModule('../src/controllers/__mocks__/api.js', () => ({
    loginApi: jest.fn(),
}));

// =============================================================
// IMPORTS (after mocks)
// =============================================================
const { loginApi } = await import('../src/controllers/__mocks__/api.js');
const { handleLogin } = await import('../src/controllers/auth.controller.js');

// =============================================================
// SUITE
// =============================================================
describe('Auth Controller - handleLogin', () => {

    beforeEach(() => {
        jest.clearAllMocks();
    });

    // ─────────────────────────────────────────────────────────
    // Input validation — AC3: cannot proceed with missing fields
    // ─────────────────────────────────────────────────────────

    // Kills: BlockStatement, ObjectLiteral, StringLiteral mutants on the guard
    test('should return error when email is missing', async () => {
        const result = await handleLogin('', 'password123');
        expect(result).toEqual({ error: 'Fields cannot be empty' });
        expect(loginApi).not.toHaveBeenCalled();
    });

    test('should return error when password is missing', async () => {
        const result = await handleLogin('user@test.com', '');
        expect(result).toEqual({ error: 'Fields cannot be empty' });
        expect(loginApi).not.toHaveBeenCalled();
    });

    test('should return error when both email and password are missing', async () => {
        const result = await handleLogin('', '');
        expect(result).toEqual({ error: 'Fields cannot be empty' });
        expect(loginApi).not.toHaveBeenCalled();
    });

    // Kills: BooleanLiteral mutant — !email || password (removes ! from password)
    test('should return error when email is null', async () => {
        const result = await handleLogin(null, 'password123');
        expect(result).toEqual({ error: 'Fields cannot be empty' });
        expect(loginApi).not.toHaveBeenCalled();
    });

    // Kills: BooleanLiteral mutant — email || !password (removes ! from email)
    test('should return error when password is null', async () => {
        const result = await handleLogin('user@test.com', null);
        expect(result).toEqual({ error: 'Fields cannot be empty' });
        expect(loginApi).not.toHaveBeenCalled();
    });

    // Kills: LogicalOperator mutant — !email && !password (changes || to &&)
    test('should proceed when both email and password are provided', async () => {
        loginApi.mockResolvedValue({ id: '1', role: 'USER' });
        const result = await handleLogin('user@test.com', 'password123');
        expect(result.token).toBeDefined();
        expect(loginApi).toHaveBeenCalledWith('user@test.com', 'password123');
    });

    // ─────────────────────────────────────────────────────────
    // Successful login
    // ─────────────────────────────────────────────────────────

    // Kills: BlockStatement (try body → {}), ObjectLiteral, StringLiteral mutants
    test('should return token, message, and role on successful login', async () => {
        loginApi.mockResolvedValue({ id: 'user-1', role: 'ADMIN' });

        const result = await handleLogin('admin@test.com', 'securepass');

        // Kills: ObjectLiteral → {} and StringLiteral message → ""
        expect(result.message).toBe('Login successful');
        expect(result.role).toBe('ADMIN');
        expect(result.token).toBeDefined();
        expect(result.error).toBeUndefined();
    });

    // Kills: ObjectLiteral { id: user.id, role: user.role } → {}
    test('should embed correct id and role in JWT payload', async () => {
        const { default: jwt } = await import('jsonwebtoken');
        loginApi.mockResolvedValue({ id: 'user-42', role: 'MANAGER' });

        const result = await handleLogin('manager@test.com', 'pass');

        const decoded = jwt.verify(result.token, process.env.JWT_SECRET);
        // Kills: ObjectLiteral {} — payload must contain both id and role
        expect(decoded.id).toBe('user-42');
        expect(decoded.role).toBe('MANAGER');
    });

    // Kills: StringLiteral '1h' → "" — token must actually expire
    test('should issue token that expires in 1 hour', async () => {
        const { default: jwt } = await import('jsonwebtoken');
        loginApi.mockResolvedValue({ id: 'user-1', role: 'USER' });

        const result = await handleLogin('user@test.com', 'pass');

        const decoded = jwt.verify(result.token, process.env.JWT_SECRET);
        const issuedAt = decoded.iat;
        const expiresAt = decoded.exp;

        // exp - iat should be 3600 seconds (1 hour)
        expect(expiresAt - issuedAt).toBe(3600);
    });

    // Kills: ConditionalExpression + LogicalOperator on JWT_SECRET || 'dev_backup_secret'
    test('should use JWT_SECRET from environment when set', async () => {
        const { default: jwt } = await import('jsonwebtoken');
        loginApi.mockResolvedValue({ id: 'u1', role: 'USER' });

        const result = await handleLogin('user@test.com', 'pass');

        // Token must be verifiable with the env secret — not the fallback
        expect(() => jwt.verify(result.token, process.env.JWT_SECRET)).not.toThrow();
    });

    // Kills: ConditionalExpression process.env.JWT_SECRET → false/true
    test('should fall back to dev_backup_secret when JWT_SECRET is not set', async () => {
        const { default: jwt } = await import('jsonwebtoken');
        loginApi.mockResolvedValue({ id: 'u1', role: 'USER' });

        const original = process.env.JWT_SECRET;
        delete process.env.JWT_SECRET;

        const result = await handleLogin('user@test.com', 'pass');

        // Token must be verifiable with the fallback secret
        expect(() => jwt.verify(result.token, 'dev_backup_secret')).not.toThrow();
        expect(result.message).toBe('Login successful');

        process.env.JWT_SECRET = original; // restore
    });

    // ─────────────────────────────────────────────────────────
    // Error handling
    // ─────────────────────────────────────────────────────────

    // Kills: BlockStatement catch → {}, ObjectLiteral → {}
    test('should return error message when loginApi throws', async () => {
        loginApi.mockRejectedValue(new Error('Invalid credentials'));

        const result = await handleLogin('user@test.com', 'wrongpass');

        // Kills: ObjectLiteral { error: error.message } → {}
        expect(result).toEqual({ error: 'Invalid credentials' });
        expect(result.token).toBeUndefined();
    });

    test('should return error message when loginApi throws a network error', async () => {
        loginApi.mockRejectedValue(new Error('Network timeout'));

        const result = await handleLogin('user@test.com', 'pass');

        expect(result.error).toBe('Network timeout');
    });

    // Kills: StringLiteral message → "" in error response
    test('should preserve the exact error message from the thrown error', async () => {
        const exactMessage = 'Account suspended — contact administrator';
        loginApi.mockRejectedValue(new Error(exactMessage));

        const result = await handleLogin('user@test.com', 'pass');

        expect(result.error).toBe(exactMessage);
    });

    // ─────────────────────────────────────────────────────────
    // Role propagation
    // ─────────────────────────────────────────────────────────

    // Ensures role is correctly passed through for all valid roles
    test('should correctly propagate USER role', async () => {
        loginApi.mockResolvedValue({ id: 'u1', role: 'USER' });
        const result = await handleLogin('user@test.com', 'pass');
        expect(result.role).toBe('USER');
    });

    test('should correctly propagate MANAGER role', async () => {
        loginApi.mockResolvedValue({ id: 'u2', role: 'MANAGER' });
        const result = await handleLogin('manager@test.com', 'pass');
        expect(result.role).toBe('MANAGER');
    });

    test('should correctly propagate ADMIN role', async () => {
        loginApi.mockResolvedValue({ id: 'u3', role: 'ADMIN' });
        const result = await handleLogin('admin@test.com', 'pass');
        expect(result.role).toBe('ADMIN');
    });
});
