import { OAuthAccountSchema } from '../src/models/OAuthAccount.js';

describe('OAuthAccount Schema', () => {

    test('should export OAuthAccountSchema as an object', () => {
        expect(typeof OAuthAccountSchema).toBe('object');
        expect(OAuthAccountSchema).not.toBeNull();
    });

    test('should have userId field with required:true', () => {
        expect(OAuthAccountSchema.userId).toBeDefined();
        expect(OAuthAccountSchema.userId.required).toBe(true);
    });

    test('should have provider field with required:true', () => {
        expect(OAuthAccountSchema.provider).toBeDefined();
        expect(OAuthAccountSchema.provider.required).toBe(true);
    });

    test('should have providerUserId field with required:true', () => {
        expect(OAuthAccountSchema.providerUserId).toBeDefined();
        expect(OAuthAccountSchema.providerUserId.required).toBe(true);
    });

    test('should have providerEmail field with required:true', () => {
        expect(OAuthAccountSchema.providerEmail).toBeDefined();
        expect(OAuthAccountSchema.providerEmail.required).toBe(true);
    });

    test('should have linkedAt field with a default date function', () => {
        expect(OAuthAccountSchema.linkedAt).toBeDefined();
        expect(typeof OAuthAccountSchema.linkedAt.default).toBe('function');
        // default() should return a Date
        expect(OAuthAccountSchema.linkedAt.default()).toBeInstanceOf(Date);
    });

    test('linkedAt default should return current date', () => {
        const before = Date.now();
        const result = OAuthAccountSchema.linkedAt.default();
        const after  = Date.now();
        expect(result.getTime()).toBeGreaterThanOrEqual(before);
        expect(result.getTime()).toBeLessThanOrEqual(after);
    });
});
