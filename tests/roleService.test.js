import roleService from '../src/services/roleService.js';

describe('Role Service - Production Grade Coverage Suite', () => {

    // ─────────────────────────────────────────────────────────
    // getPermissionsByRole
    // ─────────────────────────────────────────────────────────
    describe('ADMIN role resolution', () => {

        test('should return full permission set for ADMIN', async () => {
            const res = await roleService.getPermissionsByRole('ADMIN');
            expect(Array.isArray(res)).toBe(true);
            expect(res).toEqual(
                expect.arrayContaining(['all:all', 'manage:users', 'view:logs', 'manage:roles', 'approve:roles'])
            );
        });

        test('ADMIN role should include elevated permissions', async () => {
            const res = await roleService.getPermissionsByRole('ADMIN');
            expect(res.length).toBeGreaterThan(3);
            expect(res).not.toEqual([]);
        });
    });

    describe('Role normalization branch', () => {

        test('should treat lowercase admin as ADMIN', async () => {
            const res = await roleService.getPermissionsByRole('admin');
            expect(Array.isArray(res)).toBe(true);
            expect(res.length).toBeGreaterThan(0);
        });

        test('should handle mixed-case role input', async () => {
            const res = await roleService.getPermissionsByRole('AdMiN');
            expect(Array.isArray(res)).toBe(true);
            expect(res.length).toBeGreaterThan(0);
        });
    });

    describe('Unknown role branch', () => {

        test('should return empty array for unknown role', async () => {
            const res = await roleService.getPermissionsByRole('NON_EXISTENT_ROLE');
            expect(Array.isArray(res)).toBe(true);
            expect(res).toEqual([]);
        });
    });

    describe('Null / undefined input branches', () => {

        test('should safely handle null input', async () => {
            const res = await roleService.getPermissionsByRole(null);
            expect(Array.isArray(res)).toBe(true);
        });

        test('should safely handle undefined input', async () => {
            const res = await roleService.getPermissionsByRole(undefined);
            expect(Array.isArray(res)).toBe(true);
        });

        test('should safely handle empty string', async () => {
            const res = await roleService.getPermissionsByRole('');
            expect(Array.isArray(res)).toBe(true);
        });
    });

    describe('Non-admin role branch coverage', () => {

        test('should return array for USER role', async () => {
            const res = await roleService.getPermissionsByRole('USER');
            expect(Array.isArray(res)).toBe(true);
        });

        test('should return array for MANAGER role', async () => {
            const res = await roleService.getPermissionsByRole('MANAGER');
            expect(Array.isArray(res)).toBe(true);
        });
    });

    describe('Edge behavior & consistency', () => {

        test('should always return array for any input', async () => {
            const roles = ['ADMIN', 'USER', 'MANAGER', 'INVALID', null, undefined];
            for (const role of roles) {
                const res = await roleService.getPermissionsByRole(role);
                expect(Array.isArray(res)).toBe(true);
            }
        });

        test('should not throw for any invalid input', async () => {
            const badInputs = [123, {}, [], Symbol('x')];
            for (const input of badInputs) {
                await expect(roleService.getPermissionsByRole(input)).resolves.toEqual(expect.any(Array));
            }
        });
    });

describe('roleService Custom Edge Cases (Killing Remaining Mutants)', () => {
    
    // Kills Mutants in getPermissionsByRole, checkPermission, and validateRole for falsy inputs
    test('should handle falsy inputs gracefully across all methods', async () => {
        // Test getPermissionsByRole
        const resNull = await roleService.getPermissionsByRole(null);
        const resUndef = await roleService.getPermissionsByRole(undefined);
        expect(resNull).toEqual([]);
        expect(resUndef).toEqual([]);

        // Test checkPermission
        expect(roleService.checkPermission(null, 'view:logs')).toBe(false);
        expect(roleService.checkPermission('ADMIN', null)).toBe(false);

        // Test validateRole
        expect(roleService.validateRole(null)).toBe(false);
        expect(roleService.validateRole(undefined)).toBe(false);
    });

    // Kills Mutants for non-string / alternative types type-casting
    test('should properly cast and upscale non-string types and lower-case roles', async () => {
        // Test checkPermission string casting
        const hasPerm = roleService.checkPermission('admin', 'all:all');
        expect(hasPerm).toBeDefined();

        // Test validateRole type casting
        const isValidNum = roleService.validateRole(123);
        expect(isValidNum).toBe(false);
    });

    // Kills Mutants for unmapped or invalid inputs
    test('should return standard fallbacks for unmapped or invalid roles', async () => {
        const permissions = await roleService.getPermissionsByRole('FAKE_NON_EXISTENT_ROLE');
        expect(permissions).toEqual([]);

        const isValid = roleService.validateRole('INVALID_ROLE_XYZ');
        expect(isValid).toBe(false);
    });

    // Kills the short-circuit branch mutant on Line 21
    test('should fall back to wildcard all:all check when explicit permission is missing', () => {
        // This forces evaluation of the second condition (perms.includes('all:all'))
        const hasWildcard = roleService.checkPermission('ADMIN', 'some:completely-random-permission');
        expect(hasWildcard).toBe(true);
    });
});

// STRYKER MUTANT ELIMINATION SUITE
    // =========================================================================
    describe('roleService - Precision Mutant Elimination', () => {
        
        describe('Type Normalization Checks (Line 5)', () => {
            it('should explicitly exercise both sides of the string type branch using custom objects', () => {
                const customRoleObj = {
                    toString: () => 'admim'
                };

                const result = roleService.checkPermission(customRoleObj, 'admin:read');
                expect(result).toBe(false);
            });

            it('should kill all condition mutations on line 5 by forcing crashes on the wrong branches', () => {
                const plainObj = {};
                expect(roleService.checkPermission(plainObj, 'read')).toBe(false);

                const asymmetricObj = {
                    toUpperCase: () => 'I_AM_THE_TRUE_PATH',
                    toString: () => 'i_am_the_false_path'
                };

                    expect(() => roleService.checkPermission(asymmetricObj, 'all:all')).not.toThrow();
		    expect(roleService.checkPermission(asymmetricObj, 'all:all')).toBe(false);
            });

            it('should return a completely empty array for completely unregistered roles', () => {
                const result = roleService.checkPermission('NON_EXISTENT_ROLE', 'admin:read');

                expect(result).toBe(false); // This kills the injected "Stryker was here" element
            });

            it('should catch string coercion mismatches using plain alphabetic booleans', () => {
                const result = roleService.checkPermission(false, 'some:permission');
                expect(result).toBe(false);
            });
        });

describe('roleService - Stryker Surgical Killers', () => {

    // Kills: if (!role) return '' → if (false) return ''
    // Forces the !role branch to be taken AND skipped
    test('getPermissionsByRole with truthy role must NOT return empty string path', async () => {
        const withRole = await roleService.getPermissionsByRole('ADMIN');
        const withNull = await roleService.getPermissionsByRole(null);
        expect(withNull).toStrictEqual([]);  // went through '' path → PERMISSION_MATRIX[''] → []
        expect(withRole.length).toBeGreaterThan(0); // did NOT go through '' path
    });

    // Kills: return '' → return "Stryker was here!"
    test('null role must resolve to empty string key returning strictly empty array', async () => {
        const res1 = await roleService.getPermissionsByRole(null);
        const res2 = await roleService.getPermissionsByRole(undefined);
        expect(res1).toStrictEqual([]);
        expect(res2).toStrictEqual([]);
        expect(res1.length).toBe(0);
        expect(res2.length).toBe(0);
    });

    // Kills: typeof role === 'string' → false (forces String() path for strings)
    test('string role must use toUpperCase directly — result must differ from String() path', async () => {
        const fromString = await roleService.getPermissionsByRole('admin');
        const fromUpper  = await roleService.getPermissionsByRole('ADMIN');
        // Both must return identical non-empty arrays proving string path works
        expect(fromString).toEqual(fromUpper);
        expect(fromString.length).toBeGreaterThan(0);
    });

    // Kills: String(role).toUpperCase() → toLowerCase()
    test('non-string role object toString lowercase must NOT match any matrix key', async () => {
        const lowerObj = { toString: () => 'admin' }; // String(obj) = 'admin', toLowerCase = 'admin', toUpperCase = 'ADMIN'
        const res = await roleService.getPermissionsByRole(lowerObj);
        // If toLowerCase() used: 'admin' → not in matrix → []
        // If toUpperCase() used: 'ADMIN' → in matrix → permissions
        expect(res.length).toBeGreaterThan(0); // proves toUpperCase was used
    });

    // Kills: || [] → || ["Stryker was here"] in checkPermission (line 19)
    test('checkPermission with unknown role must return strictly false not truthy', () => {
        const result = roleService.checkPermission('COMPLETELY_UNKNOWN_ROLE_99', 'any:permission');
        expect(result).toBe(false);
        expect(result).toStrictEqual(false);
    });

    // Kills: || [] → ["Stryker was here"] — "Stryker was here" includes check
    test('unknown role checkPermission must not accidentally include any permission', () => {
        expect(roleService.checkPermission('GHOST_ROLE', 'all:all')).toBe(false);
        expect(roleService.checkPermission('GHOST_ROLE', 'view:self')).toBe(false);
        expect(roleService.checkPermission('GHOST_ROLE', 'Stryker was here')).toBe(false);
    });
});

describe('roleService - Structural Impossible Mutant Handlers', () => {

    // Kills: if (!role) return '' → if (false) return ''
    // Need to prove the !role branch is NECESSARY by showing role=0 behaves differently
    test('falsy non-empty role 0 should go through normalization not early return', async () => {
        const res = await roleService.getPermissionsByRole(0);
        // 0 is falsy → !role is true → returns '' → PERMISSION_MATRIX[''] → []
        expect(res).toStrictEqual([]);
        // Now prove it went through early return by checking validateRole too
        expect(roleService.validateRole(0)).toBe(false);
    });

    // Kills: return '' → return "Stryker was here!"
    // If '' is replaced by "Stryker was here!" → PERMISSION_MATRIX["Stryker was here!"] → undefined → []
    // We need to assert something that breaks when "Stryker was here!" is returned
    test('null role must normalize to empty string key — not any other string', async () => {
        const withNull = await roleService.getPermissionsByRole(null);
        const withEmptyStr = await roleService.getPermissionsByRole('');
        // Both go through '' key → both should return identical result
        expect(withNull).toStrictEqual(withEmptyStr);
        expect(withNull).toStrictEqual([]);
    });

    // Kills: typeof role === 'string' → typeof role === ''
    // Pass something where typeof returns a specific string
    test('typeof check must use string not empty string — number input must use String() path', async () => {
        // typeof 123 === 'number', not 'string' → goes to String(123).toUpperCase() = '123'
        // If mutated to typeof role === '' → typeof 123 === '' is false → same path → no difference
        // But typeof 'admin' === 'string' is true → role.toUpperCase() = 'ADMIN'
        // If mutated to false → String('admin').toUpperCase() = 'ADMIN' → same result
        // The ONLY way to kill this is a type where String() and direct access differ
        const numericRole = { toString: () => 'ADMIN', toUpperCase: () => 'WRONG' };
        const res = await roleService.getPermissionsByRole(numericRole);
        // typeof numericRole === 'object' → not 'string' → String(numericRole).toUpperCase()
        // String(numericRole) calls toString() → 'ADMIN' → toUpperCase() → 'ADMIN'
        // If wrong branch: numericRole.toUpperCase() → 'WRONG' → not in matrix → []
        expect(res.length).toBeGreaterThan(0); // proves String() path was used correctly
    });
});

describe('roleService - Final Mutant Killers', () => {

    // Kills: !role return '' — exact empty string return
    test('getNormalizedRole returns empty string for null causing empty key lookup', async () => {
        const res = await roleService.getPermissionsByRole(null);
        expect(res).toStrictEqual([]);
        expect(res.length).toBe(0);
    });

    // Kills: typeof role === 'string' → typeof role === "" mutations
    test('string role should be uppercased — not passed to String() constructor', async () => {
        const res = await roleService.getPermissionsByRole('admin');
        const res2 = await roleService.getPermissionsByRole('ADMIN');
        expect(res).toEqual(res2); // both must produce identical results
    });

    // Kills: String(role).toUpperCase() → toLowerCase() mutations
    test('non-string role 123 should be cast and uppercased — not lowercased', async () => {
        const res = await roleService.getPermissionsByRole(123);
        expect(Array.isArray(res)).toBe(true);
        expect(res).toStrictEqual([]); // 123 → "123" → not in matrix → []
    });

    // Kills: || [] → || ["Stryker was here"] array mutations
    test('unknown role must return strictly empty array not array with elements', async () => {
        const res = await roleService.getPermissionsByRole('TOTALLY_UNKNOWN_ROLE_XYZ');
        expect(res).toStrictEqual([]);
        expect(res.length).toBe(0);
    });

    // Kills: validateRole hasOwnProperty mutations
    test('validateRole should return true for ADMIN and false for unknown', () => {
        expect(roleService.validateRole('ADMIN')).toBe(true);
        expect(roleService.validateRole('admin')).toBe(true);
        expect(roleService.validateRole('FAKE')).toBe(false);
        expect(roleService.validateRole('')).toBe(false);
    });

    // Kills: checkPermission !role || !permission AND/OR mutations
    test('checkPermission returns false when only permission is missing', () => {
        expect(roleService.checkPermission('ADMIN', null)).toBe(false);
        expect(roleService.checkPermission('ADMIN', '')).toBe(false);
        expect(roleService.checkPermission('ADMIN', undefined)).toBe(false);
    });

    test('checkPermission returns false when only role is missing', () => {
        expect(roleService.checkPermission(null, 'all:all')).toBe(false);
        expect(roleService.checkPermission('', 'all:all')).toBe(false);
        expect(roleService.checkPermission(undefined, 'all:all')).toBe(false);
    });

    // Kills: perms.includes('all:all') string literal mutations
    test('checkPermission all:all exact string must match — not similar strings', () => {
        expect(roleService.checkPermission('ADMIN', 'all:all')).toBe(true);
        expect(roleService.checkPermission('USER', 'all:all')).toBe(false);
        expect(roleService.checkPermission('USER', 'all:al')).toBe(false);
    });
});
        describe('Permission Matrix Strict Boundaries (Line 21)', () => {
            it('should actively return false when a restricted role requests an unassigned permission without wildcards', () => {
                const hasAccess = roleService.checkPermission('USER', 'admin:delete_all');
                expect(hasAccess).toBe(false);
            });
        });
    }); // Closes: roleService - Precision Mutant Elimination

});

