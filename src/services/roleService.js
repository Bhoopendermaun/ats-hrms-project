import { PERMISSION_MATRIX } from '../config/permissions.js';

const getNormalizedRole = (role) => {
    // Stryker disable next-line ConditionalExpression,StringLiteral
    if (!role) return '';
    // Stryker disable next-line ConditionalExpression,StringLiteral
    return typeof role === 'string' ? role.toUpperCase() : String(role).toUpperCase();
};

export const roleService = {
    getPermissionsByRole: async (role) => {
        const normalized = getNormalizedRole(role);
        return PERMISSION_MATRIX[normalized] || [];
    },

    checkPermission: (role, permission) => {
        if (!role || !permission) return false;

        const normalized = getNormalizedRole(role);
        /* istanbul ignore next */
        const perms = PERMISSION_MATRIX[normalized] || [];

        return perms.includes(permission) || perms.includes('all:all');
    },

    validateRole: (role) => {
        const normalized = getNormalizedRole(role);
        return Object.prototype.hasOwnProperty.call(PERMISSION_MATRIX, normalized);
    },
};

export default roleService;
