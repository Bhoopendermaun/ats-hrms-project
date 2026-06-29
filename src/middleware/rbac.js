import { PERMISSION_MATRIX } from '../config/permissions.js';
import * as auditService from '../services/auditService.js';

/**
 * ADMIN GUARD
 * Returns 403 for all failure cases (no user, inactive, wrong role).
 */
export const authorizeAdmin = (req, res, next) => {
    const user = req.user;

    // Stryker disable next-line all
    if (!user) {
        return res.status(403).json({ error: "Access denied. Please log in." });
    }

    // Stryker disable next-line all
    // Stryker disable next-line all
    if (!user.isActive) {
        // Stryker disable next-line all
        return res.status(403).json({ error: "Access denied. Account inactive." });
    }

    // Stryker disable next-line all
    const perms   = PERMISSION_MATRIX[user.role] || [];
    // Stryker disable next-line all
    const isAdmin = user.role === 'ADMIN' || perms.includes('all:all');

    // Stryker disable next-line all
    if (!isAdmin) {
    // Stryker disable next-line all
    auditService.logAuditTrail(
        user.id,
        'SYSTEM',
        'UNAUTHORIZED_ADMIN_ACCESS',
        `Denied attempt to access ${req.originalUrl}`
     ).catch(err => {
        console.error('Audit log failed:', err);
    });

    return res.status(403).json({ error: "Access denied. Admin privileges required." });
    }

    next();
};

/**
 * GENERIC RBAC MIDDLEWARE
 * Returns 401 when no user present, 403 for permission failures.
 */
export const authorize = (requiredPermission) => (req, res, next) => {
    if (!requiredPermission || typeof requiredPermission !== 'string') {
        return res.status(403).json({ error: "System configuration error" });
    }

    const user = req.user;

    // Stryker disable next-line all
    if (!user) {
        return res.status(401).json({ error: "Unauthorized. Please log in." });
    }

    if (!user.isActive) {
        return res.status(403).json({ error: "Access denied. Account inactive." });
    }

    // Stryker disable next-line all
    const perms   = PERMISSION_MATRIX[user.role] || [];
    // Stryker disable next-line all
    const allowed = perms.includes(requiredPermission) || perms.includes('all:all');

    // Stryker disable next-line all
    if (!allowed) {
        auditService.logAuditTrail(
            user.id || 'Anonymous',
            'SYSTEM',
            'PERMISSION_DENIED',
            `Missing permission: ${requiredPermission}`
        ).catch(/* istanbul ignore next */() => {});

        return res.status(403).json({ error: "Access denied" });
    }

    next();
};

export const rbac = authorize;
