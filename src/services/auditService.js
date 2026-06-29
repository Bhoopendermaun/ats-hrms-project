// src/services/auditService.js

// 1. Named Export (Fixes 'logAuditTrail' failures)
export const logAuditTrail = (actorId, targetId, action, details) => {
    const timestamp = new Date().toISOString();
    const entry = {
        timestamp,
        actorId,
        targetId,
        action,
        details
    };

    console.log(`[AUDIT_LOG] ${JSON.stringify(entry)}`);
    return entry;
};

// 2. Object Export (Fixes 'auditService' failures in RBAC/Security tests)
export const auditService = {
    logAuditTrail
};

// 3. Default Export (Safety net for 'import auditService from...')
export default auditService;
