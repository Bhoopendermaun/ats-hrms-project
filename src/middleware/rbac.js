// middleware/rbac.js
import { PERMISSION_MATRIX, ROLES } from '../config/permissions.js';

export const authorize = (requiredPermission) => {
  return (req, res, next) => {
    const user = req.user;

    // 1. Auth Check (AC #1 & #2)
    if (!user) {
      return res.status(401).json({ error: "Authentication required" });
    }

    // 2. Role/Permission Check (AC #3)
    const userPermissions = PERMISSION_MATRIX[user.role] || [];
    const hasPermission = userPermissions.includes(requiredPermission) || 
                          userPermissions.includes('all');

    if (!hasPermission) {
      // 3. Secure Logging (AC #5)
      console.warn(`[AUTH_FAILURE]: User ${user.id} denied access to ${requiredPermission}`);
      
      // 4. Forbidden Response (AC #2 & #5)
      return res.status(403).json({ error: "Access denied" }); 
    }

    next();
  };
};
