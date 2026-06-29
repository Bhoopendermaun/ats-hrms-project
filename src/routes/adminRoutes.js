import express from 'express';
import { updateUserSettings, approveRole, getRolePermissions } from '../controllers/adminController.js';
import { authenticate } from '../middleware/auth.js';
import { authorize, authorizeAdmin } from '../middleware/rbac.js';

const router = express.Router();

/**
 * AC #5 & #6: APIs documented and secured (admin-only).
 * Applying global security to ALL routes in this file.
 */
router.use(authenticate);
router.use(authorizeAdmin); // Ensures ONLY admins can hit any of these paths

/**
 * AC #3: Admin can assign/update/revoke roles and deactivate users.
 * Use PATCH for partial updates to user settings.
 */
router.patch('/manage-user', updateUserSettings);

/**
 * NEW: Approval Workflow Endpoint (Finalize Decision)
 * Requirement: Support optional approval workflow for elevated roles.
 */
router.post('/approve-role/:userId', approveRole);

/**
 * NEW: Permission Management API
 * Requirement: Build admin APIs to manage... permissions.
 */
router.get('/permissions', getRolePermissions);

export default router;
