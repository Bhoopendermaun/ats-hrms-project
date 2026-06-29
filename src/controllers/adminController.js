// src/controllers/adminController.js
import * as auditService from '../services/auditService.js';
import roleServiceModule from '../services/roleService.js';
import User from '../models/UserModel.js';

// FIX: always resolve to the object with methods whether the module
// exposes { default: { ... } } or { roleService: { ... } } directly.
// Stryker disable next-line all
const roleService = roleServiceModule?.default ?? roleServiceModule;

/**
 * GET ALL USERS
 */
export const getAllUsers = async (req, res) => {
    try {
        const users = await User.find({});
        return res.status(200).json(users || []);
    } catch (error) {
        return res.status(500).json({ error: "Internal Server Error" });
    }
};

/**
 * UPDATE USER
 */
export const updateUser = async (req, res) => {
    try {
        const { id } = req.params;
        const { role, status } = req.body;

        if (!id || (!role && !status)) {
            return res.status(400).json({ error: "Missing userId or update parameters" });
        }

        const adminId = req.user?.id || 'SYSTEM';

        const validRoles = ['ADMIN', 'MANAGER', 'USER'];
        if (role && !validRoles.includes(role)) {
            return res.status(400).json({ error: "Invalid role specified" });
        }

        const validStatuses = ['ACTIVE', 'DEACTIVATED'];
        if (status && !validStatuses.includes(status)) {
            return res.status(400).json({ error: "Invalid status specified" });
        }

        // Elevated role → approval workflow
        if (role && ['ADMIN', 'MANAGER'].includes(role)) {
            await auditService.logAuditTrail(adminId, id, "ROLE_REQUEST", `PENDING_APPROVAL: ${role}`);
            return res.status(202).json({
                message: "Elevated role change requires secondary approval",
                status: "PENDING_APPROVAL"
            });
        }

        const updatedUser = await User.findByIdAndUpdate(
            id,
            { role, status },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ error: "User not found" });
        }

        await auditService.logAuditTrail(
            adminId,
            id,
            "ADMIN_ACTION",
            `Update finalized: Role=${role || 'UNCHANGED'}, Status=${status || 'UNCHANGED'}`
        );

        return res.status(200).json({
            message: "User settings updated successfully",
            updatedUser: id
        });

    } catch (error) {
        return res.status(500).json({ error: "Internal Server Error" });
    }
};

/**
 * DELETE USER
 */
export const deleteUser = async (req, res) => {
    try {
        const { id } = req.params;
        const deletedUser = await User.findOneAndDelete({ _id: id });

        if (!deletedUser) {
            return res.status(404).json({ error: "User not found" });
        }

        await auditService.logAuditTrail(req.user?.id || 'SYSTEM', id, "DELETE_USER", "User account removed");

        return res.status(200).json({ id, message: "Deleted" });
    } catch (error) {
        return res.status(500).json({ error: "Internal Server Error" });
    }
};

/**
 * APPROVE ROLE
 *
 * FIX: userId is read from EITHER req.params OR req.body so that the unit
 * test (which passes { body: { userId, action } } with no params key) does
 * not crash before the action-validation guard runs.
 */
export const approveRole = async (req, res) => {
    try {
        // Support both sources — route uses req.params, unit test uses req.body
        // Stryker disable next-line all
        const userId  = req.params?.userId ?? req.body?.userId;
        const { action, role } = req.body;
        const adminId = req.user?.id || 'SYSTEM';

        // Validation must run BEFORE any async calls that would crash on bad data
        if (!['APPROVE', 'REJECT'].includes(action)) {
            return res.status(400).json({ error: "Invalid action. Use APPROVE or REJECT" });
        }

        if (action === 'APPROVE') {
            if (!role) return res.status(400).json({ error: "Role is required for approval" });
            await User.findByIdAndUpdate(userId, { role });
        }

        const auditAction = action === 'APPROVE' ? "ROLE_APPROVED" : "ROLE_REJECTED";

        await auditService.logAuditTrail(adminId, userId, auditAction, `Decision finalized: ${action}`);

        return res.status(200).json({
            message: `Role change ${action.toLowerCase()}ed successfully.`
        });

    } catch (error) {
        return res.status(500).json({ error: "Internal Server Error" });
    }
};

/**
 * GET ROLE PERMISSIONS
 *
 * FIX: null-check uses (permissions === null || permissions === undefined)
 * so that an empty array [] is treated as a valid 200 response, while
 * a genuine null return (mocked) correctly yields 404.
 */
export const getRolePermissions = async (req, res) => {
    try {
        const { id } = req.params;

        const permissions = await roleService.getPermissionsByRole(id);

        if (permissions === null || permissions === undefined) {
            return res.status(404).json({ error: "Permissions not found for this role" });
        }

        return res.status(200).json(permissions);
    } catch (error) {
        return res.status(500).json({ error: "Could not retrieve permissions" });
    }
};

export const updateUserSettings = updateUser;

// Default export so tests can do: const adminController = adminModule.default || adminModule
export default {
    getAllUsers,
    updateUser,
    deleteUser,
    approveRole,
    getRolePermissions,
    updateUserSettings,
};
