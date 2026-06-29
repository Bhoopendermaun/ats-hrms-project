import mongoose from 'mongoose';

const VALID_ROLES = ['ADMIN', 'MANAGER', 'USER'];

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },

    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },

    password: {
        type: String,
        required: true,
        select: false
    },

    role: {
        type: String,
        enum: VALID_ROLES,
        default: 'USER',
        index: true
    },

    isActive: {
        type: Boolean,
        default: true,
        index: true
    },

    pendingRole: {
        type: String,
        enum: VALID_ROLES,
        default: null
    }
}, {
    timestamps: true
});

/**
 * SECURITY LAYER: Prevent invalid role injection
 */
userSchema.pre('save', function (next) {
    if (this.role && !VALID_ROLES.includes(this.role)) {
        return next(new Error('Invalid role assignment detected'));
    }

    if (this.pendingRole && !VALID_ROLES.includes(this.pendingRole)) {
        return next(new Error('Invalid pending role detected'));
    }

    next();
});

/**
 * SECURITY: Block role tampering via update operations
 */
userSchema.pre(['findOneAndUpdate', 'updateOne'], function (next) {
    const update = this.getUpdate();
    
    // Check both flat updates and $set updates
    const role = update.role || (update.$set && update.$set.role);
    const pendingRole = update.pendingRole || (update.$set && update.$set.pendingRole);

    if (role && !VALID_ROLES.includes(role)) {
        return next(new Error('Invalid role update blocked'));
    }

    if (pendingRole && !VALID_ROLES.includes(pendingRole)) {
        return next(new Error('Invalid pending role update blocked'));
    }

    next();
});


const User = mongoose.model('User', userSchema);

export { User };
export default User;
