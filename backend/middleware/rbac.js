/**
 * ROLE-BASED ACCESS CONTROL (RBAC) MIDDLEWARE
 * 
 * SECURITY CONCEPT: AUTHORIZATION
 * 
 * This implements an Access Control Matrix to enforce permissions:
 * - User: Can create and view own capsules
 * - Admin: Can manage users but CANNOT read capsule contents
 * - Auditor: Can view audit logs but CANNOT access capsules
 * 
 * This demonstrates the principle of least privilege.
 */

/**
 * ACCESS CONTROL MATRIX
 * 
 * Defines what each role can do:
 * 
 * | Role    | Create Capsule | View Own Capsule | View All Capsules | Manage Users | View Audit Logs |
 * |---------|----------------|------------------|-------------------|--------------|-----------------|
 * | user    | ✓              | ✓                | ✗                 | ✗            | ✗               |
 * | admin   | ✗              | ✗                | ✗ (metadata only) | ✓            | ✗               |
 * | auditor | ✗              | ✗                | ✗                 | ✗            | ✓               |
 */

const PERMISSIONS = {
    user: {
        canCreateCapsule: true,
        canViewOwnCapsule: true,
        canDeleteOwnCapsule: true,
        canManageUsers: false,
        canViewAuditLogs: false,
        canReadCapsuleContent: true // Only own capsules
    },
    admin: {
        canCreateCapsule: false,
        canViewOwnCapsule: false,
        canDeleteOwnCapsule: false,
        canManageUsers: true,
        canViewAuditLogs: false,
        canReadCapsuleContent: false // Cannot read any capsule content
    },
    auditor: {
        canCreateCapsule: false,
        canViewOwnCapsule: false,
        canDeleteOwnCapsule: false,
        canManageUsers: false,
        canViewAuditLogs: true,
        canReadCapsuleContent: false // Cannot read capsule content
    }
};

/**
 * Middleware to check if user has required role
 */
function requireRole(...allowedRoles) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required.'
            });
        }

        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                message: `Access denied. Required role: ${allowedRoles.join(' or ')}. Your role: ${req.user.role}`
            });
        }

        next();
    };
}

/**
 * Middleware to check specific permission
 */
function requirePermission(permission) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required.'
            });
        }

        const userPermissions = PERMISSIONS[req.user.role];

        if (!userPermissions || !userPermissions[permission]) {
            return res.status(403).json({
                success: false,
                message: `Access denied. You do not have permission: ${permission}`
            });
        }

        next();
    };
}

/**
 * Check if user can access a specific capsule
 */
function canAccessCapsule(req, res, next) {
    const userRole = req.user.role;

    // Only users can access their own capsules
    if (userRole !== 'user') {
        return res.status(403).json({
            success: false,
            message: 'Only users with role "user" can access capsules.'
        });
    }

    next();
}

module.exports = {
    PERMISSIONS,
    requireRole,
    requirePermission,
    canAccessCapsule
};
