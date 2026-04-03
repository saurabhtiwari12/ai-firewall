'use strict';

/**
 * Role hierarchy: admin > analyst > viewer
 * requireRole('admin', 'analyst') allows both admin and analyst users.
 */
const ROLE_WEIGHTS = { viewer: 1, analyst: 2, admin: 3 };

/**
 * Factory: returns middleware that restricts access to the listed roles.
 * @param {...string} roles - Allowed roles.
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, message: 'Authentication required' });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: `Access denied. Required role(s): ${roles.join(', ')}`,
      });
    }

    return next();
  };
}

/**
 * Factory: returns middleware that enforces a minimum role level.
 * e.g. requireMinRole('analyst') allows analyst and admin.
 * @param {string} minRole
 */
function requireMinRole(minRole) {
  const minWeight = ROLE_WEIGHTS[minRole] ?? 1;
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, message: 'Authentication required' });
    }
    const userWeight = ROLE_WEIGHTS[req.user.role] ?? 0;
    if (userWeight < minWeight) {
      return res.status(403).json({
        success: false,
        message: `Access denied. Minimum required role: ${minRole}`,
      });
    }
    return next();
  };
}

module.exports = { requireRole, requireMinRole };
