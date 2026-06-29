// src/config/permissions.js

export const ROLES = {
  ADMIN: 'ADMIN',
  MANAGER: 'MANAGER',
  USER: 'USER',
};

export const PERMISSION_MATRIX = {
  [ROLES.ADMIN]: [
    'all:all',
    'manage:users',
    'view:logs',
    'manage:roles',
    'approve:roles'
  ],

  [ROLES.MANAGER]: [
    'read:users',
    'edit:users',
    'view:reports'
  ],

  [ROLES.USER]: [
    'read:self'
  ],
};
