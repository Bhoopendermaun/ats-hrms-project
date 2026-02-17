
// src/config/permissions.js
export const ROLES = {
  ADMIN: 'ADMIN',
  EDITOR: 'EDITOR',
  USER: 'USER',
};

export const PERMISSION_MATRIX = {
  [ROLES.ADMIN]: ['all:all'], // Updated to match the rbac.js check
  [ROLES.EDITOR]: ['read:content', 'write:content', 'update:content'],
  [ROLES.USER]: ['read:content'],
};
