// config/permissions.js
export const ROLES = {
  ADMIN: 'ADMIN',
  EDITOR: 'EDITOR',
  USER: 'USER',
};

export const PERMISSION_MATRIX = {
  [ROLES.ADMIN]: ['all'], // Wildcard for full access
  [ROLES.EDITOR]: ['read:content', 'write:content', 'update:content'],
  [ROLES.USER]: ['read:content'],
};
