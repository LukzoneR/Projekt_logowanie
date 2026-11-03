

const ROLES = {
  ADMINISTRATOR: 'Administrator',
  PRACOWNIK: 'Pracownik',
  GOSC: 'Gość'
};

const PERMISSIONS = {
  ADMIN_ACCESS: 'admin:access',
  USERS_MANAGE: 'users:manage',
  POLICY_MANAGE: 'policy:manage',
  
  EMPLOYEE_ACCESS: 'employee:access',
  
  GUEST_ACCESS: 'guest:access'
};

const ROLE_PERMISSIONS = {
  [ROLES.ADMINISTRATOR]: [
    PERMISSIONS.ADMIN_ACCESS,
    PERMISSIONS.USERS_MANAGE,
    PERMISSIONS.POLICY_MANAGE,
    PERMISSIONS.EMPLOYEE_ACCESS,
    PERMISSIONS.GUEST_ACCESS
  ],
  [ROLES.PRACOWNIK]: [
    PERMISSIONS.EMPLOYEE_ACCESS,
    PERMISSIONS.GUEST_ACCESS
  ],
  [ROLES.GOSC]: [
    PERMISSIONS.GUEST_ACCESS
  ]
};

/**
 * Sprawdza, czy dana rola posiada określone uprawnienie
 * @param {string} role 
 * @param {string} permission 
 * @returns {boolean}
 */
function hasPermission(role, permission) {
  const permissions = ROLE_PERMISSIONS[role] || [];
  return permissions.includes(permission);
}

/**
 * Zwraca listę uprawnień dla danej roli
 * @param {string} role 
 * @returns {string[]}
 */
function getRolePermissions(role) {
  return ROLE_PERMISSIONS[role] || [];
}

module.exports = {
  ROLES,
  PERMISSIONS,
  ROLE_PERMISSIONS,
  hasPermission,
  getRolePermissions
};
