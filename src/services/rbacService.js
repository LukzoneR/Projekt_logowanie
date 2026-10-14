// Model RBAC (Role-Based Access Control)
// Wariant 5: Administrator, Pracownik, Gość

const ROLES = {
  ADMINISTRATOR: 'Administrator',
  PRACOWNIK: 'Pracownik',
  GOSC: 'Gość'
};

const PERMISSIONS = {
  // Uprawnienia administracyjne
  ADMIN_ACCESS: 'admin:access',
  USERS_MANAGE: 'users:manage',
  POLICY_MANAGE: 'policy:manage',
  
  // Uprawnienia do strefy pracownika
  EMPLOYEE_ACCESS: 'employee:access',
  
  // Uprawnienia do strefy gościa
  GUEST_ACCESS: 'guest:access'
};

// Mapowanie uprawnień do ról
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
