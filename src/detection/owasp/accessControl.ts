import { SilkerEvent } from '../../types';

interface RoleMapping {
  [key: string]: string[];
}

const ADMIN_PATHS = ['/admin', '/administrator', '/manage', '/dashboard', '/control'];
const PRIVILEGED_PATHS = ['/api/admin', '/api/users', '/api/settings', '/api/config'];
const SENSITIVE_OPERATIONS = ['DELETE', 'PUT', 'PATCH'];

const DEFAULT_ROLE_MAPPING: RoleMapping = {
  admin: ['admin', 'administrator', 'root', 'superuser'],
  user: ['user', 'member', 'customer'],
  guest: ['guest', 'anonymous', 'public']
};

export function detectBrokenAccessControl(event: SilkerEvent, userRole?: string, allowedRoles?: string[]): boolean {
  if (!event.url) return false;

  const url = event.url.toLowerCase();
  const method = event.method.toUpperCase();

  for (const adminPath of ADMIN_PATHS) {
    if (url.includes(adminPath)) {
      if (!userRole || !isAuthorizedRole(userRole, ['admin'], allowedRoles)) {
        return true;
      }
    }
  }

  for (const privilegedPath of PRIVILEGED_PATHS) {
    if (url.includes(privilegedPath)) {
      if (!userRole || !isAuthorizedRole(userRole, ['admin'], allowedRoles)) {
        return true;
      }
    }
  }

  if (SENSITIVE_OPERATIONS.includes(method)) {
    if (!userRole || userRole === 'guest' || userRole === 'anonymous') {
      return true;
    }
  }

  if (method === 'DELETE' && !userRole) {
    return true;
  }

  return false;
}

export function detectPrivilegeEscalation(event: SilkerEvent, currentRole?: string, targetRole?: string): boolean {
  if (!currentRole || !targetRole) return false;

  const roleHierarchy = ['guest', 'user', 'admin', 'superuser'];
  const currentIndex = roleHierarchy.indexOf(currentRole.toLowerCase());
  const targetIndex = roleHierarchy.indexOf(targetRole.toLowerCase());

  if (targetIndex > currentIndex) {
    return true;
  }

  if (event.payload && typeof event.payload === 'object') {
    const roleChangePatterns = ['role', 'permission', 'access_level', 'privilege'];
    for (const pattern of roleChangePatterns) {
      if (event.payload[pattern] && event.payload[pattern] !== currentRole) {
        const newRole = event.payload[pattern].toLowerCase();
        const newRoleIndex = roleHierarchy.indexOf(newRole);
        if (newRoleIndex > currentIndex) {
          return true;
        }
      }
    }
  }

  return false;
}

export function detectHorizontalPrivilegeEscalation(event: SilkerEvent, userId?: string, resourceUserId?: string): boolean {
  if (!userId || !resourceUserId) return false;

  const url = event.url || '';
  const urlUserId = extractUserIdFromUrl(url);
  
  if (urlUserId && urlUserId !== userId && urlUserId !== resourceUserId) {
    return true;
  }

  if (event.payload && typeof event.payload === 'object') {
    const payloadUserId = event.payload.userId || event.payload.id || event.payload.user_id;
    if (payloadUserId && payloadUserId !== userId) {
      return true;
    }
  }

  return false;
}

function isAuthorizedRole(userRole: string, requiredRoles: string[], allowedRoles?: string[]): boolean {
  if (allowedRoles) {
    return allowedRoles.some(role => role.toLowerCase() === userRole.toLowerCase());
  }

  const roleMapping = DEFAULT_ROLE_MAPPING;
  for (const requiredRole of requiredRoles) {
    if (roleMapping[requiredRole]?.includes(userRole.toLowerCase())) {
      return true;
    }
  }

  return false;
}

function extractUserIdFromUrl(url: string): string | null {
  const patterns = [
    /\/user\/([^\/\?]+)/i,
    /\/users\/([^\/\?]+)/i,
    /\/account\/([^\/\?]+)/i,
    /\/profile\/([^\/\?]+)/i,
    /userId=([^&]+)/i,
    /user_id=([^&]+)/i
  ];

  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (match && match[1]) {
      return match[1];
    }
  }

  return null;
}

