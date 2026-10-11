// Какой флаг доступа нужен для раздела панели. Сервер всё равно проверяет права сам: это только скрывает недоступное.
export const ROUTE_PERMS = {
  '/containers': 'machines.view',
  '/overview': 'events.view',
  '/events': 'events.view',
  '/alerts': 'events.view',
  '/analytics': 'events.view',
  '/map': 'events.view',
  '/ioc': 'iocs.export',
  '/files': 'files.view',
  '/traps': 'profiles.view',
  '/profiles': 'profiles.view',
  '/users': 'users.manage',
  '/roles': 'roles.manage',
  '/audit': 'audit.view',
  '/settings': '',
}

export const allowed = (path, can) => !ROUTE_PERMS[path] || can(ROUTE_PERMS[path])
export const firstAllowed = (can) => Object.keys(ROUTE_PERMS).find((p) => allowed(p, can)) || '/settings'
