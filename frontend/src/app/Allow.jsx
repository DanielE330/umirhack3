import { Navigate } from 'react-router-dom'
import { useAuth } from '../context/auth.js'
import { allowed, firstAllowed } from './access.js'

// Раздел открывается только при нужном флаге доступа; иначе — первый доступный раздел (сервер всё равно проверит права)
export function Allow({ path, children }) {
  const { can } = useAuth()
  return allowed(path, can) ? children : <Navigate to={firstAllowed(can)} replace />
}

export function Home() {
  const { can } = useAuth()
  return <Navigate to={firstAllowed(can)} replace />
}
