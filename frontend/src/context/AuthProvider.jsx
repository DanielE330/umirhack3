import { useCallback, useEffect, useMemo, useState } from 'react'
import { api, setCsrf, setUnauthorizedHandler } from '../lib/api.js'
import { AuthContext } from './auth.js'

// Сессия: статус loading → authed | anon. Ответ /api/auth/me содержит CSRF-токен.
export default function AuthProvider({ children }) {
  const [state, setState] = useState({ status: 'loading', user: null })

  const refresh = useCallback(async () => {
    try {
      const d = await api('/api/auth/me', { auth: false })
      setCsrf(d.csrf)
      setState({ status: 'authed', user: { username: d.username, role: d.role } })
    } catch {
      setCsrf('')
      setState({ status: 'anon', user: null })
    }
  }, [])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- начальная загрузка сессии с сервера
    refresh()
    setUnauthorizedHandler(() => {
      setCsrf('')
      setState({ status: 'anon', user: null })
    })
  }, [refresh])

  const logout = useCallback(async () => {
    try {
      await api('/api/auth/logout', { method: 'POST', body: {}, auth: false })
    } catch {
      /* уходим на вход в любом случае */
    }
    setCsrf('')
    setState({ status: 'anon', user: null })
  }, [])

  const value = useMemo(() => ({ ...state, refresh, logout }), [state, refresh, logout])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
