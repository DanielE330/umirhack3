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
      setState({
        status: 'authed',
        user: { username: d.username, role: d.role, roleTitle: d.role_title || d.role, permissions: d.permissions || [], telegramLinked: Boolean(d.telegram_linked), telegramUsername: d.telegram_username || '' },
      })
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

  const can = useCallback((flag) => Boolean(state.user && (state.user.permissions.includes('*') || state.user.permissions.includes(flag))), [state.user])
  const value = useMemo(() => ({ ...state, refresh, logout, can }), [state, refresh, logout, can])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
