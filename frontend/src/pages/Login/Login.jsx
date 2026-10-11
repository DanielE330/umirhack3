import { useState } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../../context/auth.js'
import { useLanguage } from '../../context/language.js'
import { api } from '../../lib/api.js'

// Вход: логин/пароль → (первый вход) настройка 2FA и резервные коды → код подтверждения
export default function Login() {
  const { status, refresh } = useAuth()
  const { t } = useLanguage()
  const [view, setView] = useState('login') // login | setup | code | codes
  const [msg, setMsg] = useState('')
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [code, setCode] = useState('')
  const [qr, setQr] = useState({ img: '', secret: '' })
  const [recovery, setRecovery] = useState([])
  const [busy, setBusy] = useState(false)

  if (status === 'authed' && view !== 'codes') return <Navigate to="/containers" replace />

  const go = (v) => {
    setView(v)
    setMsg('')
    setCode('')
  }
  // общий обработчик: блокирует кнопку на время запроса и показывает ошибку
  const run = (fn) => async (e) => {
    e.preventDefault()
    setBusy(true)
    try {
      await fn()
    } catch (err) {
      setMsg(err.message)
    }
    setBusy(false)
  }
  const post = (path, body) => api(path, { method: 'POST', body, auth: false })

  const login = run(async () => {
    const r = await post('/api/auth/login', { username: user, password: pass })
    setPass('')
    if (r.next === '2fa_setup') {
      const s = await post('/api/auth/2fa/setup', {})
      setQr({ img: s.qr, secret: s.secret })
      go('setup')
    } else {
      go('code')
    }
  })
  const enable = run(async () => {
    const d = await post('/api/auth/2fa/enable', { code })
    setRecovery(d.recovery_codes)
    go('codes')
  })
  const verify = run(async () => {
    await post('/api/auth/2fa/verify', { code })
    await refresh()
  })

  return (
    <div className="login">
      <div className="honeycomb" aria-hidden="true" />
      <div className="login-wrap">
        <div className="login-card">
          <header>
            <div className="mascot"><img src={import.meta.env.BASE_URL + 'logo-256.png'} width="96" height="96" alt="" /></div>
            <h1>Honey<span>Forge</span></h1>
            <p className="sub">{t('Центр управления ловушками')}</p>
          </header>

          {view === 'login' && (
            <form onSubmit={login} autoComplete="on">
              <label htmlFor="u">{t('Пользователь')}</label>
              <input id="u" autoComplete="username" autoCapitalize="none" spellCheck="false" required autoFocus value={user} onChange={(e) => setUser(e.target.value)} />
              <label htmlFor="p">{t('Пароль')}</label>
              <input id="p" type="password" autoComplete="current-password" required value={pass} onChange={(e) => setPass(e.target.value)} />
              <button className="btn wide" disabled={busy}>{t('Войти')}</button>
            </form>
          )}

          {view === 'setup' && (
            <form onSubmit={enable}>
              <p className="note">{t('Первый вход: включите двухфакторную защиту. Отсканируйте QR в Google Authenticator, Aegis или 2FAS.')}</p>
              <img className="qr" src={qr.img} width="200" height="200" alt={t('QR-код для приложения-аутентификатора')} />
              <p className="note">{t('Или введите ключ вручную:')}<br /><code>{qr.secret}</code></p>
              <label htmlFor="c1">{t('Код из приложения')}</label>
              <input id="c1" className="code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="000000" required autoFocus value={code} onChange={(e) => setCode(e.target.value)} />
              <button className="btn wide" disabled={busy}>{t('Подтвердить и включить')}</button>
            </form>
          )}

          {view === 'code' && (
            <form onSubmit={verify}>
              <p className="note">{t('Введите код из приложения-аутентификатора или резервный код.')}</p>
              <label htmlFor="c2">{t('Код подтверждения')}</label>
              <input id="c2" className="code" autoComplete="one-time-code" maxLength={14} placeholder="000000" required autoFocus value={code} onChange={(e) => setCode(e.target.value)} />
              <button className="btn wide" disabled={busy}>{t('Продолжить')}</button>
              <button type="button" className="ghost wide" onClick={() => go('login')}>{t('Назад')}</button>
            </form>
          )}

          {view === 'codes' && (
            <section>
              <p className="ok">{t('Двухфакторная защита включена')}</p>
              <p className="note">{t('Сохраните резервные коды. Каждый работает один раз, повторно они показаны не будут.')}</p>
              <ul className="codes">{recovery.map((c) => <li key={c}>{c}</li>)}</ul>
              <button className="btn wide" onClick={async () => { setRecovery([]); await refresh() }}>{t('Я сохранил(а) коды')}</button>
            </section>
          )}

          <div id="msg" role="alert" aria-live="polite">{msg}</div>
        </div>

        <footer className="credits login-credits">
          <span>HoneyForge · UmirHack III</span>
          <span>{t('Команда:')}</span>
          <a href="https://github.com/DanielE330" target="_blank" rel="noopener noreferrer">DanielE330</a><span className="role">{t('автор')}</span>
          <span>·</span>
          <a href="https://github.com/Lunarflux-hub" target="_blank" rel="noopener noreferrer">Lunarflux-hub</a><span className="role">{t('контрибьютер')}</span>
        </footer>
      </div>
    </div>
  )
}
