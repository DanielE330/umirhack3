import { useState } from 'react'
import { Eye, EyeOff } from 'lucide-react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../../context/auth.js'
import { useLanguage } from '../../context/language.js'
import { api } from '../../lib/api.js'

// Поле пароля с кнопкой «показать/скрыть»: проверить, что набрано, до отправки
function PasswordField({ id, ...props }) {
  const { t } = useLanguage()
  const [shown, setShown] = useState(false)
  const Icon = shown ? EyeOff : Eye
  return (
    <div className="pw">
      <input id={id} type={shown ? 'text' : 'password'} spellCheck="false" autoCapitalize="none" {...props} />
      <button type="button" className="pw-toggle" aria-controls={id} aria-pressed={shown}
        aria-label={shown ? t('Скрыть пароль') : t('Показать пароль')} title={shown ? t('Скрыть пароль') : t('Показать пароль')}
        onClick={() => setShown((v) => !v)}>
        <Icon size={18} strokeWidth={1.6} aria-hidden="true" />
      </button>
    </div>
  )
}

// Вход: логин/пароль → (первый вход) настройка 2FA и резервные коды → код подтверждения
export default function Login() {
  const { status, refresh } = useAuth()
  const { t } = useLanguage()
  const [view, setView] = useState('login') // login | setup | code | codes | forgot | reset
  const [msg, setMsg] = useState('')
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [code, setCode] = useState('')
  const [qr, setQr] = useState({ img: '', secret: '' })
  const [recovery, setRecovery] = useState([])
  const [busy, setBusy] = useState(false)
  const [reset, setReset] = useState({ code: '', pass: '', repeat: '' })
  const [info, setInfo] = useState('') // зелёное сообщение (код отправлен, пароль изменён)

  if (status === 'authed' && view !== 'codes') return <Navigate to="/containers" replace />

  const go = (v) => {
    setView(v)
    setMsg('')
    setInfo('')
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
  // Забытый пароль: код приходит в привязанный Telegram, вход после сброса — снова с 2FA
  const requestReset = run(async () => {
    const r = await post('/api/auth/reset/request', { username: user })
    setReset({ code: '', pass: '', repeat: '' })
    go('reset')
    setInfo(r.detail)
  })
  const confirmReset = run(async () => {
    if (reset.pass !== reset.repeat) throw new Error(t('Пароли не совпадают'))
    await post('/api/auth/reset/confirm', { username: user, code: reset.code, new_password: reset.pass })
    setReset({ code: '', pass: '', repeat: '' })
    go('login')
    setInfo(t('Пароль изменён. Войдите с новым паролем и кодом 2FA.'))
  })
  const setR = (k) => (e) => setReset((r) => ({ ...r, [k]: e.target.value }))

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
              <PasswordField id="p" autoComplete="current-password" required value={pass} onChange={(e) => setPass(e.target.value)} />
              <button className="btn wide" disabled={busy}>{t('Войти')}</button>
              <button type="button" className="linkbtn" onClick={() => go('forgot')}>{t('Забыли пароль?')}</button>
            </form>
          )}

          {view === 'forgot' && (
            <form onSubmit={requestReset}>
              <p className="note">{t('Код для сброса придёт в Telegram, привязанный к учётной записи (Настройки → Telegram). Без привязки пароль сбрасывает администратор.')}</p>
              <label htmlFor="ru">{t('Пользователь')}</label>
              <input id="ru" autoComplete="username" autoCapitalize="none" spellCheck="false" required autoFocus value={user} onChange={(e) => setUser(e.target.value)} />
              <button className="btn wide" disabled={busy}>{t('Получить код в Telegram')}</button>
              <button type="button" className="ghost wide" onClick={() => go('login')}>{t('Назад')}</button>
            </form>
          )}

          {view === 'reset' && (
            <form onSubmit={confirmReset}>
              <label htmlFor="rc">{t('Код из Telegram')}</label>
              <input id="rc" className="code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="000000" required autoFocus value={reset.code} onChange={setR('code')} />
              <label htmlFor="rp">{t('Новый пароль')}</label>
              <PasswordField id="rp" autoComplete="new-password" required minLength={12} maxLength={128} value={reset.pass} onChange={setR('pass')} />
              <label htmlFor="rp2">{t('Повторите новый пароль')}</label>
              <PasswordField id="rp2" autoComplete="new-password" required value={reset.repeat} onChange={setR('repeat')} />
              <button className="btn wide" disabled={busy}>{t('Сменить пароль')}</button>
              <button type="button" className="ghost wide" onClick={() => go('forgot')}>{t('Отправить код ещё раз')}</button>
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
              <button className="btn wide" onClick={async () => { setRecovery([]); await refresh(); go('login') }}>{t('Я сохранил(а) коды')}</button>
            </section>
          )}

          {info && !msg && <p className="ok login-info" role="status">{info}</p>}
          <div id="msg" role="alert" aria-live="polite">{msg}</div>
        </div>
      </div>
    </div>
  )
}
