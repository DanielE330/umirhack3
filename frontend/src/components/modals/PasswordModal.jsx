import { useState } from 'react'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'
import { Field } from '../common.jsx'

// Смена своего пароля: центр проверяет текущий пароль и политику, остальные сессии закрываются
export default function PasswordModal() {
  const { closeModal, showToast } = useUi()
  const { t } = useLanguage()
  const [form, setForm] = useState({ current: '', next: '', repeat: '' })
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }))

  const save = async (e) => {
    e.preventDefault()
    if (form.next !== form.repeat) return setErr(t('Пароли не совпадают'))
    setBusy(true)
    setErr('')
    try {
      await api('/api/auth/password', { method: 'POST', body: { current_password: form.current, new_password: form.next } })
    } catch (ex) {
      setBusy(false)
      return setErr(ex.message)
    }
    closeModal()
    return showToast(t('Пароль изменён. Другие сеансы этой учётной записи завершены'))
  }

  return (
    <form onSubmit={save}>
      <Field label="Текущий пароль">
        <input type="password" autoComplete="current-password" required autoFocus value={form.current} onChange={set('current')} />
      </Field>
      <Field label="Новый пароль">
        <input type="password" autoComplete="new-password" required minLength={12} maxLength={128} value={form.next} onChange={set('next')} />
      </Field>
      <Field label="Повторите новый пароль">
        <input type="password" autoComplete="new-password" required value={form.repeat} onChange={set('repeat')} />
      </Field>
      <p className="hint">{t('Не короче 12 символов и без логина внутри.')}</p>
      <div className="err" role="alert">{err}</div>
      <div className="actions">
        <button className="btn" disabled={busy}>{t('Сменить пароль')}</button>
        <button type="button" className="ghost" onClick={closeModal}>{t('Отмена')}</button>
      </div>
    </form>
  )
}
