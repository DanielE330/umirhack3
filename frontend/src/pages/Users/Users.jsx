import { useCallback, useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import Select from '../../components/Select.jsx'
import { ArmedButton, Field } from '../../components/common.jsx'
import { useAuth } from '../../context/auth.js'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'
import { fmtDateTime } from '../../lib/model.js'

const ROLES = ['operator', 'admin']

// Окно создания пользователя: пароль проверяет центр (длина, без логина внутри); 2FA пользователь настроит при входе
function NewUserModal({ onDone }) {
  const { closeModal, showToast } = useUi()
  const { t } = useLanguage()
  const [form, setForm] = useState({ username: '', password: '', role: 'operator' })
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }))
  const save = async (e) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      await api('/api/users', { method: 'POST', body: form })
    } catch (ex) {
      setBusy(false)
      return setErr(ex.message)
    }
    closeModal()
    showToast(t('Пользователь «{name}» создан. 2FA он настроит при первом входе', { name: form.username }))
    return onDone()
  }
  return (
    <form onSubmit={save}>
      <Field label="Логин"><input required autoFocus minLength={3} maxLength={64} autoCapitalize="none" spellCheck="false" value={form.username} onChange={set('username')} /></Field>
      <Field label="Пароль"><input type="password" required minLength={12} maxLength={128} autoComplete="new-password" value={form.password} onChange={set('password')} /></Field>
      <Field label="Роль">
        <Select value={form.role} onChange={set('role')} aria-label={t('Роль')}
          options={ROLES.map((r) => ({ value: r, label: r === 'admin' ? t('admin — всё, включая пользователей') : t('operator — ловушки и машины') }))} />
      </Field>
      <p className="hint">{t('Не короче 12 символов и без логина внутри.')}</p>
      <div className="err" role="alert">{err}</div>
      <div className="actions">
        <button className="btn" disabled={busy}>{t('Создать')}</button>
        <button type="button" className="ghost" onClick={closeModal}>{t('Отмена')}</button>
      </div>
    </form>
  )
}

// Управление операторами — только admin: создание, роль, блокировка, сброс 2FA
export default function Users() {
  const { user } = useAuth()
  const { showToast, openModal } = useUi()
  const { t } = useLanguage()
  const [users, setUsers] = useState(null)

  const load = useCallback(async () => {
    try {
      setUsers(await api('/api/users'))
    } catch (e) {
      showToast(e.message, true)
    }
  }, [showToast])
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- начальная загрузка списка
    if (user.role === 'admin') load()
  }, [user.role, load])

  if (user.role !== 'admin') return <Navigate to="/containers" replace />

  const patch = async (u, body, msg) => {
    try {
      await api('/api/users/' + u.id, { method: 'PATCH', body })
      showToast(msg)
    } catch (e) {
      showToast(e.message, true)
    }
    await load()
  }
  const reset2fa = async (u) => {
    try {
      await api('/api/users/' + u.id + '/reset-2fa', { method: 'POST', body: {} })
      showToast(t('2FA «{name}» сброшена', { name: u.username }))
    } catch (e) {
      showToast(e.message, true)
    }
    await load()
  }

  return (
    <section>
      <div className="toolbar">
        <button className="btn" onClick={() => openModal(t('Новый пользователь'), <NewUserModal onDone={load} />)}>{t('+ Новый пользователь')}</button>
        <span className="spacer" />
        <span className="hint">{t('Пользователей: {n}', { n: users ? users.length : 0 })}</span>
      </div>
      <div className="card">
        <table className="rows users-table">
          <thead>
            <tr><th>{t('Логин')}</th><th>{t('Роль')}</th><th>{t('Статус')}</th><th>2FA</th><th>{t('Создан')}</th><th /></tr>
          </thead>
          <tbody>
            {(users || []).map((u) => {
              const me = u.id === undefined ? false : u.username === user.username
              return (
                <tr key={u.id}>
                  <td><b>{u.username}</b>{me && <span className="hint"> · {t('это вы')}</span>}</td>
                  <td>
                    <Select value={u.role} aria-label={t('Роль')} className="users-role" onChange={(e) => e.target.value !== u.role
                      && patch(u, { role: e.target.value }, t('Роль «{name}» изменена, его сеансы завершены', { name: u.username }))}
                      options={ROLES.map((r) => ({ value: r, label: r }))} />
                  </td>
                  <td><span className={'tag ' + (u.is_active ? 'low' : 'high')}>{u.is_active ? t('активен') : t('заблокирован')}</span></td>
                  <td>{u.totp_enabled ? t('включена') : t('не настроена')}</td>
                  <td className="m">{fmtDateTime(Date.parse(u.created_at + 'Z'))}</td>
                  <td className="users-actions">
                    {!me && (
                      <>
                        <ArmedButton label={u.is_active ? t('Заблокировать') : t('Разблокировать')} armLabel={t('Точно?')} className="ghost small"
                          onConfirm={() => patch(u, { is_active: !u.is_active }, u.is_active ? t('«{name}» заблокирован', { name: u.username }) : t('«{name}» разблокирован', { name: u.username }))} />
                        <ArmedButton label={t('Сбросить 2FA')} armLabel={t('Точно?')} className="ghost small" onConfirm={() => reset2fa(u)}
                          tip={t('Пользователь настроит 2FA заново при следующем входе')} />
                      </>
                    )}
                  </td>
                </tr>
              )
            })}
            {users && !users.length && <tr><td colSpan={6} className="empty">{t('Пользователей нет')}</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  )
}
