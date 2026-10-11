import { useCallback, useEffect, useMemo, useState } from 'react'
import { ArmedButton, HelpMark } from '../../components/common.jsx'
import { useAuth } from '../../context/auth.js'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'

const EMPTY = { id: null, name: '', title: '', description: '', permissions: [] }

// Роли и флаги доступа: системные роли только читаются, свои создаются из флагов. Выдать можно лишь права, которые есть у вас самих.
export default function Roles() {
  const { t } = useLanguage()
  const { showToast } = useUi()
  const { user, can } = useAuth()
  const [roles, setRoles] = useState(null)
  const [flags, setFlags] = useState([])
  const [form, setForm] = useState(EMPTY)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      const [r, f] = await Promise.all([api('/api/roles'), api('/api/roles/permissions')])
      setRoles(r)
      setFlags(f)
    } catch (e) {
      showToast(e.message, true)
    }
  }, [showToast])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- загрузка при открытии страницы
    load()
  }, [load])

  const groups = useMemo(() => {
    const out = new Map()
    for (const f of flags) out.set(f.group, [...(out.get(f.group) || []), f])
    return [...out]
  }, [flags])

  const editing = form.id != null
  const current = roles && roles.find((r) => r.id === form.id)
  const readOnly = Boolean(current && current.is_system)
  const set = (patch) => setForm((f) => ({ ...f, ...patch }))
  const toggle = (flag) => set({ permissions: form.permissions.includes(flag) ? form.permissions.filter((x) => x !== flag) : [...form.permissions, flag] })
  const pick = (r) => setForm({ id: r.id, name: r.name, title: r.title, description: r.description, permissions: r.permissions })

  const save = async () => {
    if (!form.title.trim()) return showToast(t('Укажите название роли'), true)
    setBusy(true)
    try {
      if (editing) {
        await api('/api/roles/' + form.id, { method: 'PATCH', body: { title: form.title, description: form.description, permissions: form.permissions } })
        showToast(t('Роль сохранена: новые права действуют сразу'))
      } else {
        await api('/api/roles', { method: 'POST', body: { name: form.name.trim().toLowerCase(), title: form.title, description: form.description, permissions: form.permissions } })
        showToast(t('Роль создана — её можно назначить на вкладке «Пользователи»'))
        setForm(EMPTY)
      }
      await load()
    } catch (e) {
      showToast(e.message, true)
    } finally {
      setBusy(false)
    }
    return undefined
  }

  const remove = async () => {
    try {
      await api('/api/roles/' + form.id, { method: 'DELETE' })
      showToast(t('Роль удалена'))
      setForm(EMPTY)
    } catch (e) {
      showToast(e.message, true)
    }
    await load()
  }

  return (
    <section>
      <div className="cols">
        <div className="card">
          <h3>
            {t('Роли')}
            <HelpMark text={t('Роль — набор флагов доступа. Пользователю назначается одна роль. Системные роли встроены и не меняются, свои роли вы составляете из флагов.')} />
            <span className="hint">{t('нажмите строку, чтобы открыть')}</span>
          </h3>
          <table className="rows">
            <thead><tr><th>{t('Роль')}</th><th>{t('Прав')}</th><th>{t('Пользователей')}</th></tr></thead>
            <tbody>
              {roles && roles.map((r) => (
                <tr key={r.id} className={'click' + (r.id === form.id ? ' sel' : '')} onClick={() => pick(r)}>
                  <td>
                    <b>{r.title}</b> <span className="hint">{r.name}</span>
                    {r.is_system && <span className="tag low" data-tip={t('Системная роль: встроена в платформу, не редактируется')}> {t('системная')}</span>}
                    <div className="hint">{r.description}</div>
                  </td>
                  <td>{r.permissions.length} / {flags.length || '—'}</td>
                  <td>{r.users}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="mt-10"><button className="ghost" onClick={() => setForm(EMPTY)}>{t('+ Новая роль')}</button></div>
        </div>

        <div className="card">
          <h3>{editing ? t('Роль: {name}', { name: form.title }) : t('Новая роль')}</h3>
          {readOnly && <p className="hint">{t('Системная роль: права показаны для справки, изменить их нельзя. Чтобы получить похожую, создайте свою роль.')}</p>}
          {!editing && (
            <>
              <label htmlFor="r-name">{t('Идентификатор')}<HelpMark text={t('Короткое имя латиницей: a-z, цифры, дефис, подчёркивание. После создания не меняется.')} /></label>
              <input id="r-name" placeholder="soc-night" maxLength={40} value={form.name} onChange={(e) => set({ name: e.target.value })} />
            </>
          )}
          <label htmlFor="r-title">{t('Название')}</label>
          <input id="r-title" placeholder={t('Ночная смена SOC')} maxLength={80} value={form.title} disabled={readOnly} onChange={(e) => set({ title: e.target.value })} />
          <label htmlFor="r-desc">{t('Описание')}</label>
          <textarea id="r-desc" rows={2} maxLength={500} value={form.description} disabled={readOnly} onChange={(e) => set({ description: e.target.value })} />

          <h4>{t('Флаги доступа')}<span className="hint"> {form.permissions.length} / {flags.length}</span></h4>
          {groups.map(([group, items]) => (
            <fieldset key={group} className="perm-group">
              <legend>{t(group)}</legend>
              {items.map((f) => {
                const off = readOnly || !can(f.flag)
                return (
                  <label key={f.flag} className={'perm' + (off ? ' off' : '')}
                    data-tip={!readOnly && !can(f.flag) ? t('У вас нет этого права, поэтому выдать его нельзя') : undefined}>
                    <input type="checkbox" checked={form.permissions.includes(f.flag)} disabled={off} onChange={() => toggle(f.flag)} />
                    <span><code>{f.flag}</code> — {t(f.description)}</span>
                  </label>
                )
              })}
            </fieldset>
          ))}

          {!readOnly && (
            <div className="actions">
              <button className="btn lg" disabled={busy} onClick={save}>{editing ? t('Сохранить изменения') : t('Создать роль')}</button>
              {editing && <button className="ghost" onClick={() => setForm(EMPTY)}>{t('Отмена')}</button>}
              {editing && <ArmedButton label={t('Удалить')} armLabel={t('Точно удалить?')} className="ghost danger" onConfirm={remove} />}
            </div>
          )}
          {user.role === 'admin' ? null : <p className="hint">{t('Вы можете выдавать только те права, которые есть у вас самих.')}</p>}
        </div>
      </div>
    </section>
  )
}
