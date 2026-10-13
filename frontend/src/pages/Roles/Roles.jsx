import { useCallback, useEffect, useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, Lock, Plus, Search, ShieldCheck, UserCog } from 'lucide-react'
import { ArmedButton, HelpMark } from '../../components/common.jsx'
import { useAuth } from '../../context/auth.js'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'

const EMPTY = { id: null, name: '', title: '', description: '', permissions: [] }
const FILTERS = [['all', 'Все'], ['system', 'Системные'], ['custom', 'Пользовательские']]
const TABS = [['perms', 'Разрешения'], ['users', 'Пользователи'], ['info', 'Информация']]

// Роли и флаги доступа: слева список, справа карточка выбранной роли. Системные роли только читаются,
// свои создаются из флагов. Выдать можно лишь права, которые есть у вас самих.
export default function Roles() {
  const { t } = useLanguage()
  const { showToast } = useUi()
  const { user, can } = useAuth()
  const [roles, setRoles] = useState(null)
  const [flags, setFlags] = useState([])
  const [people, setPeople] = useState([])
  const [form, setForm] = useState(EMPTY)
  const [busy, setBusy] = useState(false)
  const [filter, setFilter] = useState('all')
  const [query, setQuery] = useState('')
  const [tab, setTab] = useState('perms')
  const [open, setOpen] = useState({})

  const load = useCallback(async () => {
    try {
      const [r, f] = await Promise.all([api('/api/roles'), api('/api/roles/permissions')])
      setRoles(r)
      setFlags(f)
    } catch (e) {
      showToast(e.message, true)
    }
    try { setPeople(await api('/api/users')) } catch { setPeople([]) }
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
  const toggleGroup = (items) => {
    const free = items.filter((f) => can(f.flag)).map((f) => f.flag)
    const all = free.every((x) => form.permissions.includes(x))
    set({ permissions: all ? form.permissions.filter((x) => !free.includes(x)) : [...new Set([...form.permissions, ...free])] })
  }
  const pick = (r) => { setForm({ id: r.id, name: r.name, title: r.title, description: r.description, permissions: r.permissions }); setTab('perms') }
  const create = () => { setForm(EMPTY); setTab('perms') }

  const list = (roles || []).filter((r) =>
    (filter === 'all' || (filter === 'system') === r.is_system) &&
    (r.title + ' ' + r.name).toLowerCase().includes(query.trim().toLowerCase()))

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

  const members = people.filter((p) => p.role === form.name)

  return (
    <section className="roles">
      <header className="roles-head">
        <div>
          <h2>{t('Роли')}<HelpMark text={t('Роль — набор флагов доступа. Пользователю назначается одна роль. Системные роли встроены и не меняются, свои роли вы составляете из флагов.')} /></h2>
          <p className="hint">{t('Управление ролями и разрешениями пользователей системы')}</p>
        </div>
        <button className="btn" onClick={create}><Plus size={16} aria-hidden="true" /> {t('Создать роль')}</button>
      </header>

      <div className="roles-grid">
        <div className="card roles-list">
          <div className="roles-tools">
            <label className="roles-search">
              <Search size={15} aria-hidden="true" />
              <input placeholder={t('Поиск по названию или идентификатору')} value={query} onChange={(e) => setQuery(e.target.value)} />
            </label>
            <div className="seg" role="tablist">
              {FILTERS.map(([k, label]) => (
                <button key={k} className={filter === k ? 'on' : ''} onClick={() => setFilter(k)}>{t(label)}</button>
              ))}
            </div>
          </div>
          <div className="role-cols"><span>{t('Название / идентификатор')}</span><span>{t('Разрешений')}</span><span>{t('Пользователей')}</span><span>{t('Тип')}</span><span /></div>
          {list.map((r) => (
            <button key={r.id} className={'role-row' + (r.id === form.id ? ' sel' : '')} onClick={() => pick(r)}>
              <span className="role-ico">{r.is_system ? <ShieldCheck size={18} /> : <UserCog size={18} />}</span>
              <span className="role-name"><b>{r.title}</b><small>{r.name}</small></span>
              <span className="role-num">{r.permissions.length}</span>
              <span className="role-num">{r.users}</span>
              <span className={'tag ' + (r.is_system ? 'low' : 'soon')}>{r.is_system ? t('Системная') : t('Пользовательская')}</span>
              <ChevronRight size={16} aria-hidden="true" />
            </button>
          ))}
          {roles && list.length === 0 && <div className="empty">{t('Ничего не найдено')}</div>}
        </div>

        <div className="card role-detail">
          <div className="role-top">
            <span className="role-ico big">{readOnly ? <ShieldCheck size={26} /> : <UserCog size={26} />}</span>
            <div>
              <h3>{editing ? form.title : t('Новая роль')}</h3>
              <small>{editing ? form.name : t('укажите идентификатор на вкладке «Информация»')}</small>
            </div>
            {editing && <span className={'tag ' + (readOnly ? 'low' : 'soon')}>{readOnly && <Lock size={11} aria-hidden="true" />} {readOnly ? t('Системная роль') : t('Пользовательская роль')}</span>}
          </div>

          <div className="role-tabs" role="tablist">
            {TABS.map(([k, label]) => (
              <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? 'on' : ''} onClick={() => setTab(k)}>{t(label)}</button>
            ))}
          </div>

          {tab === 'perms' && (
            <>
              {readOnly && <p className="hint">{t('Системная роль: права показаны для справки, изменить их нельзя. Чтобы получить похожую, создайте свою роль.')}</p>}
              {groups.map(([group, items]) => {
                const on = items.filter((f) => form.permissions.includes(f.flag)).length
                const isOpen = open[group] ?? false
                return (
                  <div key={group} className={'acc' + (isOpen ? ' open' : '')}>
                    <button className="acc-head" aria-expanded={isOpen} onClick={() => setOpen((o) => ({ ...o, [group]: !isOpen }))}>
                      <b>{t(group)}</b>
                      <span className="acc-count">{on} {t('из')} {items.length}</span>
                      {isOpen ? <ChevronDown size={16} aria-hidden="true" /> : <ChevronRight size={16} aria-hidden="true" />}
                    </button>
                    {isOpen && (
                      <div className="acc-body">
                        {!readOnly && <button className="ghost small" onClick={() => toggleGroup(items)}>{t('Выбрать всё / снять')}</button>}
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
                      </div>
                    )}
                  </div>
                )
              })}
            </>
          )}

          {tab === 'users' && (
            editing ? (
              members.length
                ? <ul className="role-members">{members.map((p) => <li key={p.id ?? p.username}><b>{p.username}</b></li>)}</ul>
                : <div className="empty">{t('У этой роли пока нет пользователей')}</div>
            ) : <div className="empty">{t('Сначала создайте роль')}</div>
          )}

          {tab === 'info' && (
            <>
              {!editing && (
                <>
                  <label htmlFor="r-name">{t('Идентификатор')}<HelpMark text={t('Короткое имя латиницей: a-z, цифры, дефис, подчёркивание. После создания не меняется.')} /></label>
                  <input id="r-name" placeholder="soc-night" maxLength={40} value={form.name} onChange={(e) => set({ name: e.target.value })} />
                </>
              )}
              <label htmlFor="r-title">{t('Название')}</label>
              <input id="r-title" placeholder={t('Ночная смена SOC')} maxLength={80} value={form.title} disabled={readOnly} onChange={(e) => set({ title: e.target.value })} />
              <label htmlFor="r-desc">{t('Описание')}</label>
              <textarea id="r-desc" rows={3} maxLength={500} value={form.description} disabled={readOnly} onChange={(e) => set({ description: e.target.value })} />
            </>
          )}

          {!readOnly && (
            <div className="actions">
              <button className="btn lg" disabled={busy} onClick={save}>{editing ? t('Сохранить изменения') : t('Создать роль')}</button>
              {editing && <button className="ghost" onClick={create}>{t('Отмена')}</button>}
              {editing && <ArmedButton label={t('Удалить')} armLabel={t('Точно удалить?')} className="ghost danger" onConfirm={remove} />}
              <span className="hint">{form.permissions.length} / {flags.length} {t('прав выбрано')}</span>
            </div>
          )}
          {user.role === 'admin' ? null : <p className="hint">{t('Вы можете выдавать только те права, которые есть у вас самих.')}</p>}
        </div>
      </div>
    </section>
  )
}
