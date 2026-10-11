import Select from '../../components/Select.jsx'
import { ArmedButton, HelpMark, LevelTag } from '../../components/common.jsx'
import { clickable } from '../../lib/clickable.js'
import { useData } from '../../context/data.js'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'
import { EMPTY_FORM, HELP, formFromProfile, formFromTemplate, portConflicts, profileToApi, readProfileForm } from '../../lib/model.js'

export default function Profiles() {
  const { pickProfiles, profiles, traps, containers, editor, setEditor, profileByName, trapsOf, refresh, fail } = useData()
  const { showToast } = useUi()
  const { t } = useLanguage()
  const { editing, form } = editor
  const set = (key) => (e) => setEditor((s) => ({ ...s, form: { ...s.form, [key]: e.target.value } }))
  const reset = () => setEditor({ editing: null, form: EMPTY_FORM })

  const save = async () => {
    const old = editing ? profileByName(editing) : null
    const r = readProfileForm(form, old)
    if (r.error) return showToast(r.error, true)
    const p = r.profile
    if (profiles.some((x) => x.name === p.name && x.name !== editing)) return showToast(t('Профиль с таким именем уже есть'), true)
    if (editing) {
      // новые порты не должны пересечься внутри машин
      const lookup = (n) => (n === editing ? p : profileByName(n))
      for (const c of containers) {
        const errs = portConflicts(trapsOf(c.name).map((tr) => ({ name: tr.name, profile: tr.profile })), lookup)
        if (errs.length) return showToast(t('Конфликт в «{name}»: {err}', { name: c.name, err: errs[0] }), true)
      }
    }
    try {
      if (p.id) await api('/api/profiles/' + p.id, { method: 'PUT', body: profileToApi(p, old) })
      else await api('/api/profiles', { method: 'POST', body: profileToApi(p, null) })
    } catch (e) {
      return fail(e)
    }
    await refresh()
    if (editing) {
      showToast(t('Профиль сохранён — ловушки получат новые настройки при ближайшем опросе'))
      setEditor((s) => ({ ...s, editing: p.name }))
    } else {
      showToast(t('Профиль создан — его можно выбрать при добавлении ловушки'))
      reset()
    }
    return undefined
  }

  const remove = async () => {
    const pr = profileByName(editing)
    if (!pr) return undefined
    if (traps.some((tr) => tr.profile === pr.name)) return showToast(t('Профиль используется ловушками: сначала смените им тип'), true)
    try {
      await api('/api/profiles/' + pr.id, { method: 'DELETE' })
    } catch (e) {
      return fail(e)
    }
    reset()
    await refresh()
    return showToast(t('Профиль удалён'))
  }

  return (
    <section>
      <div className="cols">
        <div className="card">
          <h3>
            {t('Профили')}
            <HelpMark text={t('Профиль — шаблон ловушки: уровень, какие порты открыть, что отвечать и какие приманки подложить. Одним профилем можно настроить сколько угодно ловушек.')} />
            <span className="hint">{t('шаблоны ловушек; нажмите строку, чтобы редактировать')}</span>
          </h3>
          <table className="rows">
            <thead>
              <tr>
                <th>{t('Имя')}</th><th>{t('Уровень')}</th>
                <th data-tip={t('Порт и протокол каждого эмулируемого сервиса')}>{t('Сервисы')}</th>
                <th data-tip={t('Сколько ловушек использует профиль')}>{t('Ловушек')}</th>
              </tr>
            </thead>
            <tbody>
              {pickProfiles.length ? pickProfiles.map((p) => (
                <tr key={p.name} className={'click' + (p.name === editing ? ' sel' : '')}
                  {...clickable(() => setEditor(p.virtual ? { editing: null, form: formFromTemplate(p.entry) } : { editing: p.name, form: formFromProfile(p) }))}>
                  <td>
                    {p.name}
                    {p.virtual && <span className="hint" data-tip={t('Заготовка по типу из каталога: в центре создастся при первом использовании или по кнопке «Сохранить профиль»')}> · {t('заготовка')}</span>}
                  </td>
                  <td><LevelTag level={p.level} /></td>
                  <td>{p.services.map((s) => s.port + ' (' + s.proto + ')').join(', ')}</td>
                  <td>{traps.filter((tr) => tr.profile === p.name).length}</td>
                </tr>
              )) : <tr><td className="empty" colSpan={4}>{t('Профилей пока нет')}</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="card">
          <h3>{editing ? t('Профиль: {name}', { name: editing }) : t('Конструктор профиля')}</h3>
          <label htmlFor="p-name">{t('Название')}</label>
          <input id="p-name" placeholder="web-admin-medium" value={form.name} onChange={set('name')} />
          <label htmlFor="p-level">
            {t('Уровень')}
            <HelpMark text={t('Low — порт отвечает баннером сервиса и фиксирует подключение. Medium — работает поддельный SSH или веб-сервис, который собирает логины, пароли и команды.')} />
          </label>
          <Select id="p-level" value={form.level} onChange={set('level')}
            options={[{ value: 'low', label: t('Low: баннеры портов') }, { value: 'medium', label: t('Medium: fake-SSH / fake-HTTP') }]} />
          <label htmlFor="p-services">
            {t('Сервисы (порт:протокол:баннер, по одному в строке)')}
            <HelpMark text={t('Протокол: banner — просто строка-приветствие, ssh — поддельный SSH, http — поддельный веб-сервер. Баннер — то, что увидит сканер: чем правдоподобнее, тем лучше.')} />
          </label>
          <textarea id="p-services" rows={4} placeholder={'22:ssh:SSH-2.0-OpenSSH_8.2p1\n8080:http:Apache/2.4.41'} value={form.services} onChange={set('services')} />
          <label htmlFor="p-users">
            {t('Имена пользователей-приманок (по одному в строке)')}
            <HelpMark text={t('Учётные записи, которые «существуют» на ловушке. Атакующий увидит их и попробует подобрать к ним пароль.')} />
          </label>
          <textarea id="p-users" rows={2} placeholder={'admin\nroot'} value={form.users} onChange={set('users')} />
          <label htmlFor="p-tokens">
            {t('Honeytokens (путь)')}<HelpMark text={t(HELP.honeytoken)} />
          </label>
          <textarea id="p-tokens" rows={2} placeholder="/root/.aws/credentials" value={form.tokens} onChange={set('tokens')} />
          <label htmlFor="p-beacon">
            {t('Интервал маяка, с / джиттер')}
            <HelpMark text={t(HELP.beacon) + ' ' + t('Агент — небольшая фоновая программа внутри машины-ловушки: получает от центра настройки, запускает ловушки и незаметно отправляет в центр действия атакующего.')} />
          </label>
          <div className="row2">
            <input id="p-beacon" type="number" min={5} max={300} aria-label={t('Интервал маяка')} value={form.beacon} onChange={set('beacon')} />
            <input type="number" step={0.1} min={0} max={0.9} aria-label={t('Джиттер')} value={form.jitter} onChange={set('jitter')} />
          </div>
          <div className="actions">
            <button className="btn lg" data-tip={t('Сохранить шаблон. Ловушки с этим профилем получат новые настройки при ближайшем опросе')} onClick={save}>
              {editing ? t('Сохранить изменения') : t('Сохранить профиль')}
            </button>
            {editing && <button className="ghost" onClick={reset}>{t('Отмена')}</button>}
            {editing && <ArmedButton label={t('Удалить')} armLabel={t('Точно удалить?')} className="ghost danger" onConfirm={remove} />}
          </div>
        </div>
      </div>
    </section>
  )
}
