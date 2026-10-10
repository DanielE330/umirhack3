import Select from '../../components/Select.jsx'
import { ArmedButton, HelpMark, LevelTag } from '../../components/common.jsx'
import { clickable } from '../../lib/clickable.js'
import { useData } from '../../context/data.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'
import { EMPTY_FORM, HELP, formFromProfile, portConflicts, profileToApi, readProfileForm } from '../../lib/model.js'

export default function Profiles() {
  const { profiles, traps, containers, editor, setEditor, profileByName, trapsOf, refresh, fail } = useData()
  const { showToast } = useUi()
  const { editing, form } = editor
  const set = (key) => (e) => setEditor((s) => ({ ...s, form: { ...s.form, [key]: e.target.value } }))
  const reset = () => setEditor({ editing: null, form: EMPTY_FORM })

  const save = async () => {
    const old = editing ? profileByName(editing) : null
    const r = readProfileForm(form, old)
    if (r.error) return showToast(r.error, true)
    const p = r.profile
    if (profiles.some((x) => x.name === p.name && x.name !== editing)) return showToast('Профиль с таким именем уже есть', true)
    if (editing) {
      // новые порты не должны пересечься внутри машин
      const lookup = (n) => (n === editing ? p : profileByName(n))
      for (const c of containers) {
        const errs = portConflicts(trapsOf(c.name).map((t) => ({ name: t.name, profile: t.profile })), lookup)
        if (errs.length) return showToast('Конфликт в «' + c.name + '»: ' + errs[0], true)
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
      showToast('Профиль сохранён — ловушки получат новые настройки при ближайшем опросе')
      setEditor((s) => ({ ...s, editing: p.name }))
    } else {
      showToast('Профиль создан — его можно выбрать при добавлении ловушки')
      reset()
    }
    return undefined
  }

  const remove = async () => {
    const pr = profileByName(editing)
    if (!pr) return undefined
    if (traps.some((t) => t.profile === pr.name)) return showToast('Профиль используется ловушками: сначала смените им тип', true)
    try {
      await api('/api/profiles/' + pr.id, { method: 'DELETE' })
    } catch (e) {
      return fail(e)
    }
    reset()
    await refresh()
    return showToast('Профиль удалён')
  }

  return (
    <section>
      <div className="cols">
        <div className="card">
          <h3>
            Профили
            <HelpMark text="Профиль — шаблон ловушки: уровень, какие порты открыть, что отвечать и какие приманки подложить. Одним профилем можно настроить сколько угодно ловушек." />
            <span className="hint">шаблоны ловушек; нажмите строку, чтобы редактировать</span>
          </h3>
          <table className="rows">
            <thead>
              <tr>
                <th>Имя</th><th>Уровень</th>
                <th data-tip="Порт и протокол каждого эмулируемого сервиса">Сервисы</th>
                <th data-tip="Сколько ловушек использует профиль">Ловушек</th>
              </tr>
            </thead>
            <tbody>
              {profiles.length ? profiles.map((p) => (
                <tr key={p.id ?? p.name} className={'click' + (p.name === editing ? ' sel' : '')}
                  {...clickable(() => setEditor({ editing: p.name, form: formFromProfile(p) }))}>
                  <td>{p.name}</td>
                  <td><LevelTag level={p.level} /></td>
                  <td>{p.services.map((s) => s.port + ' (' + s.proto + ')').join(', ')}</td>
                  <td>{traps.filter((t) => t.profile === p.name).length}</td>
                </tr>
              )) : <tr><td className="empty" colSpan={4}>Профилей пока нет</td></tr>}
            </tbody>
          </table>
        </div>

        <div className="card">
          <h3>{editing ? 'Профиль: ' + editing : 'Конструктор профиля'}</h3>
          <label htmlFor="p-name">Название</label>
          <input id="p-name" placeholder="web-admin-medium" value={form.name} onChange={set('name')} />
          <label htmlFor="p-level">
            Уровень
            <HelpMark text="Low — порт отвечает баннером сервиса и фиксирует подключение. Medium — работает поддельный SSH или веб-сервис, который собирает логины, пароли и команды." />
          </label>
          <Select id="p-level" value={form.level} onChange={set('level')}
            options={[{ value: 'low', label: 'Low: баннеры портов' }, { value: 'medium', label: 'Medium: fake-SSH / fake-HTTP' }]} />
          <label htmlFor="p-services">
            Сервисы (порт:протокол:баннер, по одному в строке)
            <HelpMark text="Протокол: banner — просто строка-приветствие, ssh — поддельный SSH, http — поддельный веб-сервер. Баннер — то, что увидит сканер: чем правдоподобнее, тем лучше." />
          </label>
          <textarea id="p-services" rows={4} placeholder={'22:ssh:SSH-2.0-OpenSSH_8.2p1\n8080:http:Apache/2.4.41'} value={form.services} onChange={set('services')} />
          <label htmlFor="p-users">
            Имена пользователей-приманок (по одному в строке)
            <HelpMark text="Учётные записи, которые «существуют» на ловушке. Атакующий увидит их и попробует подобрать к ним пароль." />
          </label>
          <textarea id="p-users" rows={2} placeholder={'admin\nroot'} value={form.users} onChange={set('users')} />
          <label htmlFor="p-tokens">
            Honeytokens (путь)<HelpMark text={HELP.honeytoken} />
          </label>
          <textarea id="p-tokens" rows={2} placeholder="/root/.aws/credentials" value={form.tokens} onChange={set('tokens')} />
          <label htmlFor="p-beacon">
            Интервал маяка, с / джиттер
            <HelpMark text={HELP.beacon + ' Агент — небольшая фоновая программа внутри машины-ловушки: получает от центра настройки, запускает ловушки и незаметно отправляет в центр действия атакующего.'} />
          </label>
          <div className="row2">
            <input id="p-beacon" type="number" min={5} max={300} aria-label="Интервал маяка" value={form.beacon} onChange={set('beacon')} />
            <input type="number" step={0.1} min={0} max={0.9} aria-label="Джиттер" value={form.jitter} onChange={set('jitter')} />
          </div>
          <div className="actions">
            <button className="btn lg" data-tip="Сохранить шаблон. Ловушки с этим профилем получат новые настройки при ближайшем опросе" onClick={save}>
              {editing ? 'Сохранить изменения' : 'Сохранить профиль'}
            </button>
            {editing && <button className="ghost" onClick={reset}>Отмена</button>}
            {editing && <ArmedButton label="Удалить" armLabel="Точно удалить?" className="ghost danger" onConfirm={remove} />}
          </div>
        </div>
      </div>
    </section>
  )
}
