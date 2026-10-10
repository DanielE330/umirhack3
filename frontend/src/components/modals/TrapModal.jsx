import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useData } from '../../context/data.js'
import { useUi } from '../../context/ui.js'
import { useModals } from '../../hooks/useModals.jsx'
import { api } from '../../lib/api.js'
import { TYPE_INFO, fmtTime, portConflicts } from '../../lib/model.js'
import Select from '../Select.jsx'
import { ArmedButton, Kv, StateBadge, Switch, TypeTag } from '../common.jsx'
import { clickable } from '../../lib/clickable.js'

export default function TrapModal({ trapId }) {
  const { traps, containers, profiles, events, trapsOf, containerByName, profileByName, trapByName, portsOf, removeTrap,
    refresh, fail, setCFilter, setEventFilter } = useData()
  const { closeModal, showToast } = useUi()
  const { openTrap, openEvent, openDeploy } = useModals()
  const navigate = useNavigate()
  const t = traps.find((x) => x.id === trapId)
  const [name, setName] = useState(t ? t.name : '')
  const [target, setTarget] = useState(t ? t.container : '')
  const [profile, setProfile] = useState(t ? t.profile : '')
  if (!t) return <p className="hint">Ловушка уже удалена</p>

  const patch = async (body, msg, newName) => {
    try {
      await api('/api/traps/' + t.id, { method: 'PATCH', body })
      showToast(msg)
    } catch (e) {
      return fail(e)
    }
    await refresh()
    return newName ? openTrap({ id: t.id, name: newName }) : undefined // заголовок окна содержит имя
  }

  const rename = () => {
    const n = name.trim()
    if (!/^[A-Za-z0-9._-]{1,60}$/.test(n)) return showToast('Имя: латиница, цифры, точка, дефис, подчёркивание', true)
    if (n !== t.name && trapByName(n)) return showToast('Ловушка с таким именем уже есть', true)
    return patch({ name: n }, 'Переименовано', n)
  }
  const move = () => {
    if (target === t.container) return undefined
    const errs = portConflicts([...trapsOf(target), t].map((x) => ({ name: x.name, profile: x.profile })), profileByName)
    if (errs.length) return showToast('Нельзя переместить: ' + errs[0], true)
    return patch({ machine_vmid: containerByName(target).vmid }, 'Ловушка перемещена в «' + target + '» — подключите к ней агента там')
  }
  const apply = () => {
    const errs = portConflicts(
      trapsOf(t.container).map((x) => ({ name: x.name, profile: x.id === t.id ? profile : x.profile })),
      profileByName,
    )
    if (errs.length) return showToast('Нельзя сменить тип: ' + errs[0], true)
    return patch({ profile_id: profileByName(profile).id }, 'Тип ловушки обновлён — агент подтянет конфиг')
  }
  const deploy = async () => {
    let d
    try {
      d = await api('/api/traps/' + t.id + '/deploy', { method: 'POST', body: { kind: 'script' } })
    } catch (e) {
      return fail(e)
    }
    return openDeploy(t, d.artifact)
  }

  const mine = events.filter((e) => e.trap === t.name).slice(0, 8)

  return (
    <>
      <div className="inline" style={{ marginBottom: 12 }}>
        <StateBadge state={t.state} />
        <Switch on={t.enabled} tip={t.enabled ? 'Выключить ловушку (агент закроет её порты)' : 'Включить ловушку'}
          onToggle={() => patch({ enabled: !t.enabled }, t.enabled ? 'Ловушка выключена' : 'Ловушка включена')} />
      </div>
      <Kv rows={[
        ['Имя', (
          <div className="inline">
            <input value={name} maxLength={60} style={{ width: 220 }} aria-label="Имя ловушки" onChange={(e) => setName(e.target.value)} />
            <button className="ghost small" onClick={rename}>✎ Переименовать</button>
          </div>
        )],
        ['Машина', (
          <div className="inline">
            <Select value={target} onChange={(e) => setTarget(e.target.value)} aria-label="Машина"
              options={containers.map((x) => ({ value: x.name, label: x.name + ' · ' + TYPE_INFO[x.type].kind + ' ' + x.vmid }))} />
            <button className="ghost small" onClick={move}>⇄ Переместить</button>
          </div>
        )],
        ['Профиль', (
          <div className="inline">
            <Select value={profile} onChange={(e) => setProfile(e.target.value)} aria-label="Профиль"
              options={profiles.map((p) => ({ value: p.name, label: p.name + ' (' + p.level + ')' }))} />
            <button className="ghost small" onClick={apply}>✓ Применить</button>
          </div>
        )],
        ['Порты', portsOf(t.profile).join(', ')],
        ['Событий', t.events],
      ]} />
      <div className="inline">
        <button className="ghost" onClick={() => { closeModal(); setCFilter((f) => ({ ...f, q: t.container })); navigate('/containers') }}>▦ Показать машину</button>
        <button className="ghost" onClick={() => { closeModal(); setEventFilter({ trap: t.name, type: '', q: '' }); navigate('/overview') }}>☰ Все события ловушки</button>
        <ArmedButton label="⚡ Подключить агента" armLabel="Старый токен перестанет работать. Точно?" tip="Выпустить новый токен и показать команду запуска агента для этой ловушки" onConfirm={deploy} />
        <ArmedButton label="🗑 Удалить" armLabel="Точно удалить?" className="ghost danger" onConfirm={() => { closeModal(); removeTrap(t) }} />
      </div>
      <h4>Последние события</h4>
      <table className="mini">
        <tbody>
          {mine.length ? mine.map((ev) => (
            <tr key={ev.id} className="click" {...clickable(() => openEvent(ev))}>
              <td className="m">{fmtTime(ev.ts)}</td>
              <td><TypeTag type={ev.type} /></td>
              <td className="m">{ev.src_ip}</td>
              <td className="m">{ev.command || ''}</td>
            </tr>
          )) : <tr><td className="empty" colSpan={4}>Событий пока нет</td></tr>}
        </tbody>
      </table>
    </>
  )
}
