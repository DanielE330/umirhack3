import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useData } from '../../context/data.js'
import { useLanguage } from '../../context/language.js'
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
  const { t } = useLanguage()
  const navigate = useNavigate()
  const tr = traps.find((x) => x.id === trapId)
  const [name, setName] = useState(tr ? tr.name : '')
  const [target, setTarget] = useState(tr ? tr.container : '')
  const [profile, setProfile] = useState(tr ? tr.profile : '')
  if (!tr) return <p className="hint">{t('Ловушка уже удалена')}</p>

  const patch = async (body, msg, newName) => {
    try {
      await api('/api/traps/' + tr.id, { method: 'PATCH', body })
      showToast(msg)
    } catch (e) {
      return fail(e)
    }
    await refresh()
    return newName ? openTrap({ id: tr.id, name: newName }) : undefined // заголовок окна содержит имя
  }

  const rename = () => {
    const n = name.trim()
    if (!/^[A-Za-z0-9._-]{1,60}$/.test(n)) return showToast(t('Имя: латиница, цифры, точка, дефис, подчёркивание'), true)
    if (n !== tr.name && trapByName(n)) return showToast(t('Ловушка с таким именем уже есть'), true)
    return patch({ name: n }, t('Переименовано'), n)
  }
  const move = () => {
    if (target === tr.container) return undefined
    const errs = portConflicts([...trapsOf(target), tr].map((x) => ({ name: x.name, profile: x.profile })), profileByName)
    if (errs.length) return showToast(t('Нельзя переместить: {err}', { err: errs[0] }), true)
    return patch({ machine_vmid: containerByName(target).vmid }, t('Ловушка перемещена в «{name}» — подключите к ней агента там', { name: target }))
  }
  const apply = () => {
    const errs = portConflicts(
      trapsOf(tr.container).map((x) => ({ name: x.name, profile: x.id === tr.id ? profile : x.profile })),
      profileByName,
    )
    if (errs.length) return showToast(t('Нельзя сменить тип: {err}', { err: errs[0] }), true)
    return patch({ profile_id: profileByName(profile).id }, t('Тип ловушки обновлён — агент подтянет конфиг'))
  }
  const deploy = async () => {
    let d
    try {
      d = await api('/api/traps/' + tr.id + '/deploy', { method: 'POST', body: { kind: 'script' } })
    } catch (e) {
      return fail(e)
    }
    return openDeploy(tr, d.artifact)
  }

  const mine = events.filter((e) => e.trap === tr.name).slice(0, 8)

  return (
    <>
      <div className="inline mb-12">
        <StateBadge state={tr.state} />
        <Switch on={tr.enabled} tip={tr.enabled ? t('Выключить ловушку (агент закроет её порты)') : t('Включить ловушку')}
          onToggle={() => patch({ enabled: !tr.enabled }, tr.enabled ? t('Ловушка выключена') : t('Ловушка включена'))} />
      </div>
      <Kv rows={[
        ['Имя', (
          <div className="inline">
            <input className="trap-name-input" value={name} maxLength={60} aria-label={t('Имя ловушки')} onChange={(e) => setName(e.target.value)} />
            <button className="ghost small" onClick={rename}>{t('✎ Переименовать')}</button>
          </div>
        )],
        ['Машина', (
          <div className="inline">
            <Select value={target} onChange={(e) => setTarget(e.target.value)} aria-label={t('Машина')}
              options={containers.map((x) => ({ value: x.name, label: x.name + ' · ' + TYPE_INFO[x.type].kind + ' ' + x.vmid }))} />
            <button className="ghost small" onClick={move}>{t('⇄ Переместить')}</button>
          </div>
        )],
        ['Профиль', (
          <div className="inline">
            <Select value={profile} onChange={(e) => setProfile(e.target.value)} aria-label={t('Профиль')}
              options={profiles.map((p) => ({ value: p.name, label: p.name + ' (' + p.level + ')' }))} />
            <button className="ghost small" onClick={apply}>{t('✓ Применить')}</button>
          </div>
        )],
        ['Порты', portsOf(tr.profile).join(', ')],
        ['Событий', tr.events],
      ]} />
      <div className="inline">
        <button className="ghost" onClick={() => { closeModal(); setCFilter((f) => ({ ...f, q: tr.container })); navigate('/containers') }}>{t('▦ Показать машину')}</button>
        <button className="ghost" onClick={() => { closeModal(); setEventFilter({ trap: tr.name, type: '', q: '' }); navigate('/overview') }}>{t('☰ Все события ловушки')}</button>
        <ArmedButton label={t('⚡ Подключить агента')} armLabel={t('Старый токен перестанет работать. Точно?')}
          tip={t('Выпустить новый токен и показать команду запуска агента для этой ловушки')} onConfirm={deploy} />
        <ArmedButton label={t('🗑 Удалить')} armLabel={t('Точно удалить?')} className="ghost danger" onConfirm={() => { closeModal(); removeTrap(tr) }} />
      </div>
      <h4>{t('Последние события')}</h4>
      <table className="mini">
        <tbody>
          {mine.length ? mine.map((ev) => (
            <tr key={ev.id} className="click" {...clickable(() => openEvent(ev))}>
              <td className="m">{fmtTime(ev.ts)}</td>
              <td><TypeTag type={ev.type} /></td>
              <td className="m">{ev.src_ip}</td>
              <td className="m">{ev.command || ''}</td>
            </tr>
          )) : <tr><td className="empty" colSpan={4}>{t('Событий пока нет')}</td></tr>}
        </tbody>
      </table>
    </>
  )
}
