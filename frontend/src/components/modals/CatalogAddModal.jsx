import { useState } from 'react'
import { useData } from '../../context/data.js'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'
import { Field } from '../common.jsx'

// Быстрое добавление типа ловушки из каталога в машину: профиль по шаблону создаётся сам, если его ещё нет.
export default function CatalogAddModal({ entry }) {
  const { containers, trapsOf, portsOf, ensureProfile, trapByName, uniqueName, refresh } = useData()
  const { closeModal, showToast } = useUi()
  const { t } = useLanguage()
  const profileName = entry.id + '-' + entry.level
  const entryPorts = entry.services.map((s) => s.port)
  const free = (c) => !trapsOf(c.name).some((x) => portsOf(x.profile).some((p) => entryPorts.includes(p)))
  const options = containers.filter((c) => c.type === 'lxc' && c.state !== 'failed' && c.state !== 'creating')
  const [vmid, setVmid] = useState(() => String((options.find(free) || {}).vmid || ''))
  const [name, setName] = useState(() => uniqueName(entry.id + '-bait'))
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const add = async () => {
    const c = options.find((x) => String(x.vmid) === vmid)
    const n = name.trim()
    if (!c) return setErr(t('Выберите машину'))
    if (!free(c)) return setErr(t('Порты этого типа уже заняты в машине «{name}»', { name: c.name }))
    if (!/^[A-Za-z0-9._-]{1,60}$/.test(n)) return setErr(t('Имя: латиница, цифры, точка, дефис, подчёркивание'))
    if (trapByName(n)) return setErr(t('Ловушка с таким именем уже есть'))
    setBusy(true)
    setErr('')
    try {
      const profile = await ensureProfile(profileName)
      await api('/api/traps', { method: 'POST', body: { name: n, profile_id: profile.id, machine_vmid: c.vmid } })
    } catch (e) {
      setBusy(false)
      return setErr(e.message)
    }
    closeModal()
    showToast(t('Ловушка «{name}» добавлена в «{machine}» — агент включится сам', { name: n, machine: c.name }))
    return refresh()
  }

  return (
    <>
      <p className="hint">{t(entry.emulates)}</p>
      {options.length ? (
        <Field label="Машина">
          <select value={vmid} aria-label={t('Машина')} onChange={(e) => setVmid(e.target.value)}>
            {options.map((c) => (
              <option key={c.vmid} value={c.vmid} disabled={!free(c)}>
                {c.name + ' · ' + (c.host || c.vmid) + (free(c) ? '' : ' — ' + t('порты заняты'))}
              </option>
            ))}
          </select>
        </Field>
      ) : <p className="hint">{t('Нет подходящих машин: сначала создайте контейнер на вкладке «Контейнеры».')}</p>}
      <Field label="Имя ловушки">
        <input maxLength={60} value={name} aria-label={t('Имя ловушки')} onChange={(e) => setName(e.target.value)} />
      </Field>
      <div className="err" role="alert">{err}</div>
      <div className="actions">
        <button className="btn" disabled={busy || !options.length} onClick={add}>{t('Добавить в контейнер')}</button>
        <button className="ghost" onClick={closeModal}>{t('Отмена')}</button>
      </div>
    </>
  )
}
