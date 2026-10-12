import { useState } from 'react'
import { useData } from '../../context/data.js'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'
import { baseName, portConflicts } from '../../lib/model.js'
import { Field } from '../common.jsx'
import TrapPicker from './TrapPicker.jsx'

export default function AddTrapModal({ vmid }) {
  const { containers, trapsOf, portsOf, profileByName, trapByName, uniqueName, refresh, pickProfiles, ensureProfile } = useData()
  const { closeModal, showToast } = useUi()
  const { t } = useLanguage()
  const c = containers.find((x) => x.vmid === vmid)
  const [selected, setSelected] = useState([])
  const [name, setName] = useState('')
  const [touched, setTouched] = useState(false)
  const [err, setErr] = useState('')
  if (!c) return <p className="hint">{t('Машина уже удалена')}</p>

  const existing = trapsOf(c.name)
  const noFree = !pickProfiles.some((p) => !portsOf(p.name).some((port) => existing.some((x) => portsOf(x.profile).includes(port))))
  const pick = (list) => {
    setSelected(list)
    if (list[0] && !touched) setName(uniqueName(baseName(list[0])))
  }

  const add = async () => {
    const p = selected[0]
    const n = name.trim()
    if (!p) return setErr(t('Выберите тип ловушки'))
    if (!/^[A-Za-z0-9._-]{1,60}$/.test(n)) return setErr(t('Имя: латиница, цифры, точка, дефис, подчёркивание'))
    if (trapByName(n)) return setErr(t('Ловушка с таким именем уже есть'))
    const errs = portConflicts([...existing.map((x) => ({ name: x.name, profile: x.profile })), { name: n, profile: p }], profileByName)
    if (errs.length) return setErr(errs.join('\n'))
    try {
      const prof = await ensureProfile(p)
      await api('/api/traps', { method: 'POST', body: { name: n, profile_id: prof.id, machine_vmid: c.vmid } })
    } catch (e) {
      return setErr(e.message)
    }
    closeModal()
    showToast(t('Ловушка «{name}» добавлена — агент включится в машине сам', { name: n }))
    return refresh()
  }

  return (
    <>
      <p className="hint">
        {existing.length
          ? t('Уже в машине: {list}', { list: existing.map((x) => x.name + ' (' + portsOf(x.profile).join(', ') + ')').join(', ') })
          : t('Машина пока пустая.')}
      </p>
      <TrapPicker existing={existing} selected={selected} multi={false} onChange={pick} />
      <Field label="Имя ловушки">
        <input maxLength={60} value={name} placeholder={t('сначала выберите тип выше')} aria-label={t('Имя ловушки')}
          onChange={(e) => { setTouched(true); setName(e.target.value) }} />
      </Field>
      <div className="err" role="alert">
        {err || (noFree ? t('Все типы ловушек конфликтуют по портам с уже установленными. Создайте профиль с другими портами или новую машину.') : '')}
      </div>
      <div className="actions">
        <button className="btn" disabled={!selected.length} onClick={add}>{t('Добавить ловушку')}</button>
        <button className="ghost" onClick={closeModal}>{t('Отмена')}</button>
      </div>
    </>
  )
}
