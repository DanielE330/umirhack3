import { useState } from 'react'
import { useData } from '../../context/data.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'
import { HELP, PVE, TYPE_INFO, baseName, readResources } from '../../lib/model.js'
import { Field, HelpMark } from '../common.jsx'
import ResourceFields from './ResourceFields.jsx'
import TrapPicker from './TrapPicker.jsx'

export default function NewContainerModal() {
  const { profiles, portsOf, containerByName, profileByName, uniqueName, uniqueContainerName, refresh } = useData()
  const { closeModal, showToast } = useUi()
  const [type, setType] = useState('lxc')
  const [name, setName] = useState(() => uniqueContainerName('edge-dmz'))
  const [res, setRes] = useState({ ...PVE.defaults })
  const [selected, setSelected] = useState(() => (profiles[0] ? [profiles[0].name] : []))
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const ports = selected.flatMap(portsOf).sort((a, b) => a - b)

  const create = async () => {
    const n = name.trim()
    const errs = []
    if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,59}$/.test(n)) errs.push('Имя (hostname): латиница, цифры и дефис')
    else if (containerByName(n)) errs.push('Машина с таким именем уже есть')
    const r = readResources(res)
    if (r.error) errs.push(r.error)
    if (!selected.length) errs.push('Выберите хотя бы одну ловушку')
    if (errs.length) return setErr(errs.join('\n'))
    setBusy(true)
    setErr('')
    try {
      const m = await api('/api/machines', {
        method: 'POST',
        body: { name: n, type, cores: r.value.cores, memory_gb: r.value.ram, disk_gb: r.value.disk },
      })
      const taken = new Set()
      for (const pn of selected) {
        const tn = uniqueName(baseName(pn), taken)
        taken.add(tn)
        await api('/api/traps', { method: 'POST', body: { name: tn, profile_id: profileByName(pn).id, machine_vmid: m.vmid } })
      }
      closeModal()
      showToast('Создаю ' + TYPE_INFO[type].kind + ' ' + m.vmid + ' в Proxmox (адрес ' + m.ip + ')…')
    } catch (e) {
      setErr(e.message)
      setBusy(false)
      return
    }
    await refresh()
  }

  return (
    <>
      <div>
        <label>
          Тип машины
          <HelpMark text="LXC — лёгкий контейнер, стартует за секунды, подходит для Low и Medium. KVM — полноценная виртуальная машина: дольше стартует, но изоляция сильнее." />
        </label>
        <div className="seg" role="radiogroup">
          {Object.entries(TYPE_INFO).map(([k, t]) => (
            <button key={k} type="button" role="radio" aria-checked={k === type} className={k === type ? 'on' : ''} onClick={() => setType(k)}>
              <b>{t.label} — {t.title}</b>
              <small>{t.desc}</small>
            </button>
          ))}
        </div>
      </div>
      <Field label="Имя (hostname)">
        <input autoFocus maxLength={60} value={name} onChange={(e) => setName(e.target.value)} aria-label="Имя" onFocus={(e) => e.target.select()} />
      </Field>
      <div className="hint">VMID и адрес в DMZ выдаст оркестратор автоматически · шаблон {PVE.templates[type] || 'не настроен'}</div>
      <h4>Ресурсы</h4>
      <ResourceFields value={res} onChange={setRes} />
      <h4>Сеть <HelpMark text={HELP.dmz} /></h4>
      <div className="ro">{PVE.bridgeLabel} — ловушки не видят домашнюю сеть и прод</div>
      <h4>
        Какие ловушки запустить
        <HelpMark text="Каждая карточка — профиль ловушки. В одной машине может работать несколько ловушек, если их порты не пересекаются. Запускает их агент внутри машины." />
      </h4>
      <p className="hint">Можно выбрать несколько. Типы с пересекающимися портами в одной машине недоступны.</p>
      <TrapPicker existing={[]} selected={selected} multi onChange={setSelected} />
      <div className="hint" style={{ marginTop: 10 }}>
        {selected.length ? 'Выбрано ловушек: ' + selected.length + ' · порты: ' + ports.join(', ') : 'Ничего не выбрано'}
      </div>
      <div className="err" role="alert">{err}</div>
      <div className="actions">
        <button className="btn" disabled={busy} onClick={create}
          data-tip="Центр клонирует шаблон в Proxmox, выдаёт ресурсы и сеть, запускает машину; агент внутри поднимет выбранные ловушки">
          Создать в Proxmox
        </button>
        <button className="ghost" onClick={closeModal}>Отмена</button>
      </div>
    </>
  )
}
