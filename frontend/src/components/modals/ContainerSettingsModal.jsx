import { useState } from 'react'
import { Check, X } from 'lucide-react'
import { useData } from '../../context/data.js'
import { useUi } from '../../context/ui.js'
import { useModals } from '../../hooks/useModals.jsx'
import { api } from '../../lib/api.js'
import { PVE, TYPE_INFO, readResources } from '../../lib/model.js'
import { ArmedButton, Field, Kv, StateBadge } from '../common.jsx'
import { clickable } from '../../lib/clickable.js'
import ResourceFields from './ResourceFields.jsx'

export default function ContainerSettingsModal({ vmid }) {
  const { containers, containerByName, containerPorts, trapsOf, removeTrap, refresh } = useData()
  const { closeModal, showToast } = useUi()
  const { openTrap, openAddTrap } = useModals()
  const c = containers.find((x) => x.vmid === vmid)
  const [name, setName] = useState(c ? c.name : '')
  const [res, setRes] = useState(c ? { cores: c.cores, ram: c.ram, disk: c.disk } : PVE.defaults)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  if (!c) return <p className="hint">Машина уже удалена</p>

  const t = TYPE_INFO[c.type]
  const list = trapsOf(c.name)

  const save = async () => {
    const n = name.trim()
    if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,59}$/.test(n)) return setErr('Имя (hostname): латиница, цифры и дефис')
    if (n !== c.name && containerByName(n)) return setErr('Машина с таким именем уже есть')
    const r = readResources(res, c.disk)
    if (r.error) return setErr(r.error)
    const body = { cores: r.value.cores, memory_gb: r.value.ram, disk_gb: r.value.disk }
    if (n !== c.name) body.name = n
    setBusy(true)
    try {
      await api('/api/machines/' + c.vmid, { method: 'PUT', body })
    } catch (e) {
      setErr(e.message)
      setBusy(false)
      return undefined
    }
    closeModal()
    showToast(t.cli + ' set ' + c.vmid + ' — применено' + (c.type === 'kvm' ? ' (ресурсы KVM — после перезапуска)' : ''))
    return refresh()
  }

  return (
    <>
      <Kv rows={[
        ['Тип', t.label + ' — ' + t.title],
        ['VMID / нода', t.kind + ' ' + c.vmid + ' · ' + c.node],
        ['Состояние', <StateBadge key="s" state={c.state} />],
        ['Сеть', PVE.bridgeLabel],
        ['IP в DMZ', c.host || '—'],
        ['Порты', containerPorts(c.name).join(', ') || '—'],
      ]} />
      <Field label="Имя (hostname)">
        <input value={name} maxLength={60} onChange={(e) => setName(e.target.value)} aria-label="Имя" />
      </Field>
      <h4>Ресурсы</h4>
      <ResourceFields value={res} onChange={setRes} />
      <h4>Ловушки</h4>
      <div className="titems">
        {list.length ? list.map((x) => (
          <div key={x.id} className="titem" {...clickable(() => openTrap(x))}>
            <span className={'dot ' + x.state} />
            <span className="nm">{x.name}</span>
            <span className="pf">{x.profile}</span>
            <span className="ev" />
            <ArmedButton label={<X size={16} strokeWidth={1.5} aria-hidden="true" />} armLabel={<Check size={16} strokeWidth={1.5} aria-hidden="true" />}
              aria-label="Убрать" className="icon-btn" tip="Убрать ловушку из машины (нажмите дважды)" onConfirm={() => removeTrap(x)} />
          </div>
        )) : <div className="cnone">Ловушек нет</div>}
      </div>
      <div className="err" role="alert">{err}</div>
      <div className="actions">
        <button className="btn" disabled={busy} onClick={save}>Сохранить</button>
        <button className="ghost" onClick={() => openAddTrap(c)}>+ Добавить ловушку</button>
        <button className="ghost" onClick={closeModal}>Закрыть</button>
      </div>
    </>
  )
}
