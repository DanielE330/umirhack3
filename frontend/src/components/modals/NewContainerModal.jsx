import { useState } from 'react'
import { useData } from '../../context/data.js'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'
import { HELP, PVE, TYPE_INFO, baseName, readResources } from '../../lib/model.js'
import { Field, HelpMark } from '../common.jsx'
import ResourceFields from './ResourceFields.jsx'
import TrapPicker from './TrapPicker.jsx'

export default function NewContainerModal() {
  const { profiles, portsOf, containerByName, profileByName, uniqueName, uniqueContainerName, refresh } = useData()
  const { closeModal, showToast } = useUi()
  const { t } = useLanguage()
  const [type, setType] = useState('lxc')
  const [name, setName] = useState(() => uniqueContainerName('web-prod'))
  const [res, setRes] = useState({ ...PVE.defaults })
  const [selected, setSelected] = useState(() => (profiles[0] ? [profiles[0].name] : []))
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const ports = selected.flatMap(portsOf).sort((a, b) => a - b)

  const create = async () => {
    const n = name.trim()
    const errs = []
    if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,59}$/.test(n)) errs.push(t('Имя (hostname): латиница, цифры и дефис'))
    else if (containerByName(n)) errs.push(t('Машина с таким именем уже есть'))
    const r = readResources(res)
    if (r.error) errs.push(r.error)
    if (!selected.length) errs.push(t('Выберите хотя бы одну ловушку'))
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
      showToast(t('Создаю {kind} {vmid} (адрес {ip}): клон, запуск и агенты — автоматически, около минуты', { kind: TYPE_INFO[type].kind, vmid: m.vmid, ip: m.ip }))
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
          {t('Тип машины')}
          <HelpMark text={t('LXC — лёгкий контейнер, стартует за секунды, подходит для Low и Medium. KVM — полноценная виртуальная машина: дольше стартует, но изоляция сильнее.')} />
        </label>
        <div className="seg" role="radiogroup">
          {Object.entries(TYPE_INFO).map(([k, info]) => (
            <button key={k} type="button" role="radio" aria-checked={k === type} className={k === type ? 'on' : ''} onClick={() => setType(k)}>
              <b>{info.label} — {t(info.title)}</b>
              <small>{t(info.desc)}</small>
            </button>
          ))}
        </div>
      </div>
      <Field label="Имя (hostname)">
        <input autoFocus maxLength={60} value={name} onChange={(e) => setName(e.target.value)} aria-label={t('Имя')} onFocus={(e) => e.target.select()} />
      </Field>
      <div className="hint">{t('VMID и адрес в DMZ выдаст оркестратор автоматически · шаблон {tpl}', { tpl: PVE.templates[type] || t('не настроен') })}</div>
      <h4>{t('Ресурсы')}</h4>
      <ResourceFields value={res} onChange={setRes} />
      <h4>{t('Сеть')} <HelpMark text={t(HELP.dmz)} /></h4>
      <div className="ro">{t('{bridge} — ловушки не видят домашнюю сеть и прод', { bridge: t(PVE.bridgeLabel) })}</div>
      <h4>
        {t('Какие ловушки запустить')}
        <HelpMark text={t('Каждая карточка — профиль ловушки. В одной машине может работать несколько ловушек, если их порты не пересекаются. Запускает их агент внутри машины.')} />
      </h4>
      <p className="hint">{t('Можно выбрать несколько. Типы с пересекающимися портами в одной машине недоступны.')}</p>
      <TrapPicker existing={[]} selected={selected} multi onChange={setSelected} />
      <div className="hint mt-10">
        {selected.length ? t('Выбрано ловушек: {n} · порты: {ports}', { n: selected.length, ports: ports.join(', ') }) : t('Ничего не выбрано')}
      </div>
      <div className="err" role="alert">{err}</div>
      <div className="actions">
        <button className="btn" disabled={busy} onClick={create}
          data-tip={t('Центр клонирует шаблон в Proxmox, выдаёт ресурсы и сеть, запускает машину; агент внутри поднимет выбранные ловушки')}>
          {t('Создать в Proxmox')}
        </button>
        <button className="ghost" onClick={closeModal}>{t('Отмена')}</button>
      </div>
    </>
  )
}
