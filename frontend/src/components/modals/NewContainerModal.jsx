import { useState } from 'react'
import { useData } from '../../context/data.js'
import { useLanguage } from '../../context/language.js'
import { useUi } from '../../context/ui.js'
import { api } from '../../lib/api.js'
import { HELP, PVE, TYPE_INFO, baseName } from '../../lib/model.js'
import { HelpMark } from '../common.jsx'
import TrapPicker from './TrapPicker.jsx'

// Создание машины-ловушки мастером по образцу окна Proxmox «Create CT»: вкладки слева направо,
// «Назад»/«Далее», на последнем шаге — сводка и эквивалентные команды pct.
// Поля, которые задаёт оркестратор (VMID, IP, шаблон, хранилище, пул, мост DMZ), показаны, но не редактируются:
// это граница изоляции ловушек, а не настройка.
const STEPS = ['Общие', 'Шаблон', 'Диск', 'CPU', 'Память', 'Сеть', 'Ловушки', 'Подтверждение']
const SWAP_MB = 512        // swap ставит оркестратор
const NAMESERVER = '1.1.1.1'

function Row({ label, help, children }) {
  const { t } = useLanguage()
  return (
    <div className="wiz-row">
      <span className="wiz-label">{t(label)}{help && <HelpMark text={t(help)} />}</span>
      <div className="wiz-field">{children}</div>
    </div>
  )
}
const Fixed = ({ children }) => <input value={children} disabled readOnly />

export default function NewContainerModal() {
  const { profiles, containers, portsOf, containerByName, profileByName, uniqueName, uniqueContainerName, refresh } = useData()
  const { closeModal, showToast } = useUi()
  const { t } = useLanguage()
  const [step, setStep] = useState(0)
  const [type, setType] = useState('lxc')
  const [name, setName] = useState(() => uniqueContainerName('web-prod'))
  const [cores, setCores] = useState(String(PVE.defaults.cores))
  const [memMb, setMemMb] = useState(String(PVE.defaults.ram * 1024))
  const [disk, setDisk] = useState(String(PVE.defaults.disk))
  const [selected, setSelected] = useState(() => (profiles[0] ? [profiles[0].name] : []))
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const info = TYPE_INFO[type]
  const template = PVE.templates[type]
  const node = (containers.find((c) => c.node) || {}).node || t('выберет оркестратор')
  const ports = selected.flatMap(portsOf).sort((a, b) => a - b)
  const [netBase, prefix] = PVE.network.split('/')
  const gw = PVE.gateway
  const firstIp = netBase.replace(/\.0$/, '.10')

  // Проверка шага: пустая строка — можно дальше
  const check = (i) => {
    if (i === 0) {
      const n = name.trim()
      if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,59}$/.test(n)) return t('Имя (hostname): латиница, цифры и дефис')
      if (containerByName(n)) return t('Машина с таким именем уже есть')
    }
    if (i === 1 && !template) return t('Шаблон для {kind} не настроен в оркестраторе — выберите LXC на вкладке «Общие»', { kind: info.label })
    const mb = Number(memMb)
    if (i === 3 && !(Number.isInteger(Number(cores)) && Number(cores) >= PVE.limits.cores[0] && Number(cores) <= PVE.limits.cores[1]))
      return t('Ядра: от {a} до {b}', { a: PVE.limits.cores[0], b: PVE.limits.cores[1] })
    if (i === 4 && (!Number.isInteger(mb) || mb % 1024 !== 0 || mb < PVE.limits.ram[0] * 1024 || mb > PVE.limits.ram[1] * 1024))
      return t('Память: от {a} до {b} МиБ, кратно 1024', { a: PVE.limits.ram[0] * 1024, b: PVE.limits.ram[1] * 1024 })
    if (i === 2) {
      const d = Number(disk)
      if (!Number.isInteger(d) || d < PVE.limits.disk[0] || d > PVE.limits.disk[1]) return t('Диск: от {a} до {b} ГБ', { a: PVE.limits.disk[0], b: PVE.limits.disk[1] })
    }
    if (i === 6 && !selected.length) return t('Выберите хотя бы одну ловушку')
    return ''
  }
  const go = (to) => {
    // вперёд — только через проверенные шаги, назад — свободно
    for (let i = step; i < to; i++) {
      const e = check(i)
      if (e) {
        setStep(i)
        return setErr(e)
      }
    }
    setErr('')
    return setStep(to)
  }

  const create = async () => {
    for (let i = 0; i < STEPS.length - 1; i++) {
      const e = check(i)
      if (e) {
        setStep(i)
        return setErr(e)
      }
    }
    setBusy(true)
    setErr('')
    try {
      const m = await api('/api/machines', {
        method: 'POST',
        body: { name: name.trim(), type, cores: Number(cores), memory_gb: Number(memMb) / 1024, disk_gb: Number(disk) },
      })
      const taken = new Set()
      for (const pn of selected) {
        const tn = uniqueName(baseName(pn), taken)
        taken.add(tn)
        await api('/api/traps', { method: 'POST', body: { name: tn, profile_id: profileByName(pn).id, machine_vmid: m.vmid } })
      }
      closeModal()
      showToast(t('Создаю {kind} {vmid} (адрес {ip}): клон, запуск и агенты — автоматически, около минуты', { kind: info.kind, vmid: m.vmid, ip: m.ip }))
    } catch (e) {
      setErr(e.message)
      setBusy(false)
      return undefined
    }
    return refresh()
  }

  const id = '<' + t('авто') + '>'
  const commands = [
    `${info.cli} clone ${template || '—'} ${id} ${type === 'kvm' ? '--name' : '--hostname'} ${name.trim()} --full --storage ${PVE.storage} --pool ${PVE.pool}`,
    `${info.cli} set ${id} --cores ${cores} --memory ${memMb}${type === 'lxc' ? ` --swap ${SWAP_MB} --nameserver ${NAMESERVER}` : ''} --tags honeyforge`,
    type === 'lxc'
      ? `${info.cli} set ${id} --net0 name=eth0,bridge=${PVE.bridge},ip=${netBase.replace(/\.0$/, '.X')}/${prefix},gw=${gw},type=veth`
      : `${info.cli} set ${id} --net0 virtio,bridge=${PVE.bridge} --ipconfig0 ip=${netBase.replace(/\.0$/, '.X')}/${prefix},gw=${gw}`,
    `${info.cli} resize ${id} ${type === 'kvm' ? 'scsi0' : 'rootfs'} ${disk}G`,
    `${info.cli} start ${id}`,
  ].join('\n')

  const summary = [
    ['Нода', node], ['Тип', info.label + ' — ' + t(info.title)], [info.kind + ' ID', t('авто, от {n}', { n: PVE.vmidFrom })],
    ['Hostname', name.trim()], ['Шаблон', template ? String(template) : '—'], ['Пул', PVE.pool], ['Теги', 'honeyforge'],
    ['Хранилище', PVE.storage], ['Диск', disk + ' ГБ'], ['Ядра', cores], ['Память', memMb + ' МиБ'], ...(type === 'lxc' ? [['Swap', SWAP_MB + ' МиБ']] : []),
    ['Сеть', PVE.bridge + ' · ' + PVE.network], ['IPv4', t('авто, от {ip}', { ip: firstIp }) + ' · ' + t('статический')], ['Шлюз', gw], ['DNS', NAMESERVER],
    ['Ловушки', selected.length ? selected.join(', ') + ' · ' + t('порты') + ' ' + ports.join(', ') : '—'],
  ]

  return (
    <div className="wiz">
      <div className="wiz-tabs" role="tablist">
        {STEPS.map((s, i) => (
          <button key={s} type="button" role="tab" aria-selected={i === step} className={i === step ? 'on' : i < step ? 'done' : ''} onClick={() => go(i)}>
            {t(s)}
          </button>
        ))}
      </div>

      <div className="wiz-body">
        {step === 0 && (
          <div className="wiz-grid">
            <div>
              <Row label="Нода"><Fixed>{node}</Fixed></Row>
              <Row label={info.kind + ' ID'} help="Номер машины в Proxmox. Оркестратор берёт первый свободный, начиная с 1100."><Fixed>{t('авто, от {n}', { n: PVE.vmidFrom })}</Fixed></Row>
              <Row label="Hostname">
                <input autoFocus maxLength={60} value={name} onChange={(e) => setName(e.target.value)} aria-label="Hostname" onFocus={(e) => e.target.select()} />
              </Row>
            </div>
            <div>
              <Row label="Тип" help="LXC — лёгкий контейнер, стартует за секунды, подходит для Low и Medium. KVM — полноценная виртуальная машина: дольше стартует, но изоляция сильнее.">
                <div className="seg wiz-seg" role="radiogroup">
                  {Object.entries(TYPE_INFO).map(([k, ti]) => (
                    <button key={k} type="button" role="radio" aria-checked={k === type} className={k === type ? 'on' : ''} onClick={() => setType(k)}>
                      <b>{ti.label}</b>
                    </button>
                  ))}
                </div>
              </Row>
              <Row label="Пул" help="Права оркестратора в Proxmox ограничены этим пулом: прод-машины ему не видны."><Fixed>{PVE.pool}</Fixed></Row>
              <Row label="Теги"><Fixed>honeyforge</Fixed></Row>
              {type === 'lxc' && <Row label="Непривилегированный"><Fixed>{t('да')}</Fixed></Row>}
            </div>
          </div>
        )}

        {step === 1 && (
          <div className="wiz-grid one">
            <Row label="Хранилище"><Fixed>{PVE.storage}</Fixed></Row>
            <Row label="Шаблон" help="Полный клон этого шаблона. В нём уже установлен агент HoneyForge, настоящий sshd выключен.">
              <Fixed>{template ? (type === 'lxc' ? `${template} · Ubuntu 24.04 + агент HoneyForge` : String(template)) : t('не настроен')}</Fixed>
            </Row>
            {!template && <p className="cnote warn">{t('Шаблон для {kind} не настроен в оркестраторе — выберите LXC на вкладке «Общие»', { kind: info.label })}</p>}
          </div>
        )}

        {step === 2 && (
          <div className="wiz-grid one">
            <Row label="Хранилище"><Fixed>{PVE.storage}</Fixed></Row>
            <Row label="Размер диска (ГиБ)" help="Proxmox умеет только увеличивать диск: меньше, чем у шаблона, не сделать.">
              <input type="number" min={PVE.limits.disk[0]} max={PVE.limits.disk[1]} step={1} value={disk} onChange={(e) => setDisk(e.target.value)} />
            </Row>
          </div>
        )}

        {step === 3 && (
          <div className="wiz-grid one">
            <Row label="Ядра">
              <input type="number" min={PVE.limits.cores[0]} max={PVE.limits.cores[1]} step={1} value={cores} onChange={(e) => setCores(e.target.value)} />
            </Row>
          </div>
        )}

        {step === 4 && (
          <div className="wiz-grid one">
            <Row label="Память (МиБ)">
              <input type="number" min={PVE.limits.ram[0] * 1024} max={PVE.limits.ram[1] * 1024} step={1024} value={memMb} onChange={(e) => setMemMb(e.target.value)} />
            </Row>
            {type === 'lxc' && <Row label="Swap (МиБ)"><Fixed>{SWAP_MB}</Fixed></Row>}
          </div>
        )}

        {step === 5 && (
          <div className="wiz-grid">
            <div>
              <Row label="Имя"><Fixed>{type === 'lxc' ? 'eth0' : 'net0'}</Fixed></Row>
              <Row label="Мост" help={HELP.dmz}><Fixed>{PVE.bridge}</Fixed></Row>
              <Row label="Подсеть"><Fixed>{PVE.network + ' · DMZ'}</Fixed></Row>
            </div>
            <div>
              <Row label="IPv4" help="Статический адрес: оркестратор выдаёт первый свободный в DMZ, начиная с .10."><Fixed>{t('авто, от {ip}', { ip: firstIp })}</Fixed></Row>
              <Row label="Шлюз (IPv4)"><Fixed>{gw}</Fixed></Row>
              <Row label="DNS-сервер"><Fixed>{NAMESERVER}</Fixed></Row>
            </div>
            <p className="hint wiz-note">{t('{bridge} — ловушки не видят домашнюю сеть и прод', { bridge: t(PVE.bridgeLabel) })}</p>
          </div>
        )}

        {step === 6 && (
          <>
            <p className="hint">{t('Можно выбрать несколько. Типы с пересекающимися портами в одной машине недоступны.')}</p>
            <TrapPicker existing={[]} selected={selected} multi onChange={setSelected} />
            <div className="hint mt-10">
              {selected.length ? t('Выбрано ловушек: {n} · порты: {ports}', { n: selected.length, ports: ports.join(', ') }) : t('Ничего не выбрано')}
            </div>
          </>
        )}

        {step === 7 && (
          <>
            <table className="wiz-confirm">
              <thead><tr><th>{t('Ключ')}</th><th>{t('Значение')}</th></tr></thead>
              <tbody>{summary.map(([k, v]) => <tr key={k}><td>{t(k)}</td><td>{v}</td></tr>)}</tbody>
            </table>
            <label className="wiz-check"><input type="checkbox" checked disabled readOnly /> {t('Запустить после создания')}</label>
            <h4>{t('Эквивалентные команды Proxmox')}</h4>
            <pre>{commands}</pre>
          </>
        )}
      </div>

      <div className="err" role="alert">{err}</div>
      <div className="wiz-foot">
        <button type="button" className="ghost" onClick={closeModal}>{t('Отмена')}</button>
        <span className="spacer" />
        <button type="button" className="ghost" disabled={step === 0} onClick={() => go(step - 1)}>{t('Назад')}</button>
        {step < STEPS.length - 1
          ? <button type="button" className="btn" onClick={() => go(step + 1)}>{t('Далее')}</button>
          : <button type="button" className="btn" disabled={busy} onClick={create}
            data-tip={t('Центр клонирует шаблон в Proxmox, выдаёт ресурсы и сеть, запускает машину; агент внутри поднимет выбранные ловушки')}>
            {t('Готово')}
          </button>}
      </div>
    </div>
  )
}
